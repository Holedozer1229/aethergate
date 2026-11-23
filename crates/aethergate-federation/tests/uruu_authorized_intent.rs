use aethergate_federation::authorized_intent::{
    require_exact_sighash, require_live_operator_status, require_signature_compatibility, verify_uruu_authorization, ApprovalMessage, AuthorizationEnvelope, LiveOperatorStatus,
    ChainIntent, GuardianSignature, Policy, RecoveryInput,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::collections::BTreeMap;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn accepts_three_independent_guardian_signatures_and_binds_frost_message() {
    let now = 1_900_000_000u64;
    let expires = now + 600;
    let intent = ChainIntent {
        schema: "uruu.frostgate-signing-intent.v1".into(),
        chain_id: "EXCAL".into(),
        network_magic: "testnet-magic".into(),
        genesis_hash: "11".repeat(32),
        operation: "RECOVERY".into(),
        request_id: "request-01".into(),
        inputs: vec![RecoveryInput {
            txid: "22".repeat(32), vout: 1, amount_sats: "5000".into(),
        }],
        destination_script_hex: "51".into(),
        amount_sats: "4000".into(),
        fee_sats: "100".into(),
        expires_at: expires,
        sighash_hex: "33".repeat(32),
    };
    let canonical_intent = json!({
        "amountSats": intent.amount_sats,
        "chainId": intent.chain_id,
        "destinationScriptHex": intent.destination_script_hex,
        "expiresAt": intent.expires_at,
        "feeSats": intent.fee_sats,
        "genesisHash": intent.genesis_hash,
        "inputs": [{"amountSats":"5000","txid":"22".repeat(32),"vout":1}],
        "networkMagic": intent.network_magic,
        "operation": intent.operation,
        "requestId": intent.request_id,
        "schema": intent.schema,
        "sighashHex": intent.sighash_hex,
    });
    let intent_hash = {
        use sha2::{Digest, Sha256};
        hex(&Sha256::digest(serde_json::to_vec(&canonical_intent).unwrap()))
    };
    let message = ApprovalMessage {
        schema: "uruu.guardian-approval.v1".into(),
        policy_version: "policy-v1".into(),
        request_id: "request-01".into(),
        new_key_commit: "new-key".into(),
        policy_commit: "policy-commit".into(),
        requested_timelock: 86_400,
        proof_hash: "44".repeat(32),
        public_inputs_hash: "55".repeat(32),
        timelock_expires_at: "2030-01-01T00:00:00.000Z".into(),
        chain_intent_hash: intent_hash.clone(),
    };

    let mut trusted = BTreeMap::new();
    let mut approvals = Vec::new();
    for index in 1u8..=5 {
        let key = SigningKey::from_bytes(&[index; 32]);
        let guardian_id = format!("guardian-{index}");
        trusted.insert(guardian_id.clone(), hex(&key.verifying_key().to_bytes()));
        if index <= 3 {
            let canonical_message = json!({
                "chainIntentHash": message.chain_intent_hash,
                "guardianId": guardian_id,
                "newKeyCommit": message.new_key_commit,
                "policyCommit": message.policy_commit,
                "policyVersion": message.policy_version,
                "proofHash": message.proof_hash,
                "publicInputsHash": message.public_inputs_hash,
                "requestId": message.request_id,
                "requestedTimelock": message.requested_timelock,
                "schema": message.schema,
                "timelockExpiresAt": message.timelock_expires_at,
            });
            let mut bytes = b"URUU-GUARDIAN-APPROVAL\0".to_vec();
            bytes.extend_from_slice(&serde_json::to_vec(&canonical_message).unwrap());
            approvals.push(GuardianSignature {
                guardian_id,
                signature: hex(&key.sign(&bytes).to_bytes()),
            });
        }
    }

    let envelope = AuthorizationEnvelope {
        schema: "uruu.frostgate-authorization.v1".into(),
        policy: Policy { version: "policy-v1".into(), quorum: 3, guardian_count: 5 },
        chain_intent: intent.clone(),
        chain_intent_hash: intent_hash,
        sighash_hex: intent.sighash_hex.clone(),
        approval_message_schema: "uruu.guardian-approval.v1".into(),
        approval_message: message,
        guardian_signatures: approvals,
        expires_at: expires,
        status: "READY_FOR_INDEPENDENT_OPERATOR_VERIFICATION".into(),
    };

    let verified = verify_uruu_authorization(&envelope, &trusted, now).unwrap();
    assert_eq!(verified.verified_guardians().len(), 3);
    assert!(require_signature_compatibility(&verified).is_err(), "EXCAL signing must remain disabled until compatibility is proven");
    let approved_sighash = (0..32).map(|_| 0x33u8).collect::<Vec<_>>();
    require_exact_sighash(&verified, &approved_sighash, now).unwrap();
    let live = LiveOperatorStatus {
        schema: "uruu.frostgate-operator-status.v1".into(),
        request_id: "request-01".into(),
        chain_intent_hash: intent_hash.clone(),
        expires_at: Some(expires),
        status: "APPROVED".into(),
        approval_count: 3,
        quorum: 3,
        policy_version: Some("policy-v1".into()),
        new_key_commit: "new-key".into(),
        policy_commit: "policy-commit".into(),
        proof_hash: "44".repeat(32),
        public_inputs_hash: "55".repeat(32),
        timelock_expires_at: Some("2030-01-01T00:00:00.000Z".into()),
        revoked: false,
        checked_at: now,
    };
    require_live_operator_status(&verified, &live, now).unwrap();
    assert!(require_live_operator_status(&verified, &live, now + 31).is_err());
    assert!(require_exact_sighash(&verified, &[0u8; 32], now).is_err());
    assert!(require_exact_sighash(&verified, &approved_sighash, expires).is_err());
}
