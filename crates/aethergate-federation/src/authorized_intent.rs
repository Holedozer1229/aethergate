//! Independent validation of URUU guardian authorization certificates.
//!
//! Every FROST operator runs this verifier locally before considering signing.
//! It does not create nonces or signature shares. EXCAL consensus/signature
//! compatibility remains a separate mandatory gate.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;

const APPROVAL_DOMAIN: &[u8] = b"URUU-GUARDIAN-APPROVAL\0";
const ENVELOPE_SCHEMA: &str = "uruu.frostgate-authorization.v1";
const INTENT_SCHEMA: &str = "uruu.frostgate-signing-intent.v1";
const APPROVAL_SCHEMA: &str = "uruu.guardian-approval.v1";

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("malformed authorization envelope: {0}")]
    Malformed(String),
    #[error("authorization rejected: {0}")]
    Rejected(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryInput { pub txid: String, pub vout: u32, pub amount_sats: String }

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainIntent {
    pub schema: String, pub chain_id: String, pub network_magic: String, pub genesis_hash: String,
    pub operation: String, pub request_id: String, pub inputs: Vec<RecoveryInput>,
    pub destination_script_hex: String, pub amount_sats: String, pub fee_sats: String,
    pub expires_at: u64, pub sighash_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy { pub version: String, pub quorum: usize, pub guardian_count: usize }

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalMessage {
    pub schema: String, pub policy_version: String, pub request_id: String,
    pub new_key_commit: String, pub policy_commit: String, pub requested_timelock: u64,
    pub proof_hash: String, pub chain_intent_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardianSignature { pub guardian_id: String, pub signature: String }

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationEnvelope {
    pub schema: String, pub policy: Policy, pub chain_intent: ChainIntent,
    pub chain_intent_hash: String, pub sighash_hex: String, pub approval_message_schema: String,
    pub approval_message: ApprovalMessage, pub guardian_signatures: Vec<GuardianSignature>,
    pub expires_at: u64, pub status: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedAuthorizedIntent {
    request_id: String, chain_intent_hash: [u8; 32], sighash: [u8; 32],
    expires_at: u64, verified_guardians: Vec<String>,
}

impl VerifiedAuthorizedIntent {
    pub fn request_id(&self) -> &str { &self.request_id }
    pub fn chain_intent_hash(&self) -> &[u8; 32] { &self.chain_intent_hash }
    pub fn sighash(&self) -> &[u8; 32] { &self.sighash }
    pub fn expires_at(&self) -> u64 { self.expires_at }
    pub fn verified_guardians(&self) -> &[String] { &self.verified_guardians }
}

fn hex_decode(value: &str) -> Result<Vec<u8>, AuthorizationError> {
    if value.len() % 2 != 0 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AuthorizationError::Malformed("invalid hex encoding".into()));
    }
    (0..value.len()).step_by(2).map(|i|
        u8::from_str_radix(&value[i..i + 2], 16)
            .map_err(|_| AuthorizationError::Malformed("invalid hex encoding".into()))
    ).collect()
}

fn hex32(value: &str, field: &str) -> Result<[u8; 32], AuthorizationError> {
    hex_decode(value)?.try_into()
        .map_err(|_| AuthorizationError::Malformed(format!("{field} must be 32 bytes")))
}
fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}
fn sha256(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }

fn canonical_intent(i: &ChainIntent) -> String {
    let inputs = i.inputs.iter().map(|x| format!(
        "{{\"amountSats\":{},\"txid\":{},\"vout\":{}}}",
        json_string(&x.amount_sats), json_string(&x.txid), x.vout
    )).collect::<Vec<_>>().join(",");
    format!(
        concat!(
            "{{\"amountSats\":{},\"chainId\":{},\"destinationScriptHex\":{},",
            "\"expiresAt\":{},\"feeSats\":{},\"genesisHash\":{},\"inputs\":[{}],",
            "\"networkMagic\":{},\"operation\":{},\"requestId\":{},\"schema\":{},\"sighashHex\":{}}}"
        ),
        json_string(&i.amount_sats), json_string(&i.chain_id), json_string(&i.destination_script_hex),
        i.expires_at, json_string(&i.fee_sats), json_string(&i.genesis_hash), inputs,
        json_string(&i.network_magic), json_string(&i.operation), json_string(&i.request_id),
        json_string(&i.schema), json_string(&i.sighash_hex),
    )
}

fn canonical_approval(m: &ApprovalMessage, guardian_id: &str) -> String {
    format!(
        concat!(
            "{{\"chainIntentHash\":{},\"guardianId\":{},\"newKeyCommit\":{},",
            "\"policyCommit\":{},\"policyVersion\":{},\"proofHash\":{},",
            "\"requestedTimelock\":{},\"requestId\":{},\"schema\":{}}}"
        ),
        json_string(&m.chain_intent_hash), json_string(guardian_id), json_string(&m.new_key_commit),
        json_string(&m.policy_commit), json_string(&m.policy_version), json_string(&m.proof_hash),
        m.requested_timelock, json_string(&m.request_id), json_string(&m.schema),
    )
}

/// trusted_guardians is operator-local configuration: guardian ID -> lowercase
/// hex raw 32-byte Ed25519 public key. Never trust keys supplied by URUU.
pub fn verify_uruu_authorization(
    e: &AuthorizationEnvelope, trusted_guardians: &BTreeMap<String, String>, now: u64,
) -> Result<VerifiedAuthorizedIntent, AuthorizationError> {
    if e.schema != ENVELOPE_SCHEMA || e.status != "READY_FOR_INDEPENDENT_OPERATOR_VERIFICATION" {
        return Err(AuthorizationError::Rejected("unexpected schema or non-ready status".into()));
    }
    if e.policy.quorum < 2 || e.policy.quorum > e.policy.guardian_count ||
       e.policy.guardian_count != trusted_guardians.len() {
        return Err(AuthorizationError::Rejected("local guardian registry does not match policy".into()));
    }
    if e.expires_at <= now || e.chain_intent.expires_at <= now {
        return Err(AuthorizationError::Rejected("authorization or intent expired".into()));
    }
    let i = &e.chain_intent;
    if i.schema != INTENT_SCHEMA || i.operation != "RECOVERY" ||
       i.request_id != e.approval_message.request_id || e.expires_at != i.expires_at ||
       e.sighash_hex != i.sighash_hex {
        return Err(AuthorizationError::Rejected("chain intent fields disagree".into()));
    }
    let ih = sha256(canonical_intent(i).as_bytes());
    if ih != hex32(&e.chain_intent_hash, "chainIntentHash")? ||
       ih != hex32(&e.approval_message.chain_intent_hash, "approval chainIntentHash")? {
        return Err(AuthorizationError::Rejected("chain intent commitment mismatch".into()));
    }
    let sighash = hex32(&i.sighash_hex, "sighash")?;
    let amount: u128 = i.amount_sats.parse().map_err(|_| AuthorizationError::Malformed("invalid amount".into()))?;
    let fee: u128 = i.fee_sats.parse().map_err(|_| AuthorizationError::Malformed("invalid fee".into()))?;
    if i.inputs.is_empty() { return Err(AuthorizationError::Rejected("empty input set".into())); }
    let mut total = 0u128;
    for input in &i.inputs {
        hex32(&input.txid, "input txid")?;
        total = total.checked_add(input.amount_sats.parse::<u128>()
            .map_err(|_| AuthorizationError::Malformed("invalid input amount".into()))?)
            .ok_or_else(|| AuthorizationError::Malformed("input sum overflow".into()))?;
    }
    if amount.checked_add(fee).filter(|x| *x <= total).is_none() {
        return Err(AuthorizationError::Rejected("spend exceeds committed inputs".into()));
    }
    if i.destination_script_hex.is_empty() || i.destination_script_hex.len() % 2 != 0 ||
       !i.destination_script_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AuthorizationError::Malformed("invalid destination script".into()));
    }
    let m = &e.approval_message;
    if e.approval_message_schema != APPROVAL_SCHEMA || m.schema != APPROVAL_SCHEMA ||
       m.policy_version != e.policy.version || m.chain_intent_hash != e.chain_intent_hash {
        return Err(AuthorizationError::Rejected("approval policy binding mismatch".into()));
    }
    hex32(&m.proof_hash, "proofHash")?;
    let mut seen = HashSet::new();
    let mut verified = Vec::new();
    for approval in &e.guardian_signatures {
        if !seen.insert(approval.guardian_id.clone()) {
            return Err(AuthorizationError::Rejected("duplicate guardian signature".into()));
        }
        let key_hex = trusted_guardians.get(&approval.guardian_id)
            .ok_or_else(|| AuthorizationError::Rejected(format!("untrusted guardian {}", approval.guardian_id)))?;
        let key_bytes = hex32(key_hex, "guardian public key")?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| AuthorizationError::Malformed("invalid Ed25519 public key".into()))?;
        let sig_bytes = hex_decode(&approval.signature)?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| AuthorizationError::Malformed("invalid Ed25519 signature".into()))?;
        let mut signed = APPROVAL_DOMAIN.to_vec();
        signed.extend_from_slice(canonical_approval(m, &approval.guardian_id).as_bytes());
        key.verify(&signed, &sig)
            .map_err(|_| AuthorizationError::Rejected(format!("invalid guardian signature: {}", approval.guardian_id)))?;
        verified.push(approval.guardian_id.clone());
    }
    if verified.len() < e.policy.quorum {
        return Err(AuthorizationError::Rejected("guardian quorum not met".into()));
    }
    Ok(VerifiedAuthorizedIntent {
        request_id: i.request_id.clone(), chain_intent_hash: ih, sighash,
        expires_at: i.expires_at, verified_guardians: verified,
    })
}

/// Verify the exact 32-byte message presented to a FROST signer. This does not
/// establish that EXCAL accepts the resulting BIP340 signature.
pub fn require_exact_sighash(
    auth: &VerifiedAuthorizedIntent, proposed_message: &[u8], now: u64,
) -> Result<(), AuthorizationError> {
    if auth.expires_at <= now { return Err(AuthorizationError::Rejected("authorization expired".into())); }
    if proposed_message != auth.sighash.as_slice() {
        return Err(AuthorizationError::Rejected("FROST message differs from approved chain sighash".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_schema_and_expired_authorization() {
        let e: AuthorizationEnvelope = serde_json::from_str(r#"{
          "schema":"wrong","policy":{"version":"v1","quorum":3,"guardianCount":5},
          "chainIntent":{"schema":"wrong","chainId":"EXCAL","networkMagic":"test","genesisHash":"0000000000000000000000000000000000000000000000000000000000000000","operation":"RECOVERY","requestId":"r","inputs":[],"destinationScriptHex":"51","amountSats":"1","feeSats":"0","expiresAt":1,"sighashHex":"0000000000000000000000000000000000000000000000000000000000000000"},
          "chainIntentHash":"0000000000000000000000000000000000000000000000000000000000000000",
          "sighashHex":"0000000000000000000000000000000000000000000000000000000000000000",
          "approvalMessageSchema":"uruu.guardian-approval.v1",
          "approvalMessage":{"schema":"uruu.guardian-approval.v1","policyVersion":"v1","requestId":"r","newKeyCommit":"x","policyCommit":"y","requestedTimelock":60,"proofHash":"0000000000000000000000000000000000000000000000000000000000000000","chainIntentHash":"0000000000000000000000000000000000000000000000000000000000000000"},
          "guardianSignatures":[],"expiresAt":1,"status":"READY_FOR_INDEPENDENT_OPERATOR_VERIFICATION"
        }"#).unwrap();
        assert!(verify_uruu_authorization(&e, &BTreeMap::new(), 2).is_err());
    }
}
