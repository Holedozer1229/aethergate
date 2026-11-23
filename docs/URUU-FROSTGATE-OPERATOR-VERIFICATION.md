# URUU / FrostGate independent operator verification

The `authorized_intent` module validates the certificate returned by URUU's
`GET /recovery/:requestId/signing-intent` endpoint. Each operator verifies the
guardian signatures against its own local trust registry. The signer wrapper
checks live revocation state and the exact FROST SigningPackage message. This
repository does not deploy the operator transport, run distributed DKG, or
aggregate/broadcast transactions.

## Operator procedure

1. Fetch the authorization certificate over mutually authenticated TLS using
   that operator's unique URUU operator token.
2. Load the operator's locally provisioned guardian registry
   (guardian ID -> lowercase hex raw 32-byte Ed25519 public key). Never accept
   public keys from the certificate itself.
3. Deserialize the JSON into `AuthorizationEnvelope`.
4. Call `verify_uruu_authorization(&envelope, &trusted_guardians, now)`.
5. Immediately before producing a share, fetch
   `GET /recovery/:requestId/operator-status` over the authenticated channel.
   Parse `LiveOperatorStatus`; the response is valid for at most 30 seconds
   and must match every signed field: request, chain-intent hash, new-key and
   policy commitments, proof hash, public-input hash, timelock expiry, policy
   version, and quorum.
6. The `OperatorSigner::sign_authorized` wrapper requires that verified
   certificate and fresh live status, then compares the FROST
   SigningPackage's exact `message()` with the approved 32-byte sighash.
   **It hard-rejects EXCAL chain IDs** until a separate compatibility review
   proves EXCAL's native sighash and signature-verification semantics.

The guardian signature bytes are:
`URUU-GUARDIAN-APPROVAL\0` || UTF-8 compact canonical JSON.
The JSON object has lexicographically sorted keys:
`chainIntentHash, guardianId, newKeyCommit, policyCommit, policyVersion,
proofHash, publicInputsHash, requestId, requestedTimelock, schema,
timelockExpiresAt`.
The canonical chain-intent SHA-256 uses sorted keys and compact JSON as
implemented in the URUU policy module. Inputs preserve their submitted order;
each input's keys are sorted. Amounts are decimal integer strings.

## Public-key provisioning

URUU stores guardian Ed25519 public keys as PEM SubjectPublicKeyInfo. For the
FROST operator's local trust registry, provision the corresponding raw
32-byte Ed25519 public key in lowercase hex from the same independently
verified key ceremony. The operator registry must be delivered through a
separate trusted configuration channel, not copied blindly from URUU's API.
Provision a different operator token to each of the five operator processes.

## Current safety status

This is an authorization verifier and signer gate, not a deployed distributed
signing network. The EXCAL share-generation path is explicitly hard-disabled
in code pending compatibility evidence. The existing FROST coordinator/signers
still include in-process orchestration. Do not expose operator key shares or
enable production key custody until there are five separate operator
processes, authenticated operator-to-operator channels, protected shares,
durable nonce state, and an audited recovery/revocation design.

The existing FROST ciphersuite emits BIP340/Taproot signatures. EXCAL's active
transaction/script rules have not yet been shown to accept that exact signature
format and sighash. Keep EXCAL's current signature rules unchanged; no EXCAL
signature shares or broadcasts are authorized by this branch.
