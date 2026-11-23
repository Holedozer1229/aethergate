# URUU / FrostGate independent operator verification

The `authorized_intent` module validates the certificate returned by URUU's
`GET /recovery/:requestId/signing-intent` endpoint. It does not perform
transport, create nonces, sign, aggregate, broadcast, or alter EXCAL.

## Operator procedure

1. Fetch the authorization certificate over mutually authenticated TLS.
2. Load the operator's locally provisioned guardian registry
   (guardian ID -> lowercase hex raw 32-byte Ed25519 public key). Never accept
   public keys from the certificate itself.
3. Deserialize the JSON into `AuthorizationEnvelope`.
4. Call `verify_uruu_authorization(&envelope, &trusted_guardians, now)`.
5. Immediately before any signing share, fetch
   `GET /recovery/:requestId/operator-status` over the authenticated channel.
   Reject if `revoked=true`, request/intent hash differs, or expiry passed.
6. If and only if a separately approved EXCAL compatibility report establishes
   the exact native sighash and signature semantics, compare the FROST
   SigningPackage's `message()` with the returned `VerifiedAuthorizedIntent`
   using `require_exact_sighash`.

The approval signature bytes are:
`URUU-GUARDIAN-APPROVAL\0` || UTF-8 compact canonical JSON.
The JSON object has lexicographically sorted keys:
`chainIntentHash, guardianId, newKeyCommit, policyCommit, policyVersion,
proofHash, requestedTimelock, requestId, schema`.
The canonical chain-intent SHA-256 uses sorted keys and compact JSON as
implemented in the URUU policy module. Inputs preserve their submitted order;
each input's keys are sorted. All amounts are decimal integer strings.

## Public-key provisioning

URUU stores guardian Ed25519 public keys as PEM SubjectPublicKeyInfo. For the
FROST operator's local trust registry, provision the corresponding raw
32-byte Ed25519 public key in lowercase hex from the same independently
verified key ceremony. The operator registry must be delivered through a
separate trusted configuration channel, not copied blindly from URUU's API.

## Current safety status

This is an independent authorization verifier and signing-package message
gate, not a deployed distributed signing network. The existing FROST
coordinator/signers still include in-process orchestration. Do not expose
operator key shares or enable production signing until there are five separate
operator processes, authenticated operator-to-operator channels, protected
shares, durable nonce state, and an audited recovery/revocation design.

Most importantly, the existing FROST ciphersuite is BIP340/Taproot. EXCAL's
active transaction/script rules have not yet been shown to accept that exact
signature format and sighash. Keep EXCAL's current signature rules unchanged;
no EXCAL signature shares or broadcasts are authorized by this module.
