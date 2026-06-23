# Prova Proof

On-chain attestation for private AI. An Anchor program that records a verifiable
proof for every TEE inference — and **verifies that proof on-chain before
recording it**, so a confirmed transaction is itself cryptographic evidence the
response came from genuine, attested TEE hardware.

Program id: `D4fwqE74azXzC6euWAmDoH6Up1gZEh725odUuZHcCqEB` (Solana mainnet)

## Instructions

- **`register_tee_key(signing_address[20], attestation_hash[32], provider)`**
  Authority-only. Stores a verified TEE signing key in a PDA
  (`seeds = ["tee_key", signing_address]`), bound to a public attestation-report
  hash so the registration is independently auditable.

- **`set_tee_key_status(signing_address[20], active, attestation_hash?)`**
  Authority-only. Activate / deactivate a key (rotation & revocation).

- **`record_proof(request_id, model, req_hash, res_hash, signed_message, signing_address[20], signature[64], recovery_id, timestamp)`**
  Permissionless to call, but it **rejects** anything that isn't real:
  1. the key must be registered + `active` (else no PDA → tx rejected);
  2. the EIP-191 `personal_sign` digest of `signed_message` must
     `secp256k1_recover` to that exact key's Ethereum-style address.
  On success it emits `ProofRecorded { verified_signature: true, verified_registry: true, … }`.

## Verification math

`record_proof` reconstructs exactly what `ethers.verifyMessage(text, sig)` does
off-chain:

```
digest   = keccak256("\x19Ethereum Signed Message:\n" + len(signed_message) + signed_message)
pubkey   = secp256k1_recover(digest, recovery_id, signature)   // 64-byte uncompressed
address  = keccak256(pubkey)[12..32]                            // 20-byte eth address
require(address == registered signing_address)
```

## Build

```bash
anchor build --no-idl     # IDL is hand-maintained in prova_proof.idl.json
```

See [DEPLOY.md](./DEPLOY.md) for the upgrade + key-registration runbook.

## Audit

Source is open and verified by OtterSec.
