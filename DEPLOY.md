# Prova Proof — deploy & registry runbook

`record_proof` now verifies every proof **on-chain** before recording it:

1. **Registry check** — the signing key must exist + be `active` in a `tee_key` PDA
   (an unregistered key has no PDA → the tx is rejected by Anchor).
2. **Signature check** — the EIP-191 `personal_sign` digest of the TEE's signed
   message must `secp256k1_recover` to that exact key's Ethereum-style address.

A *confirmed* `record_proof` tx is therefore itself cryptographic proof: no fake
key, unregistered key, or forged/edited signature can produce one.

Program id: `D4fwqE74azXzC6euWAmDoH6Up1gZEh725odUuZHcCqEB`
Authority (upgrade + registry writer): `EfidFw4z8xAN6daskNKpENnDr6g4hgeS3AE587cuv4Re`

## Order of operations (owner — spends SOL, needs the authority key)

```bash
# 0. Build (IDL is hand-maintained in prova_proof.idl.json; the 0.30.1 IDL
#    generator is incompatible with the current Rust toolchain).
anchor build --no-idl
#    -> target/deploy/prova_proof.so

# 1. Upgrade the live program (authority must be the upgrade authority).
#    The new binary (~228 KB) is LARGER than the originally-allocated program
#    data, so extend it first (one-time; ~0.6 SOL more rent). Skip if deploy
#    succeeds without the "account data too small" error.
solana program extend D4fwqE74azXzC6euWAmDoH6Up1gZEh725odUuZHcCqEB 80000 \
  --keypair /path/to/proof-wallet.json --url "$SOLANA_RPC_URL"
solana program deploy target/deploy/prova_proof.so \
  --program-id D4fwqE74azXzC6euWAmDoH6Up1gZEh725odUuZHcCqEB \
  --upgrade-authority /path/to/proof-wallet.json \
  --url "$SOLANA_RPC_URL"

# 2. Publish the IDL so Solscan decodes the new instructions/events.
anchor idl upgrade D4fwqE74azXzC6euWAmDoH6Up1gZEh725odUuZHcCqEB \
  -f prova_proof.idl.json \
  --provider.cluster "$SOLANA_RPC_URL" --provider.wallet /path/to/proof-wallet.json
#    (use `anchor idl init …` if no IDL was ever published)

# 3. Register every model's TEE key (run from the vera-ai-trader repo, which has
#    @solana/web3.js). Re-run whenever a key rotates — registered keys are skipped.
SOLANA_RPC_URL=… REDPILL_API_KEY=… \
AUTHORITY_KEYPAIR=/path/to/proof-wallet.json \
MODELS="phala/gpt-oss-120b,phala/qwen3-…,…"  \
node scripts/register-tee-keys.cjs
#    dry-run first:  node scripts/register-tee-keys.cjs --check

# 4. Deploy the edge functions (push to GitHub → Lovable, or `supabase functions deploy`).
#    They already build the new instruction (signed_message + registry PDA).

# 5. TEST end-to-end:
#    a) send a real chat message → open the tx on Solscan → /verify should show
#       "Solana enforced TEE-registry + signature on-chain" = PASS.
#    b) NEGATIVE: a record_proof with a random (unregistered) signing_address, or
#       an edited signature, MUST fail to confirm. (See scripts note below.)

# 6. Re-run OtterSec verification (commit hash changed).
```

## Why this is un-larpable

| Attack | Blocked | Why |
|---|---|---|
| Forged signature | ✅ | `secp256k1_recover` ≠ registered address → `require!` reverts |
| Random keypair (not a TEE) | ✅ | no `tee_key` PDA for it → Anchor rejects the tx |
| Register a fake key | ✅ | only `PROGRAM_AUTHORITY` can register; each entry carries a public `attestation_hash` (sha256 of the Intel TDX quote) anyone can reproduce |
| Edit req/res/model after signing | ✅ | the signed `text` is recovered against the registered key; any change breaks recovery |

The registry is fully public (PDAs under `["tee_key", address]`), so anyone can
audit which keys are trusted and reproduce each key's attestation hash.
