# TEE attestation artifacts

Each file `0x<address>.json` is the **exact** RedPill/Phala attestation report captured
when that TEE signing key was registered on-chain. The on-chain registry entry stores

```
attestation_hash = sha256( the exact bytes of 0x<address>.json )
```

so anyone can independently verify the registration. There are **no placeholders** —
this is the live hardware attestation.

## How to audit a registered key

1. **Hash matches chain.** `sha256(0x<address>.json)` must equal the `attestation_hash`
   in the key's registry PDA (`seeds = ["tee_key", address]`, program
   `D4fwqE74azXzC6euWAmDoH6Up1gZEh725odUuZHcCqEB`).

2. **The quote commits to the signing key.** Inside the report,
   `attestation.report_data` begins with the 20-byte signing address:

   ```
   report_data = <signing_address (20 bytes)> · <zero pad> · <nonce>
   ```

   i.e. the Intel TDX quote was produced *for this exact key*. The `nonce` is
   `sha256("prova-proof-registry-v1:" + address)` — deterministic and documented, so
   the binding is explainable, not cherry-picked.

3. **The quote is genuine Intel TDX.** Decode `intel_quote` (hex) and verify it through
   Intel's DCAP/PCS the usual way — it chains to Intel's roots and certifies the
   `tee_type: tdx` enclave that holds the key.

4. **GPU is genuine NVIDIA CC.** `nvidia_payload` verifies against NVIDIA NRAS
   (`https://nras.attestation.nvidia.com/v3/attest/gpu`).

5. **Same key signs every model.** The signing address is KMS-derived and shared across
   the model fleet — recover the signer of ANY on-chain proof's signature (EIP-191) and
   it equals this address. The program enforces exactly this at consensus in
   `record_proof`.

> The report includes per-fetch freshness (quote collateral, NVIDIA nonce), so a
> re-fetch won't be byte-identical — the published file here *is* the canonical
> snapshot the on-chain hash commits to.
