use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;
use anchor_lang::solana_program::secp256k1_recover::secp256k1_recover;

declare_id!("D4fwqE74azXzC6euWAmDoH6Up1gZEh725odUuZHcCqEB");

// Only this key may register / (de)activate TEE signing keys. It is the program
// upgrade authority and Prova's proof wallet. Anyone can READ the registry, but
// only the authority can WRITE it — and each entry is bound to a public
// attestation-report hash so the registration itself is independently auditable.
const PROGRAM_AUTHORITY: Pubkey = pubkey!("EfidFw4z8xAN6daskNKpENnDr6g4hgeS3AE587cuv4Re");

#[program]
pub mod prova_proof {
    use super::*;

    /// Register a verified TEE signing key in an on-chain PDA.
    /// `signing_address` is the 20-byte Ethereum-style address the TEE signs with
    /// (last 20 bytes of keccak256(uncompressed secp256k1 pubkey)) — exactly what
    /// ethers.verifyMessage() recovers off-chain. `attestation_hash` links the key
    /// to a published hardware attestation report so the registration is auditable.
    /// Authority-gated: only PROGRAM_AUTHORITY can call this.
    pub fn register_tee_key(
        ctx: Context<RegisterTeeKey>,
        signing_address: [u8; 20],
        attestation_hash: [u8; 32],
        provider: String, // "phala" | "chutes" | "near_ai" | "tinfoil" | ...
    ) -> Result<()> {
        require!(provider.len() <= 32, ProvaError::ProviderTooLong);
        let registry = &mut ctx.accounts.tee_registry;
        registry.signing_address = signing_address;
        registry.attestation_hash = attestation_hash;
        registry.provider = provider.clone();
        registry.registered_at = Clock::get()?.unix_timestamp;
        registry.active = true;

        emit!(TeeKeyRegistered { signing_address, attestation_hash, provider });
        Ok(())
    }

    /// Activate / deactivate an already-registered key (rotation & revocation).
    /// Optionally re-point it at a fresh attestation hash. Authority-gated.
    pub fn set_tee_key_status(
        ctx: Context<SetTeeKeyStatus>,
        _signing_address: [u8; 20],
        active: bool,
        attestation_hash: Option<[u8; 32]>,
    ) -> Result<()> {
        let registry = &mut ctx.accounts.tee_registry;
        registry.active = active;
        if let Some(h) = attestation_hash {
            registry.attestation_hash = h;
        }
        emit!(TeeKeyStatusChanged {
            signing_address: registry.signing_address,
            active,
            attestation_hash: registry.attestation_hash,
        });
        Ok(())
    }

    /// Record an inference proof — ONLY if it carries a real TEE signature from a
    /// REGISTERED key. Two on-chain checks, both must pass or the tx is rejected:
    ///   1. REGISTRY  — the signing key exists in the registry and is `active`.
    ///                  (An unregistered key has no PDA → Anchor rejects the tx
    ///                   before this even runs.)
    ///   2. SIGNATURE — the EIP-191 `personal_sign` digest of the TEE's signed
    ///                  message recovers, via secp256k1, to exactly that key's
    ///                  address. A fake/edited signature can't recover correctly.
    ///
    /// `signed_message` is the EXACT text the TEE signed (RedPill /signature{text}).
    /// We reconstruct the same digest ethers.verifyMessage() uses:
    ///   keccak256("\x19Ethereum Signed Message:\n" + len(text) + text)
    pub fn record_proof(
        ctx: Context<RecordProof>,
        request_id: String,
        model: String,
        req_hash: String,
        res_hash: String,
        signed_message: String,
        signing_address: [u8; 20],
        signature: [u8; 64],
        recovery_id: u8,
        timestamp: i64,
    ) -> Result<()> {
        // ── CHECK 1: key is registered & active ──────────────────────────────
        let registry = &ctx.accounts.tee_registry;
        require!(registry.active, ProvaError::TeeKeyNotRegistered);
        require!(
            registry.signing_address == signing_address,
            ProvaError::TeeKeyMismatch
        );

        // ── CHECK 2: signature recovers to that exact address ────────────────
        // EIP-191 personal_sign prefix (byte length rendered as ASCII decimal).
        let msg = signed_message.as_bytes();
        let len_str = msg.len().to_string();
        let mut prefixed =
            Vec::with_capacity(26 + len_str.len() + msg.len());
        prefixed.extend_from_slice(b"\x19Ethereum Signed Message:\n");
        prefixed.extend_from_slice(len_str.as_bytes());
        prefixed.extend_from_slice(msg);
        let digest = keccak::hash(&prefixed);

        let recovered = secp256k1_recover(&digest.0, recovery_id, &signature)
            .map_err(|_| ProvaError::InvalidSignature)?;
        // Ethereum address = last 20 bytes of keccak256(64-byte uncompressed pubkey).
        let addr_hash = keccak::hash(&recovered.0);
        let recovered_address: [u8; 20] = addr_hash.0[12..32]
            .try_into()
            .map_err(|_| ProvaError::InvalidSignature)?;
        require!(
            recovered_address == signing_address,
            ProvaError::SignatureMismatch
        );

        // ── BOTH PASSED — record the proof (decoded by Solscan via the IDL) ───
        emit!(ProofRecorded {
            request_id,
            model,
            req_hash,
            res_hash,
            signing_address,
            timestamp,
            verified_signature: true,
            verified_registry: true,
            attestation_hash: registry.attestation_hash,
            provider: registry.provider.clone(),
            prover: ctx.accounts.prover.key(),
        });
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(signing_address: [u8; 20])]
pub struct RegisterTeeKey<'info> {
    #[account(
        init,
        payer = authority,
        // 8 disc + 20 addr + 32 attest + (4 + 32 provider) + 8 ts + 1 active
        space = 8 + 20 + 32 + 4 + 32 + 8 + 1,
        seeds = [b"tee_key", signing_address.as_ref()],
        bump,
    )]
    pub tee_registry: Account<'info, TeeKeyRegistry>,
    #[account(mut, address = PROGRAM_AUTHORITY @ ProvaError::Unauthorized)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(signing_address: [u8; 20])]
pub struct SetTeeKeyStatus<'info> {
    #[account(
        mut,
        seeds = [b"tee_key", signing_address.as_ref()],
        bump,
    )]
    pub tee_registry: Account<'info, TeeKeyRegistry>,
    #[account(address = PROGRAM_AUTHORITY @ ProvaError::Unauthorized)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(
    request_id: String,
    model: String,
    req_hash: String,
    res_hash: String,
    signed_message: String,
    signing_address: [u8; 20],
)]
pub struct RecordProof<'info> {
    #[account(mut)]
    pub prover: Signer<'info>,
    // Must exist for `signing_address` — an unregistered key has no PDA, so Anchor
    // rejects the tx here (AccountNotInitialized) before the handler runs.
    #[account(
        seeds = [b"tee_key", signing_address.as_ref()],
        bump,
    )]
    pub tee_registry: Account<'info, TeeKeyRegistry>,
}

#[account]
pub struct TeeKeyRegistry {
    pub signing_address: [u8; 20],
    pub attestation_hash: [u8; 32],
    pub provider: String,
    pub registered_at: i64,
    pub active: bool,
}

#[event]
pub struct TeeKeyRegistered {
    pub signing_address: [u8; 20],
    pub attestation_hash: [u8; 32],
    pub provider: String,
}

#[event]
pub struct TeeKeyStatusChanged {
    pub signing_address: [u8; 20],
    pub active: bool,
    pub attestation_hash: [u8; 32],
}

#[event]
pub struct ProofRecorded {
    pub request_id: String,
    pub model: String,
    pub req_hash: String,
    pub res_hash: String,
    pub signing_address: [u8; 20],
    pub timestamp: i64,
    pub verified_signature: bool,
    pub verified_registry: bool,
    pub attestation_hash: [u8; 32],
    pub provider: String,
    pub prover: Pubkey,
}

#[error_code]
pub enum ProvaError {
    #[msg("Invalid ECDSA signature")]
    InvalidSignature,
    #[msg("Recovered address does not match signing address")]
    SignatureMismatch,
    #[msg("TEE key not found in registry or inactive")]
    TeeKeyNotRegistered,
    #[msg("Signing address does not match registered TEE key")]
    TeeKeyMismatch,
    #[msg("Only the program authority may manage the TEE key registry")]
    Unauthorized,
    #[msg("Provider string too long (max 32 bytes)")]
    ProviderTooLong,
}
