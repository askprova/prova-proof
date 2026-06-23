#!/usr/bin/env node
/**
 * Register every model's TEE signing key in the on-chain Prova Proof registry,
 * binding each to a REPRODUCIBLE, published attestation artifact.
 *
 * For each distinct signing address the script:
 *   1. fetches the live RedPill attestation report with a DOCUMENTED nonce
 *      = sha256("prova-proof-registry-v1:" + address) — so the quote's report_data
 *      provably commits to that exact key (see attestations/README.md),
 *   2. saves the exact report bytes to attestations/0x<address>.json (publish these),
 *   3. registers the key with attestation_hash = sha256(that file).
 *
 * USAGE (owner — spends a little SOL for rent, needs the authority key):
 *   SOLANA_RPC_URL=...  REDPILL_API_KEY=...  AUTHORITY_KEYPAIR=/path/to/proof-wallet.json
 *   MODELS="openai/gpt-oss-20b,phala/uncensored-24b,..."   # backend slugs
 *   node scripts/register-tee-keys.cjs            # dry-run
 *   node scripts/register-tee-keys.cjs --send     # register on-chain
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Connection, Keypair, PublicKey, Transaction, TransactionInstruction, SystemProgram } = require("@solana/web3.js");

const PROGRAM = new PublicKey("D4fwqE74azXzC6euWAmDoH6Up1gZEh725odUuZHcCqEB");
const AUTH = "EfidFw4z8xAN6daskNKpENnDr6g4hgeS3AE587cuv4Re";
const REGISTER_DISC = Buffer.from([135, 139, 52, 108, 26, 47, 81, 108]); // sha256("global:register_tee_key")[:8]
const BASE = "https://api.redpill.ai/v1";
const SEND = process.argv.includes("--send");
const RPC = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const API_KEY = process.env.REDPILL_API_KEY || "";
const MODELS = (process.env.MODELS || "").split(",").map((s) => s.trim()).filter(Boolean);
const ATT_DIR = path.join(__dirname, "..", "attestations");

const sha = (b) => crypto.createHash("sha256").update(b).digest();
const hexToBytes = (h) => { h = h.replace(/^0x/, ""); if (h.length % 2) h = "0" + h; return Buffer.from(h, "hex"); };
const borshString = (s) => { const b = Buffer.from(s, "utf8"); const o = Buffer.alloc(4 + b.length); o.writeUInt32LE(b.length, 0); b.copy(o, 4); return o; };
const docNonce = (addr) => crypto.createHash("sha256").update("prova-proof-registry-v1:" + addr).digest("hex");
async function report(model, nonce) {
  const r = await fetch(`${BASE}/attestation/report?model=${encodeURIComponent(model)}&nonce=${nonce}`, { headers: { Authorization: `Bearer ${API_KEY}` } });
  if (!r.ok) throw new Error(`report ${r.status} (${model})`);
  return await r.text();
}

(async () => {
  if (!MODELS.length || !API_KEY) { console.error("Set MODELS=… and REDPILL_API_KEY"); process.exit(1); }
  const conn = new Connection(RPC, "confirmed");
  let authority = null;
  if (SEND) {
    authority = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(process.env.AUTHORITY_KEYPAIR, "utf8"))));
    if (authority.publicKey.toBase58() !== AUTH) { console.error("authority != PROGRAM_AUTHORITY — register would be rejected"); process.exit(1); }
  }
  fs.mkdirSync(ATT_DIR, { recursive: true });

  const done = new Set();
  for (const model of MODELS) {
    let addr;
    try { addr = (JSON.parse(await report(model, docNonce("probe"))).signing_address || "").toLowerCase(); }
    catch (e) { console.warn(`! ${model}: ${e.message}`); continue; }
    if (!/^0x[0-9a-f]{40}$/.test(addr)) { console.warn(`! ${model}: no signing_address`); continue; }
    if (done.has(addr)) { console.log(`= ${model}: shares already-handled key ${addr}`); continue; }
    done.add(addr);

    // canonical artifact: re-fetch with the documented per-address nonce so report_data binds this key
    const raw = await report(model, docNonce(addr));
    const file = path.join(ATT_DIR, addr + ".json");
    fs.writeFileSync(file, raw);
    const att = sha(raw);
    const addr20 = hexToBytes(addr);
    const [pda, bump] = PublicKey.findProgramAddressSync([Buffer.from("tee_key"), addr20], PROGRAM);
    console.log(`\n${addr}  (via ${model})`);
    console.log(`  artifact: attestations/${addr}.json  sha256=0x${att.toString("hex")}`);
    console.log(`  PDA: ${pda.toBase58()} (bump ${bump})`);

    const exists = await conn.getAccountInfo(pda);
    if (exists) { console.log("  = already registered"); continue; }
    if (!SEND) { console.log("  [dry-run] pass --send to register"); continue; }

    const data = Buffer.concat([REGISTER_DISC, addr20, att, borshString("phala")]);
    const ix = new TransactionInstruction({ programId: PROGRAM, keys: [
      { pubkey: pda, isSigner: false, isWritable: true },
      { pubkey: authority.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ], data });
    const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash("confirmed");
    const tx = new Transaction({ recentBlockhash: blockhash, feePayer: authority.publicKey }).add(ix);
    tx.sign(authority);
    const sig = await conn.sendRawTransaction(tx.serialize(), { maxRetries: 5 });
    await conn.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, "confirmed");
    console.log(`  ✓ registered  https://solscan.io/tx/${sig}`);
  }
  console.log("\nDone.");
})().catch((e) => { console.error(e); process.exit(1); });
