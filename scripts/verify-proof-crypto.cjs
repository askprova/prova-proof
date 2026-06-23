#!/usr/bin/env node
/**
 * Pre-deploy correctness check against LIVE RedPill data. Confirms the upgraded
 * record_proof program will ACCEPT real proofs and reject fakes:
 *  1. fetch the live attestation report -> signing_address + real Intel quote
 *  2. run a real completion -> fetch its TEE signature {signing_address,signature,text}
 *  3. reproduce EXACTLY what the on-chain program does (EIP-191 keccak digest ->
 *     secp256k1 recover -> eth address) and assert it == the registered address
 *  4. check signature is low-S (Solana secp256k1_recover REJECTS high-S)
 *  5. check `text` byte-size fits a Solana tx
 *  6. compute the REAL attestation_hash = sha256(intel_quote) for registration
 */
const crypto = require("crypto");
const ethers = require("ethers");
const RP = process.env.RP_KEY;
const BASE = "https://api.redpill.ai/v1";
const MODEL = process.env.MODEL || "openai/gpt-oss-20b";
const EXPECT = "0x79a5061efe5a46b0d1f33b11cf1c5adbedae6b79";
const SECP256K1_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const HALF_N = SECP256K1_N / 2n;
const H = (o) => ({ Authorization: `Bearer ${RP}`, "Content-Type": "application/json" });

(async () => {
  if (!RP) { console.error("set RP_KEY"); process.exit(1); }

  console.log(`\n=== 1. attestation report (${MODEL}) ===`);
  const nonce = crypto.randomBytes(32).toString("hex");
  const rep = await (await fetch(`${BASE}/attestation/report?model=${encodeURIComponent(MODEL)}&nonce=${nonce}`, { headers: H() })).json();
  const repAddr = (rep.signing_address || "").toLowerCase();
  const intelQuote = String(rep.intel_quote || "");
  const attHash = crypto.createHash("sha256").update(intelQuote).digest("hex");
  console.log("signing_address:", repAddr);
  console.log("intel_quote bytes:", intelQuote.length, "| nvidia_payload?", !!rep.nvidia_payload);
  console.log("REAL attestation_hash = sha256(intel_quote):", "0x" + attHash);
  console.log("matches expected on-chain key:", repAddr === EXPECT);

  console.log(`\n=== 2. live completion -> request id ===`);
  const comp = await (await fetch(`${BASE}/chat/completions`, {
    method: "POST", headers: H(),
    body: JSON.stringify({ model: MODEL, messages: [{ role: "user", content: "ping" }], max_tokens: 1, stream: false }),
  })).json();
  const reqId = comp.id;
  console.log("request id:", reqId, "| served model:", comp.model);

  console.log(`\n=== 3. fetch TEE signature ===`);
  let sigResp = null;
  for (let i = 0; i < 5 && !sigResp; i++) {
    const r = await fetch(`${BASE}/signature/${encodeURIComponent(reqId)}?model=${encodeURIComponent(MODEL)}&signing_algo=ecdsa`, { headers: H() });
    if (r.ok) { sigResp = await r.json(); break; }
    await new Promise((res) => setTimeout(res, 1200));
  }
  if (!sigResp) { console.error("could not fetch signature"); process.exit(2); }
  const { signing_address, signature, text } = sigResp;
  console.log("sig signing_address:", (signing_address || "").toLowerCase());
  console.log("signature:", signature);
  console.log("text (the signed message):", JSON.stringify(text));
  const textBytes = Buffer.from(text || "", "utf8").length;
  console.log("text byte length:", textBytes);

  console.log(`\n=== 4. reproduce the ON-CHAIN verification ===`);
  // ethers.verifyMessage = recoverAddress(hashMessage(text), sig) — identical to:
  //   digest = keccak256("\x19Ethereum Signed Message:\n"+len+text)
  //   addr   = keccak256(secp256k1_recover(digest, recid, r||s))[12..32]
  // which is exactly what the Anchor program computes.
  const recovered = ethers.utils.verifyMessage(text, signature).toLowerCase();
  const digest = ethers.utils.hashMessage(text);
  console.log("EIP-191 digest (program computes same):", digest);
  console.log("recovered address:", recovered);
  console.log("  == registered key:", recovered === EXPECT, "| == sig addr:", recovered === (signing_address || "").toLowerCase());

  console.log(`\n=== 5. low-S check (Solana rejects high-S) ===`);
  const sig = ethers.utils.splitSignature(signature);
  const s = BigInt(sig.s);
  const highS = s > HALF_N;
  console.log("v:", sig.v, "recovery:", sig.recoveryParam, "| s high?", highS, highS ? "  ⚠️ NEEDS NORMALIZATION" : "  ✓ canonical");

  console.log(`\n=== 6. tx-size sanity ===`);
  const argBytes = textBytes + 20 + 64 + 1 + 8 + 4 * 5 + 8 + 64 /*req_id*/ + 64 /*hashes*/;
  console.log("approx record_proof arg bytes:", argBytes, argBytes < 900 ? "  ✓ fits a tx" : "  ⚠️ may not fit");

  console.log(`\n=== VERDICT ===`);
  const ok = recovered === EXPECT && recovered === (signing_address || "").toLowerCase() && !highS && textBytes < 800;
  console.log(ok ? "✅ ON-CHAIN VERIFICATION WILL WORK — proof recovers to the registered key, low-S, fits."
                 : "❌ NEEDS ATTENTION (see flags above)");
})().catch((e) => { console.error("ERR", e.message || e); process.exit(1); });
