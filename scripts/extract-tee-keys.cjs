#!/usr/bin/env node
// READ-ONLY. Scrape recent record_proof txs from the proof wallet and extract the
// distinct (model -> TEE signing_address) pairs actually used on-chain, so we know
// exactly which keys to register — independent of the RedPill API key.
const { Connection, PublicKey } = require("@solana/web3.js");
const PROGRAM = "D4fwqE74azXzC6euWAmDoH6Up1gZEh725odUuZHcCqEB";
const WALLET = "EfidFw4z8xAN6daskNKpENnDr6g4hgeS3AE587cuv4Re";
const RPC = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58dec(str){const m={};for(let i=0;i<A.length;i++)m[A[i]]=i;const b=[0];for(const c of str){let car=m[c];if(car===undefined)throw 0;for(let j=0;j<b.length;j++){car+=b[j]*58;b[j]=car&0xff;car>>=8;}while(car>0){b.push(car&0xff);car>>=8;}}for(let k=0;k<str.length&&str[k]==="1";k++)b.push(0);return Uint8Array.from(b.reverse());}
// Decode OLD-format record_proof: disc(8) + 6 borsh strings + i64. (Pre-upgrade.)
function decodeOld(data){try{const dv=new DataView(data.buffer,data.byteOffset,data.byteLength);let o=8;const rs=()=>{const n=dv.getUint32(o,true);o+=4;const s=new TextDecoder().decode(data.subarray(o,o+n));o+=n;return s;};return{request_id:rs(),model:rs(),req_hash:rs(),res_hash:rs(),signing_address:rs(),signature:rs()};}catch{return null;}}
(async()=>{
  const conn=new Connection(RPC,"confirmed");
  const sigs=await conn.getSignaturesForAddress(new PublicKey(WALLET),{limit:Number(process.env.LIMIT||60)});
  console.log(`scanning ${sigs.length} recent txs…`);
  const map=new Map(); // model -> Map(addr->count)
  for(const s of sigs){
    if(s.err) continue;
    let p; try{p=await conn.getParsedTransaction(s.signature,{maxSupportedTransactionVersion:0});}catch{continue;}
    if(!p) continue;
    for(const ix of p.transaction.message.instructions){
      const pid=ix.programId?.toString?.()??ix.programId;
      if(pid!==PROGRAM||typeof ix.data!=="string") continue;
      const m=decodeOld(b58dec(ix.data)); if(!m||!m.signing_address) continue;
      const addr=m.signing_address.toLowerCase();
      if(!/^0x[0-9a-f]{40}$/.test(addr)) continue;
      if(!map.has(m.model)) map.set(m.model,new Map());
      const mm=map.get(m.model); mm.set(addr,(mm.get(addr)||0)+1);
    }
  }
  console.log(`\n${map.size} model(s) with on-chain proofs:`);
  const allAddrs=new Set();
  for(const [model,mm] of map){
    const sorted=[...mm.entries()].sort((a,b)=>b[1]-a[1]);
    console.log(`  ${model.padEnd(28)} -> ${sorted.map(([a,c])=>`${a} (${c})`).join(", ")}`);
    for(const [a] of sorted) allAddrs.add(a);
  }
  console.log(`\n${allAddrs.size} distinct signing address(es) to register:`);
  for(const a of allAddrs) console.log("  "+a);
})().catch(e=>{console.error(e);process.exit(1);});
