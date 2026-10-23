"use strict";
// File loading, bytecode fingerprint comparison and DOM text updates only.
// No wallet connection, credentials, signing, transactions or live RPC calls.
const el = id => document.getElementById(id);
function mk(tag, klass, text) {
  const n = document.createElement(tag);
  if (klass) n.className = klass;
  if (text !== undefined) n.textContent = text == null ? "Not available" : String(text);
  return n;
}
function datum(card, label, value) {
  const wrap = mk("div", "datum");
  wrap.append(mk("span", "", label), mk("code", "", value));
  card.append(wrap);
}
function validate(d) {
  if (!d || d.schema !== "tapeout-upgrade-guard-v1" ||
      d.network?.chain_id !== 196 || !Number.isSafeInteger(d.network.block_number) ||
      !/^0x[0-9a-f]{64}$/i.test(d.network.block_hash)) {
    throw new Error("Unexpected snapshot: schema, chainId, block height, or block hash invalid");
  }
  for (const key of ["factory", "transistor_beacon", "circuit_beacon"]) {
    const c = d.components?.[key];
    const outer = c?.proxy || c?.beacon;
    if (!outer?.address || !outer?.runtime_sha256 ||
        !c?.implementation?.address || !c?.implementation?.runtime_sha256 ||
        !c?.owner_call?.state) throw new Error("Missing evidence: " + key);
  }
  return d;
}
function card(title, record) {
  const box = mk("article", "card");
  box.append(mk("h3", "", title), mk("p", "kind", record.kind));
  const outer = record.proxy || record.beacon;
  datum(box, "PROXY OR BEACON ADDRESS", outer.address);
  datum(box, "IMPLEMENTATION ADDRESS", record.implementation.address);
  datum(box, "IMPLEMENTATION RUNTIME SHA-256", record.implementation.runtime_sha256);
  datum(box, "IMPLEMENTATION SIZE", record.implementation.runtime_bytes + " bytes");
  datum(box, "OWNER() OBSERVATION", record.owner_call.state === "READ" ?
    (record.owner_call.address || "ABI null / zero; not a safety guarantee") :
    "Unavailable; do not assume ownerless");
  if (Object.hasOwn(record, "eip1967_admin_slot_address")) {
    datum(box, "EIP-1967 ADMIN SLOT", record.eip1967_admin_slot_address || "Zero; not a no-admin guarantee");
  }
  return box;
}
function display(raw) {
  const d = validate(raw);
  el("chain").textContent = String(d.network.chain_id);
  el("block").textContent = d.network.block_number.toLocaleString("en-US");
  el("time").textContent = d.network.block_timestamp_utc;
  el("count").textContent = String(Object.keys(d.components).length);
  el("block-hash").textContent = d.network.block_hash;
  el("components").replaceChildren(
    card("FACTORY", d.components.factory),
    card("TRANSISTOR BEACON", d.components.transistor_beacon),
    card("CIRCUIT BEACON", d.components.circuit_beacon)
  );
  const status = d.source?.external_doc_vs_live_implementation === "MATCH";
  el("reference").textContent = status ? "Reference and pinned pointer match" :
    "Reference differs from pinned pointer";
  el("source-note").textContent =
    "Third-party published reference: " +
    String(d.source?.external_documented_factory_implementation || "not recorded") +
    " · Pinned X Layer factory implementation slot: " +
    String(d.components.factory.implementation.address) +
    ". A mismatch may reflect an intentional upgrade or stale documentation, not an exploit.";
  el("state").textContent = "EVIDENCE VERIFIED";
}
function compare(before, after) {
  const a=validate(before),b=validate(after);
  if (b.network.block_number < a.network.block_number) {
    throw new Error("The later snapshot must have equal or greater block height.");
  }
  const changes=[];
  for (const label of ["factory","transistor_beacon","circuit_beacon"]) {
    const ca=a.components[label],cb=b.components[label],outer=label==="factory"?"proxy":"beacon";
    for (const part of [outer,"implementation"]) {
      for (const field of ["address","runtime_sha256","runtime_bytes"]) {
        if (!Object.hasOwn(ca[part],field)||!Object.hasOwn(cb[part],field)) {
          throw new Error("Incomplete code evidence for "+label+"."+part+"."+field);
        }
        if (ca[part][field]!==cb[part][field]) {
          changes.push(label+" / "+part+"."+field+": "+ca[part][field]+" → "+cb[part][field]);
        }
      }
    }
    const extras=["owner_call"];
    if(label==="factory")extras.push("eip1967_admin_slot_address");
    for(const field of extras){
      if(!Object.hasOwn(ca,field)||!Object.hasOwn(cb,field))throw new Error("Missing "+label+"."+field);
      if(JSON.stringify(ca[field])!==JSON.stringify(cb[field])){
        changes.push(label+" / "+field+": "+JSON.stringify(ca[field])+" → "+JSON.stringify(cb[field]));
      }
    }
  }
  return changes;
}
async function localFile(id) {
  const files=el(id).files;
  if(!files||files.length!==1)throw new Error("Select "+id+" JSON evidence.");
  if(files[0].size>1024*1024)throw new Error("Evidence JSON file too large (>1 MiB).");
  return JSON.parse(await files[0].text());
}
el("compare-button").addEventListener("click",async()=>{
  const output=el("result");
  output.replaceChildren(mk("span","","Checking local files…"));
  try{
    const before=await localFile("before"),after=await localFile("after");
    const changes=compare(before,after);
    output.replaceChildren(mk("strong","",changes.length?String(changes.length)+" observed field changes; human review required":"No observed difference in compared fields"));
    output.append(mk("p","","Blocks "+before.network.block_number+" → "+after.network.block_number+
      ". An unchanged pair cannot rule out changes between observations."));
    if(changes.length){
      const ul=mk("ul");
      for(const change of changes)ul.append(mk("li","",change));
      output.append(ul);
    }
  }catch(error){output.replaceChildren(mk("span","","Cannot compare: "+String(error.message)))}
});
fetch("./latest.json",{cache:"no-store"})
  .then(response=>{
    if(!response.ok)throw new Error("Published evidence unavailable, HTTP "+response.status);
    return response.json();
  })
  .then(display)
  .catch(error=>{
    el("state").className="badge bad";
    el("state").textContent="EVIDENCE NOT VERIFIED";
    el("components").replaceChildren(mk("p","",error.message));
  });
