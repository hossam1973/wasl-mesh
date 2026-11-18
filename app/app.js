/* وَصْل — offline mesh messenger.
 * Transport: WebRTC data channels between devices on the same local network
 * (hotspot / Wi-Fi without internet). No STUN/TURN, no signalling server:
 * the first link is paired with a QR code, later links are signalled through the mesh.
 * Every device floods packets onward (TTL + dedup) and keeps a store-and-forward cache.
 * Private payloads: ECDH P-256 -> AES-GCM-256, signed with ECDSA P-256.
 * Ledger: per-device signed hash chain of message fingerprints, witnessed by peers.
 */
'use strict';
(() => {
const subtle = crypto.subtle, enc = new TextEncoder(), dec = new TextDecoder();
const $ = s => document.querySelector(s);
const TTL = 8, CHUNK = 16 * 1024, MAX_FILE = 25 * 1024 * 1024, CARD_EVERY = 20000;
const SOS = '*sos';

/* ---------- utils ---------- */
const b64e = buf => { const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf); let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const b64d = str => { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '=';
  const s = atob(str), b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i); return b; };
const hex = buf => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');
const sha = async data => hex(await subtle.digest('SHA-256', typeof data === 'string' ? enc.encode(data) : data));
const rid = () => hex(crypto.getRandomValues(new Uint8Array(10)));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtSize = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(0) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
const fmtTime = ts => new Date(ts).toLocaleTimeString('ar', { hour: '2-digit', minute: '2-digit' });
const COLORS = ['#0d7a68', '#2b6cb0', '#9c4221', '#6b46c1', '#b7791f', '#2f855a', '#c53030', '#2c7a7b', '#805ad5', '#d53f8c'];
const colorOf = id => COLORS[parseInt(String(id).replace(/\W/g, '').slice(0, 6) || '0', 16) % COLORS.length];
const initial = name => (name || '؟').trim().charAt(0).toUpperCase() || '؟';
async function deflate(str) {
  const cs = new CompressionStream('deflate-raw'); const w = cs.writable.getWriter();
  w.write(enc.encode(str)); w.close(); return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}
async function inflate(bytes) {
  const ds = new DecompressionStream('deflate-raw'); const w = ds.writable.getWriter();
  w.write(bytes); w.close(); return dec.decode(await new Response(ds.readable).arrayBuffer());
}
let toastT;
function toast(msg, sos) { const t = $('#toast'); t.textContent = msg; t.className = sos ? 'sos' : ''; t.hidden = false;
  clearTimeout(toastT); toastT = setTimeout(() => t.hidden = true, sos ? 7000 : 3200); }

/* ---------- storage (IndexedDB) ---------- */
const db = {
  p: null,
  open() { return this.p ||= new Promise((res, rej) => { const r = indexedDB.open('wasl', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); },
  async get(k) { const d = await this.open(); return new Promise((res, rej) => { const q = d.transaction('kv').objectStore('kv').get(k);
    q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); }); },
  async set(k, v) { const d = await this.open(); return new Promise((res, rej) => { const t = d.transaction('kv', 'readwrite');
    t.objectStore('kv').put(v, k); t.oncomplete = res; t.onerror = () => rej(t.error); }); },
};
const saveT = {};
const saveLater = (k, getter) => { clearTimeout(saveT[k]); saveT[k] = setTimeout(() => db.set(k, getter()).catch(() => {}), 400); };

/* ---------- state ---------- */
const ME = {};                    // id, name, keys
let contacts = {};                // id -> {id,name,sPub,ePub,hops,seen,head}
let chats = {};                   // peerId -> [msg]
let ledger = { blocks: [], pending: [] };
let witness = {};                 // peerId -> {i,h,ts,fork}
const keys = {};                  // peerId -> {vk, aes}
const links = new Map();          // peerId -> link
const seen = new Map();           // pid -> ts
const outbox = new Map();         // pid -> {pkt, ref}
const dtn = new Map();            // pid -> {pkt, ts}   (store-and-forward for others)
const stash = [];                 // packets from unknown senders
const cardPkts = {};              // peerId -> last signed card packet (handed to newly met devices)
const incoming = {};              // fileId -> {meta, parts, got}
const stats = { relayed: 0, sent: 0, recv: 0 };
let active = null;                // open chat peerId

/* ---------- identity ---------- */
const pubJwk = j => ({ kty: j.kty, crv: j.crv, x: j.x, y: j.y });
const fpOf = async jwk => { const h = (await sha(jwk.x + '.' + jwk.y)).toUpperCase(); return h.slice(0, 4) + '-' + h.slice(4, 8) + '-' + h.slice(8, 12); };
async function loadIdentity() {
  let idn = await db.get('identity'), fresh = false;
  if (!idn) {
    const s = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const e = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    idn = { name: '', sPriv: await subtle.exportKey('jwk', s.privateKey), sPub: pubJwk(await subtle.exportKey('jwk', s.publicKey)),
      ePriv: await subtle.exportKey('jwk', e.privateKey), ePub: pubJwk(await subtle.exportKey('jwk', e.publicKey)) };
    await db.set('identity', idn); fresh = true;
  }
  ME.sKey = await subtle.importKey('jwk', idn.sPriv, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  ME.vKey = await subtle.importKey('jwk', idn.sPub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  ME.eKey = await subtle.importKey('jwk', idn.ePriv, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
  ME.sPub = idn.sPub; ME.ePub = idn.ePub; ME.name = idn.name; ME.idn = idn; ME.callsign = idn.callsign || '';
  ME.id = await fpOf(idn.sPub);
  return fresh;
}
const sign = async data => b64e(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, ME.sKey, enc.encode(data)));
async function verifyWith(jwk, data, sig) {
  try { const k = await subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, b64d(sig), enc.encode(data)); } catch { return false; }
}
async function keyFor(id) {
  const c = contacts[id]; if (!c) throw new Error('unknown contact');
  if (!keys[id]) keys[id] = {
    vk: await subtle.importKey('jwk', c.sPub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']),
    aes: await subtle.deriveKey({ name: 'ECDH', public: await subtle.importKey('jwk', c.ePub, { name: 'ECDH', namedCurve: 'P-256' }, false, []) },
      ME.eKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
  };
  return keys[id];
}

/* ---------- identity cards (signed presence) ---------- */
const headInfo = () => { const b = ledger.blocks[ledger.blocks.length - 1]; return b ? { i: b.i, h: b.hash } : null; };
async function makeCard() {
  const body = JSON.stringify({ id: ME.id, name: ME.name, sPub: ME.sPub, ePub: ME.ePub, ts: Date.now(), head: headInfo(),
    nb: [...links.keys()], bt: ME.batt || null, st: Date.now() < (ME.alertUntil || 0) ? 'alert' : 'ok', rl: stats.relayed });
  return { body, sig: await sign(body) };
}
async function openCard(card) {
  try { const c = JSON.parse(card.body);
    if (!(await verifyWith(c.sPub, card.body, card.sig))) return null;
    if ((await fpOf(c.sPub)) !== c.id) return null;
    return c; } catch { return null; }
}
async function learnContact(c, hops, via = 'ip') {
  if (c.id === ME.id) return;
  const old = contacts[c.id];
  if (old && (old.sPub.x !== c.sPub.x || old.sPub.y !== c.sPub.y)) return; // id is bound to key; ignore impostors
  if (old && c.ts < (old.ts || 0)) return; // stale card
  contacts[c.id] = { ...(old || {}), id: c.id, name: c.name || old?.name || '', sPub: c.sPub, ePub: c.ePub, ts: c.ts,
    hops: links.has(c.id) ? 1 : hops, via: links.has(c.id) ? 'ip' : via, seen: Date.now(), nb: c.nb || [], bt: c.bt || null, st: c.st || 'ok', rl: c.rl || 0 };
  if (old && old.ePub && old.ePub.x !== c.ePub.x) delete keys[c.id];
  if (c.head) checkWitness(c.id, c.head);
  saveLater('contacts', () => contacts);
  const pending = stash.splice(0).filter(p => { if (p.src === c.id) { onSecure(p.pkt, p.hops); return false; } return true; });
  stash.push(...pending);
  renderSoon();
}

/* ---------- links (WebRTC data channels) ---------- */
function newLink(expectId) {
  const pc = new RTCPeerConnection({ iceServers: [] });
  const link = { pc, dc: null, id: null, expectId, call: null };
  pc.onconnectionstatechange = () => { if (['failed', 'closed', 'disconnected'].includes(pc.connectionState)) setTimeout(() => {
    if (['failed', 'closed', 'disconnected'].includes(pc.connectionState)) dropLink(link); }, pc.connectionState === 'disconnected' ? 4000 : 0); };
  pc.ontrack = () => onRemoteTrack(link);
  pc.ondatachannel = e => attachDC(link, e.channel);
  return link;
}
function attachDC(link, dc) {
  link.dc = dc; dc.binaryType = 'arraybuffer';
  dc.onopen = async () => dc.send(JSON.stringify({ t: 'hello', card: await makeCard() }));
  dc.onmessage = e => { let m; try { m = JSON.parse(e.data); } catch { return; } onLinkMsg(link, m).catch(err => console.warn(err)); };
  dc.onclose = () => dropLink(link);
}
function dropLink(link) {
  if (link.dropped) return; link.dropped = true;
  try { link.pc.close(); } catch {}
  if (link.id && links.get(link.id) === link) {
    links.delete(link.id);
    const standby = [...NATIVE.links.values()].find(l => l !== link && l.id === link.id && !l.dropped);
    if (standby) { links.set(link.id, standby); renderSoon(); return; }        // fall back to the Bluetooth / Wi-Fi Direct link
    if (contacts[link.id]) contacts[link.id].hops = 9;
    if (CALL.peer === link.id) endCall(false, 'انقطع الاتصال');
    sysMsg(link.id, 'انقطع الرابط المباشر. الرسائل ستُمرَّر عبر الأجهزة الأخرى إن أمكن.');
    announce();
  }
  renderSoon();
}
const rawSend = (link, obj) => { try { if (link.dc && link.dc.readyState === 'open') { link.dc.send(JSON.stringify(obj)); return true; } } catch {} return false; };

async function onLinkMsg(link, m) {
  if (m.t === 'hello') {
    const c = await openCard(m.card); if (!c || c.id === ME.id) return dropLink(link);
    if (link.expectId && link.expectId !== c.id) return dropLink(link);
    const prev = links.get(c.id);
    if (prev && prev !== link) {
      if (link.native && !prev.native) { link.id = c.id; flushTo(link); return; }   // keep the WebRTC link (it carries calls); native stays on standby
      if (!prev.native) dropLink(prev);
    }
    link.id = c.id; links.set(c.id, link);
    await learnContact(c, 1); contacts[c.id].hops = 1;
    sysMsg(c.id, link.native ? 'رابط مباشر عبر البلوتوث / Wi-Fi Direct. الرسائل والملفات متاحة. للمكالمات اتصلوا بنفس نقطة الاتصال.' : 'رابط مباشر نشط. المكالمات متاحة.');
    toast(`اتصل ${c.name || c.id} مباشرة`);
    flushTo(link); announce();
    if (pairing && pairing.link === link) pairDone(c);
    return;
  }
  if (!link.id) return;
  if (m.t === 'pkt') return handlePacket(m.p, link);
  if (m.t === 'call') return onCallSignal(link, m);
  if (m.t === 'neg') return onNegotiation(link, m);
}

/* ---------- SDP codes ---------- */
async function waitIce(pc) {
  if (pc.iceGatheringState === 'complete') return;
  await new Promise(r => { const f = () => { if (pc.iceGatheringState === 'complete') { pc.removeEventListener('icegatheringstatechange', f); r(); } };
    pc.addEventListener('icegatheringstatechange', f); setTimeout(r, 4000); });
}
const packDesc = async d => 'WASL1.' + b64e(await deflate(JSON.stringify({ t: d.type, s: d.sdp })));
async function unpackDesc(code) {
  code = code.trim(); if (!code.startsWith('WASL1.')) throw new Error('رمز غير صالح');
  const o = JSON.parse(await inflate(b64d(code.slice(6)))); return { type: o.t, sdp: o.s };
}
async function makeOffer(expectId) {
  const link = newLink(expectId);
  attachDC(link, link.pc.createDataChannel('mesh', { ordered: true }));
  await link.pc.setLocalDescription(await link.pc.createOffer());
  await waitIce(link.pc);
  return { link, code: await packDesc(link.pc.localDescription) };
}
async function answerOffer(code, expectId) {
  const desc = await unpackDesc(code); if (desc.type !== 'offer') throw new Error('هذا رمز رد، وليس رمز ربط');
  const link = newLink(expectId);
  await link.pc.setRemoteDescription(desc);
  await link.pc.setLocalDescription(await link.pc.createAnswer());
  await waitIce(link.pc);
  return { link, code: await packDesc(link.pc.localDescription) };
}
async function acceptAnswer(link, code) {
  const desc = await unpackDesc(code); if (desc.type !== 'answer') throw new Error('هذا رمز ربط، وليس رمز رد');
  await link.pc.setRemoteDescription(desc);
}

/* ---------- mesh packets ---------- */
function markSeen(pid) { seen.set(pid, Date.now()); if (seen.size > 5000) { const cut = Date.now() - 600000; for (const [k, v] of seen) if (v < cut) seen.delete(k); } }
function flood(pkt, except) {
  let n = 0; for (const l of links.values()) if (l !== except && rawSend(l, { t: 'pkt', p: pkt })) n++;
  for (const port of radios.values()) if (port !== except && port.state === 'on' && radioSend(port, pkt)) n++;
  return n;
}

/* ---------- radio layers (LoRa / HF / VHF): what each may carry ---------- */
const radios = new Map();                 // kind -> WaslRadio port
const VIA = { ip: 'Wi-Fi / IP', lora: 'LoRa', hf: 'HF', vhf: 'VHF' };
const NARROW = { ip: 0, lora: 1, vhf: 2, hf: 3 };
const narrowest = (a = 'ip', b = 'ip') => (NARROW[a] ?? 0) >= (NARROW[b] ?? 0) ? a : b;   // slowest layer along a path
function radioPolicy(port, pkt, size) {
  if (!port.encrypt && pkt.type === 'sec') return 'التشفير ممنوع على موجات الهواة';
  if (size > port.maxPkt) return 'الحزمة أكبر من قدرة الطبقة';
  if (pkt.type === 'card') { const last = port.cardTs[pkt.src] || 0; if (Date.now() - last < port.cardEvery) return 'بطاقة حديثة أُرسلت'; }
  return null;
}
function radioSend(port, pkt) {
  const p2 = { ...pkt, lw: narrowest(pkt.lw, port.kind) };
  const wrap = JSON.stringify(!port.encrypt && ME.callsign ? { cs: ME.callsign, p: p2 } : { p: p2 });
  if (!port.encrypt && !ME.callsign) return false;                       // amateur bands require station identification
  if (radioPolicy(port, pkt, wrap.length)) return false;
  if (pkt.type === 'card') port.cardTs[pkt.src] = Date.now();
  deflate(wrap).then(b => port.send(b)).catch(() => {});
  return true;
}
async function onRadioPayload(port, bytes) {
  let w; try { w = JSON.parse(await inflate(bytes)); } catch { return; }
  if (w.cs) port.lastCall = w.cs;
  if (w.p) await handlePacket(w.p, port);
}
function attachRadio(port) {
  const old = radios.get(port.kind); if (old && old !== port) old.close?.();
  radios.set(port.kind, port);
  port.onPayload = b => onRadioPayload(port, b);
  port.onState = (st, msg) => { if (msg) toast(`${VIA[port.kind]}: ${msg}`); if (st === 'on') announce(); renderSoon(); };
  if (port.state === 'on') announce();
  renderSoon(); return port;
}
async function connectRadio(kind, how) {
  if (kind !== 'lora' && !ME.callsign) { toast('أدخل نداء الهواة (Callsign) أولاً، فهو إلزامي قانونياً على HF/VHF'); return; }
  const R = window.WaslRadio;
  const port = how === 'audio' ? new R.AudioModemPort(kind) : new R.SerialKissPort(kind);
  attachRadio(port);
  try { await port.open(kind === 'lora' ? 115200 : 9600); toast(`${VIA[kind]}: متصل`); }
  catch (e) { radios.delete(kind); toast(`${VIA[kind]}: ${e.message || 'تعذّر الاتصال'}`); }
  renderSoon();
}
function emit(type, dst, body, extra = {}) {
  const pkt = { pid: rid(), src: ME.id, dst, ttl: TTL, h: 0, type, body, ts: Date.now(), ...extra };
  markSeen(pkt.pid); const n = flood(pkt); stats.sent++;
  return { pkt, n };
}
async function handlePacket(pkt, from) {
  if (!pkt || !pkt.pid || seen.has(pkt.pid)) return;
  markSeen(pkt.pid); stats.recv++;
  const hops = (pkt.h || 0) + 1;
  if (pkt.src === ME.id) return;
  if (GOSSIP_TYPES.has(pkt.type) && pkt.ttl > 1) keepGossip({ ...pkt, ttl: pkt.ttl - 1, h: hops });
  const via = narrowest(pkt.lw, from && from.kind ? from.kind : 'ip');
  if (pkt.dst === '*' || pkt.dst === ME.id) await deliver(pkt, hops, via);
  if (pkt.dst !== ME.id && pkt.ttl > 1) {
    const fwd = { ...pkt, ttl: pkt.ttl - 1, h: hops, lw: via };
    if (pkt.dst !== '*') { dtn.set(pkt.pid, { pkt: fwd, ts: Date.now() }); pruneDtn(); }
    if (flood(fwd, from)) stats.relayed++;
  }
}
function pruneDtn() { const cut = Date.now() - 3600000; for (const [k, v] of dtn) if (v.ts < cut || dtn.size > 400) dtn.delete(k); }
function flushTo(link) {  // store-and-forward: hand known identities and pending packets to a newly met device
  for (const [id, pkt] of Object.entries(cardPkts)) if (id !== link.id) rawSend(link, { t: 'pkt', p: pkt });
  for (const { pkt } of gossip.values()) rawSend(link, { t: 'pkt', p: pkt });   // broadcasts, decisions, timers reach late joiners
  for (const { pkt } of outbox.values()) rawSend(link, { t: 'pkt', p: pkt });
  for (const { pkt } of dtn.values()) rawSend(link, { t: "pkt", p: pkt });
}
async function announce() { emit('card', '*', await makeCard()); renderSoon(); }

async function deliver(pkt, hops, via = 'ip') {
  if (pkt.type === 'card') { const c = await openCard(pkt.body);
    if (c && c.id === pkt.src) { await learnContact(c, hops, via); if (pkt.ttl > 1) cardPkts[c.id] = { ...pkt, ttl: pkt.ttl - 1, h: hops }; } return; }
  if (pkt.type === 'sos') return onSOS(pkt, hops);
  if (GOSSIP_TYPES.has(pkt.type)) return onOps(pkt.type, pkt.body, pkt.src);
  if (pkt.type === 'sec') { if (!contacts[pkt.src]) { stash.push({ src: pkt.src, pkt, hops }); if (stash.length > 200) stash.shift(); return; } return onSecure(pkt, hops); }
}

/* ---------- encrypted messaging ---------- */
async function sendSecure(dst, obj, ref) {
  const { aes } = await keyFor(dst);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = b64e(await subtle.encrypt({ name: 'AES-GCM', iv }, aes, enc.encode(JSON.stringify(obj))));
  const pid = rid(), ivs = b64e(iv);
  const sig = await sign(pid + '|' + dst + '|' + ivs + '|' + ct);
  const pkt = { pid, src: ME.id, dst, ttl: TTL, h: 0, type: 'sec', body: { iv: ivs, ct, sig }, ts: Date.now() };
  markSeen(pid);
  if (ref) outbox.set(pid, { pkt, ref });
  const n = flood(pkt); stats.sent++;
  return { pid, n, ct };
}
async function onSecure(pkt, hops) {
  const c = contacts[pkt.src]; const { iv, ct, sig } = pkt.body || {};
  if (!(await verifyWith(c.sPub, pkt.pid + '|' + pkt.dst + '|' + iv + '|' + ct, sig))) return;
  let m; try { const { aes } = await keyFor(pkt.src);
    m = JSON.parse(dec.decode(await subtle.decrypt({ name: 'AES-GCM', iv: b64d(iv) }, aes, b64d(ct)))); } catch { return; }
  const from = pkt.src;
  switch (m.k) {
    case 'text':
      addMsg(from, { id: m.id, mine: false, kind: 'text', text: m.text, ts: m.ts, hops });
      logEntry('in', from, await sha(ct)); ack(from, m.id); notify(from, m.text); break;
    case 'file':
      (incoming[m.id] ||= { parts: [], got: 0 }).meta = m;
      addMsg(from, { id: m.id, mine: false, kind: 'file', name: m.name, type: m.type, size: m.size, voice: m.voice, ts: m.ts, hops, progress: 0 });
      tryAssemble(from, m.id); break;
    case 'chunk': {
      const f = (incoming[m.id] ||= { parts: [], got: 0 });
      if (!f.parts[m.i]) { f.parts[m.i] = b64d(m.d); f.got++; }
      tryAssemble(from, m.id); break; }
    case 'ack': setStatus(from, m.ref, 'delivered'); for (const [pid, o] of outbox) if (o.ref === m.ref) outbox.delete(pid); break;
    case 'read': for (const r of m.refs) setStatus(from, r, 'read'); break;
    case 'sig': onMeshSignal(from, m); break;
  }
}
function ack(to, ref) { sendSecure(to, { k: 'ack', ref }).catch(() => {}); }
async function tryAssemble(from, id) {
  const f = incoming[id]; if (!f || !f.meta) return;
  const msg = findMsg(from, id); if (!msg) return;
  msg.progress = f.got / f.meta.n; renderMsgSoon(from);
  if (f.got < f.meta.n) return;
  const blob = new Blob(f.parts, { type: f.meta.type || 'application/octet-stream' });
  msg.blob = blob; delete msg.progress; delete incoming[id];
  logEntry('in', from, f.meta.h || await sha(await blob.arrayBuffer()));
  ack(from, id); notify(from, msg.voice ? 'رسالة صوتية' : 'ملف: ' + msg.name);
  saveChats(); renderMsgSoon(from);
}

async function sendText(to, text) {
  const m = { id: rid(), mine: true, kind: 'text', text, ts: Date.now(), status: 'pending' };
  addMsg(to, m);
  const { n, ct } = await sendSecure(to, { k: 'text', id: m.id, text, ts: m.ts }, m.id);
  m.status = n ? 'sent' : 'queued'; logEntry('out', to, await sha(ct)); saveChats(); renderMsgSoon(to);
}
async function sendFile(to, file, voice) {
  if (file.size > MAX_FILE) return toast('الحد الأقصى للملف عبر الشبكة 25 ميغابايت');
  const via = links.has(to) ? 'ip' : contacts[to]?.via || 'ip';
  if (via === 'hf' || via === 'vhf') return toast('نقل الملفات غير متاح عبر HF/VHF: الطبقة بطيئة جداً والتشفير ممنوع عليها');
  if (via === 'lora' && file.size > 12 * 1024) return toast('عبر LoRa يمكن إرسال ملفات حتى 12 كيلوبايت فقط. للملفات الأكبر يلزم رابط Wi-Fi أو مايكروويف');
  const CH = file.size <= 12 * 1024 ? 1500 : CHUNK;
  const buf = new Uint8Array(await file.arrayBuffer()); const n = Math.max(1, Math.ceil(buf.length / CH));
  const m = { id: rid(), mine: true, kind: 'file', name: file.name || 'voice.webm', type: file.type, size: buf.length, voice: !!voice,
    ts: Date.now(), status: 'pending', blob: new Blob([buf], { type: file.type }), progress: 0 };
  addMsg(to, m);
  const h = await sha(buf);
  const first = await sendSecure(to, { k: 'file', id: m.id, name: m.name, type: m.type, size: m.size, n, voice: m.voice, ts: m.ts, h }, m.id);
  for (let i = 0; i < n; i++) {
    for (const l of links.values()) while (l.dc && l.dc.bufferedAmount > 1 << 20) await sleep(30);
    await sendSecure(to, { k: 'chunk', id: m.id, i, d: b64e(buf.subarray(i * CH, (i + 1) * CH)) }, m.id);
    m.progress = (i + 1) / n; if (i % 4 === 0 || i === n - 1) renderMsgSoon(to);
  }
  delete m.progress; m.status = first.n ? 'sent' : 'queued';
  logEntry('out', to, h); saveChats(); renderMsgSoon(to);
}

/* ---------- operations (merged from NexLink Control Center, rebuilt to run on the mesh itself) ----------
 * typed broadcasts + human acknowledgements, MultiSig group decisions, TimeBomb safety timers,
 * device status (battery / alert / relays) and a live network-health score with topology. */
const BT = { SOS: { l: 'استغاثة', e: '🚨' }, EVAC: { l: 'إخلاء', e: '📢' }, WARN: { l: 'تحذير', e: '⚠️' }, TEST: { l: 'اختبار', e: '🧪' } };
let ops = { bc: {}, props: {}, psigs: {}, tbs: {} };
const gossip = new Map();                       // pid -> {pkt, ts}: public packets handed to devices we meet later
const GOSSIP_TYPES = new Set(['sos', 'back', 'prop', 'psig', 'tb', 'tbx', 'tbf']);
function keepGossip(pkt) {
  gossip.set(pkt.pid, { pkt, ts: Date.now() });
  const cut = Date.now() - 86400000;
  for (const [k, v] of gossip) if (v.ts < cut || gossip.size > 300) gossip.delete(k);
}
const saveOps = () => saveLater('ops', () => ops);
const fmtDur = ms => { const m = Math.round(ms / 60000); return m < 1 ? 'أقل من دقيقة' : m < 60 ? `${m} دقيقة` : m < 1440 ? `${(m / 60).toFixed(m < 600 ? 1 : 0)} ساعة` : `${Math.round(m / 1440)} يوم`; };
const nameOf = id => id === ME.id ? (ME.name || 'أنا') : (contacts[id]?.name || id);
async function signedObj(obj) { const body = JSON.stringify({ ...obj, by: ME.id, pk: ME.sPub, ts: Date.now() }); return { body, sig: await sign(body) }; }
async function openedObj(b) {
  try { const o = JSON.parse(b.body); if ((await fpOf(o.pk)) !== o.by) return null;
    return (await verifyWith(o.pk, b.body, b.sig)) ? o : null; } catch { return null; }
}
async function publish(type, obj) {
  const b = await signedObj(obj); const { pkt } = emit(type, '*', b); keepGossip(pkt);
  await onOps(type, b, ME.id); return JSON.parse(b.body);
}

/* typed broadcasts */
async function sendSOS(text, ty = 'SOS') {
  if (!BT[ty]) ty = 'SOS';
  const bid = rid(), ts = Date.now();
  const body = JSON.stringify({ id: ME.id, name: ME.name, sPub: ME.sPub, text, ts, ty, bid });
  const { pkt } = emit('sos', '*', { body, sig: await sign(body) }); keepGossip(pkt);
  ops.bc[bid] = { bid, ty, text, from: ME.name || ME.id, fromId: ME.id, ts, acks: {}, reach: Object.keys(contacts).filter(id => reachOf(id).cls).length };
  if (ty === 'SOS') { ME.alertUntil = ts + 1800000; announce(); }
  saveOps();
  addMsg(SOS, { id: bid, mine: true, kind: 'sos', ty, bid, text, ts, status: 'sent', from: ME.name || ME.id });
  logEntry('out', SOS, await sha(body)); renderOpsSoon();
}
async function onSOS(pkt, hops) {
  const { body, sig } = pkt.body || {}; let o; try { o = JSON.parse(body); } catch { return; }
  if (o.id !== pkt.src || (await fpOf(o.sPub)) !== o.id || !(await verifyWith(o.sPub, body, sig))) return;
  const ty = BT[o.ty] ? o.ty : 'SOS', bid = o.bid || pkt.pid, from = o.name || o.id;
  const prev = ops.bc[bid];
  ops.bc[bid] = { acks: {}, ...(prev || {}), bid, ty, text: o.text, from, fromId: o.id, ts: o.ts }; saveOps();
  addMsg(SOS, { id: bid, mine: false, kind: 'sos', ty, bid, text: o.text, ts: o.ts, hops, from, fromId: o.id });
  logEntry('in', SOS, await sha(body));
  if (ty === 'TEST') toast(`🧪 بث اختبار من ${from}: ${o.text}`);
  else { toast(`${BT[ty].e} ${BT[ty].l} من ${from}: ${o.text}`, true);
    try { navigator.vibrate && navigator.vibrate([400, 150, 400, 150, 400]); } catch {} beep(3); }
  renderOpsSoon();
}
const ackBroadcast = bid => publish('back', { bid });

/* MultiSig group decisions */
async function createProposal(title, text, signers, th, evac) {
  signers = [...new Set(signers)]; th = Math.max(1, Math.min(th, signers.length));
  const o = await publish('prop', { pid: rid(), title, text, signers, th, evac: !!evac });
  if (signers.includes(ME.id)) await signProposal(o.pid);
  return o.pid;
}
async function signProposal(pid) { const p = ops.props[pid]; if (!p || !p.signers.includes(ME.id)) return; await publish('psig', { pid, h: p.h }); }
function evalProp(pid) {
  const p = ops.props[pid]; if (!p) return;
  const valid = Object.entries(ops.psigs[pid] || {}).filter(([by, h]) => p.signers.includes(by) && h === p.h).map(([by]) => by);
  p.signed = valid;
  if (p.state === 'open' && valid.length >= p.th) {
    p.state = 'done'; p.doneAt = Date.now();
    if (p.evac) {
      addMsg(SOS, { id: 'prop-' + pid, mine: false, kind: 'sos', ty: 'EVAC', text: `${p.title}: ${p.text} (قرار موثّق بتوقيع ${valid.length} من ${p.signers.length})`, ts: Date.now(), from: 'قرار جماعي' });
      toast(`📢 قرار إخلاء موثّق: ${p.title}`, true); beep(3);
      try { navigator.vibrate && navigator.vibrate([600, 200, 600]); } catch {}
    } else toast(`اكتملت التواقيع: ${p.title}`);
  }
  saveOps(); renderOpsSoon();
}

/* TimeBomb safety timers, watched by every other device */
const armTimer = (ms, msg) => publish('tb', { tid: rid(), ms, msg, name: ME.name });
const disarmTimer = tid => publish('tbx', { tid });
function lastHeard(id) { return Math.max(contacts[id]?.seen || 0, links.has(id) ? Date.now() : 0); }
async function checkTimers() {
  for (const t of Object.values(ops.tbs)) {
    if (t.by === ME.id) continue;
    const last = Math.max(t.ts, lastHeard(t.by));
    if (t.state === 'armed' && Date.now() - last > t.ms) { fireTimer(t, ME.id, last); publish('tbf', { tid: t.tid }); }
    else if (t.state === 'fired' && last > t.firedAt) { t.state = 'armed'; saveOps(); toast(`عاد ${nameOf(t.by)} للظهور في الشبكة`); }
  }
  renderOpsSoon();
}
function fireTimer(t, det, last) {
  if (t.state !== 'armed') return;
  t.state = 'fired'; t.firedAt = Date.now(); t.det = det; saveOps();
  const since = fmtDur(Date.now() - (last || lastHeard(t.by) || t.ts));
  addMsg(SOS, { id: 'tb-' + t.tid + '-' + t.firedAt, mine: false, kind: 'sos', ty: 'SOS', ts: Date.now(), from: 'مؤقّت الأمان',
    text: `لم يُسمع من ${nameOf(t.by)} منذ ${since}. رسالته المسبقة: ${t.msg || '—'}` });
  toast(`🚨 مؤقّت الأمان: انقطع ${nameOf(t.by)} منذ ${since}`, true); beep(3);
}

async function onOps(type, b, src) {
  const o = await openedObj(b || {}); if (!o || o.by !== src) return;
  switch (type) {
    case 'back': { const bc = (ops.bc[o.bid] ||= { bid: o.bid, acks: {} }); bc.acks[o.by] = o.ts; if (active === SOS) renderMsgSoon(SOS); break; }
    case 'prop':
      if (!ops.props[o.pid]) { ops.props[o.pid] = { ...o, h: await sha(b.body), state: 'open', signed: [] };
        if (o.by !== ME.id && o.signers.includes(ME.id)) toast(`طُلب توقيعك على قرار: ${o.title}`); }
      evalProp(o.pid); break;
    case 'psig': (ops.psigs[o.pid] ||= {})[o.by] = o.h; evalProp(o.pid); break;
    case 'tb': if (!ops.tbs[o.tid]) ops.tbs[o.tid] = { ...o, ts: Date.now(), state: 'armed' }; break;
    case 'tbx': { const t = ops.tbs[o.tid]; if (t && t.by === o.by) t.state = 'off'; break; }
    case 'tbf': { const t = ops.tbs[o.tid]; if (t && t.by !== ME.id && Date.now() - Math.max(t.ts, lastHeard(t.by)) > t.ms) fireTimer(t, o.by); break; }
  }
  saveOps(); renderOpsSoon();
}

/* network health + topology */
function health() {
  const reach = Object.keys(contacts).filter(id => reachOf(id).cls);
  const nodes = [ME.id, ...reach], set = new Set(nodes), adj = {};
  nodes.forEach(n => adj[n] = new Set());
  const add = (a, b) => { if (a !== b && set.has(a) && set.has(b)) { adj[a].add(b); adj[b].add(a); } };
  for (const id of links.keys()) add(ME.id, id);
  for (const id of reach) for (const n of contacts[id].nb || []) add(id, n);
  const edges = nodes.reduce((s, n) => s + adj[n].size, 0) / 2;
  const seenC = new Set(); let clusters = 0;
  for (const n of nodes) if (!seenC.has(n)) { clusters++; const q = [n]; seenC.add(n); while (q.length) for (const m of adj[q.shift()]) if (!seenC.has(m)) { seenC.add(m); q.push(m); } }
  let t = 0, bridges = 0; const tin = {}, low = {};
  const dfs = (v, p) => { tin[v] = low[v] = t++; for (const u of adj[v]) { if (u === p) continue;
    if (tin[u] !== undefined) low[v] = Math.min(low[v], tin[u]); else { dfs(u, v); low[v] = Math.min(low[v], low[u]); if (low[u] > tin[v]) bridges++; } } };
  for (const n of nodes) if (tin[n] === undefined) dfs(n, null);
  const known = Object.keys(contacts).length;
  const conn = known ? reach.length / known : 0, avgDeg = nodes.length ? (2 * edges) / nodes.length : 0;
  const score = known ? Math.round(100 * (0.4 * conn + 0.3 * Math.min(1, avgDeg / 3) + 0.3 * (edges ? 1 - bridges / edges : 0))) : 0;
  const hopsL = reach.map(id => contacts[id].hops).filter(h => h < 9);
  return { score, label: score >= 80 ? 'ممتاز' : score >= 60 ? 'جيد' : score >= 40 ? 'مقبول' : 'ضعيف', nodes, adj, edges, clusters, bridges, known, reach: reach.length,
    avgHops: hopsL.length ? (hopsL.reduce((a, b) => a + b, 0) / hopsL.length).toFixed(1) : '0', alerts: reach.filter(id => contacts[id].st === 'alert').length + (Date.now() < (ME.alertUntil || 0) ? 1 : 0) };
}
function drawTopo(h) {
  const cv = $('#topo'); if (!cv || !cv.clientWidth) return;
  const dpr = devicePixelRatio || 1, W = cv.clientWidth, H = cv.clientHeight; cv.width = W * dpr; cv.height = H * dpr;
  const ctx = cv.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
  const cs = getComputedStyle(document.documentElement), col = k => cs.getPropertyValue(k).trim();
  const rings = {}; for (const id of h.nodes) { const r = id === ME.id ? 0 : Math.min(4, contacts[id].hops); (rings[r] ||= []).push(id); }
  const maxR = Math.max(1, ...Object.keys(rings).map(Number)), pos = {}, R = Math.min(W, H) / 2 - 34;
  for (const [r, ids] of Object.entries(rings)) ids.forEach((id, i) => { const a = (i / ids.length) * Math.PI * 2 + r * 2.4 - Math.PI / 2;
    const rad = (r / maxR) * R; pos[id] = [W / 2 + Math.cos(a) * rad, H / 2 + Math.sin(a) * rad]; });
  ctx.strokeStyle = col('--line'); ctx.setLineDash([3, 5]);
  for (let r = 1; r <= maxR; r++) { ctx.beginPath(); ctx.arc(W / 2, H / 2, (r / maxR) * R, 0, Math.PI * 2); ctx.stroke(); }
  ctx.setLineDash([]); ctx.lineWidth = 2; ctx.strokeStyle = col('--accent'); ctx.globalAlpha = .55;
  for (const a of h.nodes) for (const b of h.adj[a]) if (a < b) { ctx.beginPath(); ctx.moveTo(...pos[a]); ctx.lineTo(...pos[b]); ctx.stroke(); }
  ctx.globalAlpha = 1; ctx.font = '600 11px ' + col('--font'); ctx.textAlign = 'center';
  for (const id of h.nodes) { const [x, y] = pos[id], alert = id === ME.id ? Date.now() < (ME.alertUntil || 0) : contacts[id].st === 'alert';
    if (alert) { ctx.strokeStyle = col('--sos'); ctx.lineWidth = 3; ctx.beginPath(); ctx.arc(x, y, 16, 0, Math.PI * 2); ctx.stroke(); }
    ctx.fillStyle = colorOf(id); ctx.beginPath(); ctx.arc(x, y, id === ME.id ? 13 : 10, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = col('--fg'); ctx.fillText(nameOf(id).slice(0, 14), x, y + 26); }
}

/* control-centre rendering */
let roT;
function renderOpsSoon() { clearTimeout(roT); roT = setTimeout(renderOps, 120); }
function openOps() {
  active = null; $('#welcome').hidden = true; $('#chat').hidden = true; $('#ops').hidden = false; $('#app').classList.add('in-chat');
  renderOps(); renderList();
}
function battHtml(bt) { if (!bt) return '<small class="hint">—</small>';
  return `<span class="batt"><i><u class="${bt.l < 20 ? 'low' : ''}" style="width:${bt.l}%"></u></i>${bt.l}%${bt.c ? ' ⚡' : ''}</span>`; }
function renderOps() {
  const h = health();
  const openSig = Object.values(ops.props).filter(p => p.state === 'open' && p.signers.includes(ME.id) && !p.signed.includes(ME.id)).length;
  const fired = Object.values(ops.tbs).filter(t => t.state === 'fired').length;
  $('#opsSide').innerHTML = `<div class="stats"><div class="stat"><b>${h.score}</b><span>صحة الشبكة · ${h.label}</span></div>
    <div class="stat"><b>${h.alerts + fired}</b><span>إنذارات نشطة</span></div><div class="stat"><b>${openSig}</b><span>قرارات بانتظار توقيعك</span></div>
    <div class="stat"><b>${h.reach}/${h.known}</b><span>أجهزة متصلة</span></div></div><button class="btn primary" id="opsOpen">افتح مركز القيادة</button>`;
  $('#opsOpen').onclick = openOps;
  if ($('#ops').hidden) return;
  $('#kpis').innerHTML = `
    <div class="kpi hero"><b>${h.score}<small style="font-size:.8rem"> /100</small></b><span>صحة الشبكة · ${h.label}</span></div>
    <div class="kpi"><b>${h.reach}/${h.known}</b><span>أجهزة يمكن الوصول إليها</span></div>
    <div class="kpi"><b>${links.size}</b><span>روابط مباشرة</span></div>
    <div class="kpi ${h.alerts + fired ? 'alert' : ''}"><b>${h.alerts + fired}</b><span>إنذارات نشطة</span></div>
    <div class="kpi"><b>${ledger.blocks.length}</b><span>كتل في سجلّي</span></div>
    <div class="kpi"><b>${stats.relayed}</b><span>حزم مرّرتها</span></div>`;
  $('#topoStats').innerHTML = `<div><b>${h.edges}</b>روابط</div><div><b>${h.clusters}</b>عناقيد</div>
    <div><b>${h.bridges}</b>جسور حرجة</div><div><b>${h.avgHops}</b>متوسط القفزات</div>
    <div style="grid-column:1/-1"><small class="hint">الجسر الحرج رابط وحيد إن انقطع انقسمت الشبكة. ضع جهازاً إضافياً بين طرفيه لزيادة المتانة.</small></div>`;
  drawTopo(h);
  const devs = Object.values(contacts).sort((a, b) => (a.hops || 9) - (b.hops || 9));
  $('#devRows').innerHTML = devs.map(c => { const r = reachOf(c.id), alert = r.cls && c.st === 'alert';
    const pill = alert ? '<span class="pill alert">إنذار</span>' : r.cls === 'direct' ? '<span class="pill ok">مباشر</span>' : r.cls ? '<span class="pill mesh">عبر الشبكة</span>' : '<span class="pill off">غير متصل</span>';
    return `<tr><td><b>${esc(c.name || 'بدون اسم')}</b><br><small class="mono hint">${c.id}</small></td><td>${pill}</td><td>${battHtml(r.cls ? c.bt : null)}</td>
      <td class="mono">${r.cls ? c.hops : '—'}</td><td class="mono">${c.rl || 0}</td><td><small>${c.seen ? fmtTime(c.seen) : '—'}</small></td></tr>`; }).join('')
    || '<tr><td colspan="6" class="hint">لا توجد أجهزة بعد</td></tr>';
  $('#bcList').innerHTML = Object.values(ops.bc).filter(b => b.ty).sort((a, b) => b.ts - a.ts).slice(0, 30).map(b => { const n = Object.keys(b.acks).length, mine = b.fromId === ME.id;
    return `<div class="row-item ${b.ty === 'SOS' || b.ty === 'EVAC' ? 'alert' : ''}"><div class="top"><span class="tylbl">${BT[b.ty].e} ${BT[b.ty].l}</span><small>${esc(mine ? 'أنت' : b.from)} · ${fmtTime(b.ts)}</small></div>
      <span>${esc(b.text)}</span><div class="top"><small>أكّد الاستلام: <b>${n}</b>${mine && b.reach ? ` من ${b.reach} جهازاً كانت في المدى` : ''}</small>
      ${mine ? '' : b.acks[ME.id] ? '<small>أكّدتَ ✓</small>' : `<button class="ackb" data-act="ack" data-id="${b.bid}">تم الاستلام</button>`}</div></div>`; }).join('') || '<p class="hint">لا توجد إذاعات بعد</p>';
  const prevChecked = new Set([...document.querySelectorAll('#propSigners input:checked')].map(i => i.value));
  const firstRender = !$('#propSigners').children.length;
  const cand = [ME.id, ...Object.keys(contacts)];
  $('#propSigners').innerHTML = cand.map(id => `<label class="chk"><input type="checkbox" value="${id}" ${(firstRender ? id === ME.id || links.has(id) : prevChecked.has(id)) ? 'checked' : ''}> ${esc(nameOf(id))}</label>`).join('');
  syncTh();
  $('#propList').innerHTML = Object.values(ops.props).sort((a, b) => b.ts - a.ts).map(p => { const need = p.signers.includes(ME.id) && !p.signed.includes(ME.id) && p.state === 'open';
    return `<div class="row-item ${p.state === 'done' && p.evac ? 'alert' : ''}"><div class="top"><b>${esc(p.title)}</b><span class="pill ${p.state === 'done' ? 'ok' : 'mesh'}">${p.state === 'done' ? 'معتمد' : `${p.signed.length}/${p.th} تواقيع`}</span></div>
      <span>${esc(p.text)}</span><small>اقترحه ${esc(nameOf(p.by))} · الموقّعون: ${p.signers.map(s => esc(nameOf(s)) + (p.signed.includes(s) ? ' ✓' : '')).join('، ')}${p.evac ? ' · يطلق إنذار إخلاء عند الاعتماد' : ''}</small>
      ${need ? `<button class="ackb" data-act="sign" data-id="${p.pid}">وقّع القرار</button>` : ''}</div>`; }).join('') || '<p class="hint">لا توجد قرارات بعد</p>';
  $('#tbList').innerHTML = Object.values(ops.tbs).filter(t => t.state !== 'off').sort((a, b) => b.ts - a.ts).map(t => { const mine = t.by === ME.id;
    const left = t.ms - (Date.now() - Math.max(t.ts, mine ? Date.now() : lastHeard(t.by)));
    return `<div class="row-item ${t.state === 'fired' ? 'alert' : ''}"><div class="top"><b>${mine ? 'مؤقّتك' : esc(nameOf(t.by))}</b>
      <span class="pill ${t.state === 'fired' ? 'alert' : 'ok'}">${t.state === 'fired' ? 'انطلق' : 'نشط'}</span></div>
      <small>${mine ? `تراقبه الأجهزة الأخرى · ينطلق إن انقطعتَ ${fmtDur(t.ms)}` : t.state === 'fired' ? `انقطع منذ ${fmtDur(Date.now() - Math.max(t.ts, lastHeard(t.by)))}` : `ينطلق بعد ${fmtDur(Math.max(0, left))} إن لم يظهر`}</small>
      <span>${esc(t.msg || '')}</span>${mine ? `<button class="ackb" data-act="disarm" data-id="${t.tid}">إلغاء المؤقّت</button>` : ''}</div>`; }).join('') || '<p class="hint">لا توجد مؤقّتات نشطة</p>';
}
function syncTh() {
  const n = document.querySelectorAll('#propSigners input:checked').length, sel = $('#propTh'), cur = +sel.value || Math.max(1, Math.ceil(n / 2) + (n > 2 ? 0 : 0));
  sel.innerHTML = Array.from({ length: Math.max(1, n) }, (_, i) => `<option value="${i + 1}" ${i + 1 === Math.min(cur, Math.max(1, n)) ? 'selected' : ''}>${i + 1} من ${n}</option>`).join('');
}
function wireOps() {
  $('#opsBack').onclick = () => { $('#ops').hidden = true; $('#welcome').hidden = false; $('#app').classList.remove('in-chat'); };
  $('#bcForm').onsubmit = e => { e.preventDefault(); const t = $('#bcFormText').value.trim(); if (!t) return; $('#bcFormText').value = '';
    sendSOS(t, $('#bcFormType').value); toast('أُرسل البث'); };
  $('#propSigners').addEventListener('change', syncTh);
  $('#propForm').onsubmit = async e => { e.preventDefault();
    const title = $('#propTitle').value.trim(), text = $('#propText').value.trim();
    const signers = [...document.querySelectorAll('#propSigners input:checked')].map(i => i.value);
    if (!title || signers.length < 2) return toast('اكتب عنواناً واختر موقّعَين على الأقل');
    $('#propTitle').value = $('#propText').value = '';
    await createProposal(title, text, signers, +$('#propTh').value, $('#propEvac').checked); toast('نُشر القرار للتوقيع'); };
  $('#tbForm').onsubmit = async e => { e.preventDefault();
    if (Object.values(ops.tbs).some(t => t.by === ME.id && t.state !== 'off')) return toast('لديك مؤقّت نشط. ألغِه أولاً');
    await armTimer(+$('#tbMs').value, $('#tbMsg').value.trim()); $('#tbMsg').value = ''; toast('فُعّل مؤقّت الأمان'); };
  $('#ops').addEventListener('click', e => { const b = e.target.closest('[data-act]'); if (!b) return; b.disabled = true;
    const id = b.dataset.id; ({ ack: ackBroadcast, sign: signProposal, disarm: disarmTimer })[b.dataset.act](id); });
}

/* ---------- chats model ---------- */
function addMsg(peer, m) {
  const list = (chats[peer] ||= []);
  if (list.some(x => x.id === m.id)) return;
  list.push(m); list.sort((a, b) => a.ts - b.ts);
  if (!m.mine && m.kind !== 'sys') { if (active === peer && document.visibilityState === 'visible') queueRead(peer, m); else m.unread = true; }
  saveChats(); renderSoon(); if (active === peer) renderMsgSoon(peer);
}
function sysMsg(peer, text) { if (!contacts[peer] && peer !== SOS) return; addMsg(peer, { id: rid(), kind: 'sys', text, ts: Date.now() }); }
const findMsg = (peer, id) => (chats[peer] || []).find(m => m.id === id);
function setStatus(peer, id, st) { const m = findMsg(peer, id); if (!m) return;
  const rank = { pending: 0, queued: 1, sent: 2, delivered: 3, read: 4 }; if (rank[st] > (rank[m.status] ?? 0)) { m.status = st; saveChats(); renderMsgSoon(peer); } }
let readQ = {};
function queueRead(peer, m) { if (peer === SOS) return; (readQ[peer] ||= []).push(m.id); clearTimeout(readQ.t);
  readQ.t = setTimeout(() => { for (const p in readQ) if (p !== 't' && readQ[p].length) { sendSecure(p, { k: 'read', refs: readQ[p] }).catch(() => {}); readQ[p] = []; } }, 400); }
function saveChats() { saveLater('chats', () => chats); }
function notify(peer, text) {
  if (active === peer && document.visibilityState === 'visible') return;
  const name = contacts[peer]?.name || peer; toast(`${name}: ${String(text).slice(0, 80)}`); beep(1);
  try { if ('Notification' in window && Notification.permission === 'granted' && document.visibilityState !== 'visible')
    new Notification(name, { body: String(text).slice(0, 120), icon: 'icon.svg', tag: peer }); } catch {}
}
let actx;
function beep(n = 1, freq = 880) {
  try { actx ||= new AudioContext(); for (let i = 0; i < n; i++) { const o = actx.createOscillator(), g = actx.createGain();
    o.frequency.value = freq; g.gain.value = .08; o.connect(g).connect(actx.destination);
    const t = actx.currentTime + i * 0.35; o.start(t); o.stop(t + 0.18); } } catch {}
}

/* ---------- mesh-signalled direct links (upgrade multi-hop contact to direct) ---------- */
const meshPending = {};
async function connectDirect(peer) {
  if (links.has(peer)) return;
  const { link, code } = await makeOffer(peer);
  meshPending[peer] = link;
  await sendSecure(peer, { k: 'sig', d: code });
  sysMsg(peer, 'جارٍ إنشاء رابط مباشر عبر الشبكة…');
  setTimeout(() => { if (!links.has(peer) && meshPending[peer] === link) { dropLink(link); delete meshPending[peer];
    sysMsg(peer, 'تعذّر الرابط المباشر. الجهاز بعيد عن شبكتك المحلية، لكن الرسائل تصل عبر الأجهزة الوسيطة.'); } }, 15000);
}
async function onMeshSignal(from, m) {
  try {
    const desc = await unpackDesc(m.d);
    if (desc.type === 'offer') { if (links.has(from)) return; const { code } = await answerOffer(m.d, from); await sendSecure(from, { k: 'sig', d: code }); }
    else if (meshPending[from]) { await acceptAnswer(meshPending[from], m.d); delete meshPending[from]; }
  } catch (e) { console.warn(e); }
}

/* ---------- calls (direct links only) ---------- */
const CALL = { peer: null, state: 'idle', video: false, local: null, offerer: false };
function attachLocal(pc, stream) {
  for (const kind of ['audio', 'video']) {
    const track = stream ? stream.getTracks().find(t => t.kind === kind) : null;
    let tr = pc.getTransceivers().find(t => !t.stopped && t.receiver.track && t.receiver.track.kind === kind);
    if (!tr) { if (!track) continue; tr = pc.addTransceiver(kind, { direction: 'sendrecv' }); }
    tr.sender.replaceTrack(track || null); tr.direction = 'sendrecv';
  }
}
async function getMedia(video) {
  return navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true },
    video: video ? { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 480 } } : false });
}
async function startCall(peer, video) {
  const link = links.get(peer);
  if (link?.native) return toast('هذا الرابط عبر البلوتوث / Wi-Fi Direct ولا يحمل مكالمات في المتصفح المدمج. اتصلا بنفس نقطة الاتصال ثم اضغط «اتصال مباشر».');
  if (!link) return toast(contacts[peer]?.via && contacts[peer].via !== 'ip'
    ? `هذا الجهاز متصل عبر ${VIA[contacts[peer].via]} فقط، وسعتها لا تكفي للصوت والفيديو. المكالمات تحتاج Wi-Fi أو رابط مايكروويف.`
    : 'المكالمات تحتاج رابطاً مباشراً. اضغط «اتصال مباشر» أولاً.');
  if (CALL.state !== 'idle') return;
  Object.assign(CALL, { peer, video, state: 'out', offerer: true });
  showCall('جارٍ الاتصال…');
  try { CALL.local = await getMedia(video); } catch { endCall(false, 'لا يمكن الوصول إلى الميكروفون أو الكاميرا'); return; }
  $('#localV').srcObject = video ? CALL.local : null;
  rawSend(link, { t: 'call', a: 'ring', video });
  ringLoop();
  CALL.timer = setTimeout(() => { if (CALL.state === 'out') { rawSend(link, { t: 'call', a: 'end' }); endCall(false, 'لم يتم الرد'); } }, 45000);
}
async function onCallSignal(link, m) {
  const peer = link.id;
  if (m.a === 'ring') {
    if (CALL.state !== 'idle') return rawSend(link, { t: 'call', a: 'busy' });
    Object.assign(CALL, { peer, video: !!m.video, state: 'in', offerer: false });
    showCall(m.video ? 'مكالمة فيديو واردة' : 'مكالمة صوتية واردة'); ringLoop();
    try { navigator.vibrate && navigator.vibrate([500, 300, 500, 300, 500]); } catch {}
  } else if (m.a === 'accept' && CALL.peer === peer && CALL.state === 'out') {
    CALL.state = 'live'; clearTimeout(CALL.timer); setCallState('متصل');
    attachLocal(link.pc, CALL.local);
    await link.pc.setLocalDescription(await link.pc.createOffer());
    rawSend(link, { t: 'neg', d: { type: link.pc.localDescription.type, sdp: link.pc.localDescription.sdp } });
  } else if (m.a === 'busy' && CALL.peer === peer) { endCall(false, 'الطرف الآخر في مكالمة أخرى'); }
  else if (m.a === 'end' && CALL.peer === peer) { endCall(false, CALL.state === 'live' ? 'انتهت المكالمة' : 'أُلغيت المكالمة'); }
}
async function onNegotiation(link, m) {
  const pc = link.pc;
  await pc.setRemoteDescription(m.d);
  if (m.d.type === 'offer') {
    if (CALL.peer === link.id && CALL.local) attachLocal(pc, CALL.local);
    await pc.setLocalDescription(await pc.createAnswer());
    rawSend(link, { t: 'neg', d: { type: pc.localDescription.type, sdp: pc.localDescription.sdp } });
  }
}
async function acceptCall() {
  const link = links.get(CALL.peer); if (!link || CALL.state !== 'in') return;
  try { CALL.local = await getMedia(CALL.video); } catch { rawSend(link, { t: 'call', a: 'end' }); return endCall(false, 'لا يمكن الوصول إلى الميكروفون'); }
  $('#localV').srcObject = CALL.video ? CALL.local : null;
  CALL.state = 'live'; setCallState('متصل'); $('#acceptBtn').hidden = true;
  rawSend(link, { t: 'call', a: 'accept' });
}
function onRemoteTrack(link) {
  if (CALL.peer !== link.id) return;
  const tracks = link.pc.getReceivers().map(r => r.track).filter(t => t && t.readyState === 'live');
  const rv = $('#remoteV'); rv.srcObject = new MediaStream(tracks); rv.play().catch(() => {});
}
function endCall(notifyPeer = true, reason) {
  if (CALL.state === 'idle') return;
  const link = links.get(CALL.peer);
  if (notifyPeer && link) rawSend(link, { t: 'call', a: 'end' });
  if (link) for (const tr of link.pc.getTransceivers()) try { tr.sender.replaceTrack(null); } catch {}
  if (CALL.local) CALL.local.getTracks().forEach(t => t.stop());
  const wasLive = CALL.state === 'live', started = CALL.started, peer = CALL.peer, video = CALL.video;
  clearTimeout(CALL.timer); clearInterval(CALL.ring);
  Object.assign(CALL, { peer: null, state: 'idle', local: null, started: null });
  $('#remoteV').srcObject = null; $('#localV').srcObject = null; $('#call').hidden = true;
  if (peer) sysMsg(peer, `${video ? 'مكالمة فيديو' : 'مكالمة صوتية'}${wasLive && started ? ' · ' + Math.round((Date.now() - started) / 1000) + ' ث' : ''}${reason ? ' · ' + reason : ''}`);
  if (reason) toast(reason);
}
function ringLoop() { clearInterval(CALL.ring); CALL.ring = setInterval(() => { if (CALL.state === 'in' || CALL.state === 'out') beep(2, CALL.state === 'in' ? 660 : 440); else clearInterval(CALL.ring); }, 2000); beep(2, 660); }
function showCall(state) {
  const c = contacts[CALL.peer] || {};
  $('#call').hidden = false; $('#callName').textContent = c.name || CALL.peer;
  $('#callAvatar').textContent = initial(c.name); $('#callAvatar').style.background = colorOf(CALL.peer);
  $('#callAv').hidden = CALL.video; $('#localV').hidden = !CALL.video; $('#camBtn').hidden = !CALL.video;
  $('#acceptBtn').hidden = CALL.state !== 'in';
  $('#muteBtn').setAttribute('aria-pressed', 'false'); $('#camBtn').setAttribute('aria-pressed', 'false');
  setCallState(state);
}
function setCallState(s) { $('#callState').textContent = s; if (s === 'متصل') { CALL.started = Date.now(); clearInterval(CALL.ring); } }

/* ---------- ledger: signed hash chain + witnesses ---------- */
async function logEntry(dir, peer, h) {
  ledger.pending.push({ d: dir, p: peer, h, ts: Date.now() });
  if (ledger.pending.length >= 8) await seal(); else saveLater('ledger', () => ledger);
}
let sealing = false;
async function seal() {
  if (sealing || !ledger.pending.length) return; sealing = true;
  try {
    const prev = ledger.blocks[ledger.blocks.length - 1];
    const b = { i: prev ? prev.i + 1 : 0, prev: prev ? prev.hash : '0'.repeat(64), ts: Date.now(), by: ME.id, e: ledger.pending.splice(0) };
    b.hash = await sha(JSON.stringify([b.i, b.prev, b.ts, b.by, b.e]));
    b.sig = await sign(b.hash);
    ledger.blocks.push(b); await db.set('ledger', ledger);
    announce();
  } finally { sealing = false; }
  if (!$('#vChain').hidden) renderChain();
}
async function verifyLedger() {
  let prev = '0'.repeat(64);
  for (const b of ledger.blocks) {
    const h = await sha(JSON.stringify([b.i, b.prev, b.ts, b.by, b.e]));
    if (h !== b.hash || b.prev !== prev) return { ok: false, at: b.i, why: 'البصمة لا تطابق المحتوى أو السلسلة مقطوعة' };
    if (!(await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, ME.vKey, b64d(b.sig), enc.encode(b.hash)))) return { ok: false, at: b.i, why: 'التوقيع غير صالح' };
    prev = b.hash;
  }
  return { ok: true };
}
function checkWitness(id, head) {
  const w = witness[id];
  if (w && (head.i < w.i || (head.i === w.i && head.h !== w.h))) {
    witness[id] = { ...w, fork: true };
    toast(`تحذير: سجل ${contacts[id]?.name || id} لا يطابق ما شهدته سابقاً`, true);
  } else witness[id] = { i: head.i, h: head.h, ts: Date.now(), fork: w?.fork || false };
  saveLater('witness', () => witness);
}

/* ---------- rendering ---------- */
let rT, rmT = {};
function renderSoon() { clearTimeout(rT); rT = setTimeout(renderAll, 60); }
function renderMsgSoon(peer) { if (active !== peer) return renderSoon(); clearTimeout(rmT[peer]); rmT[peer] = setTimeout(renderMsgs, 40); }
function reachOf(id) {
  if (id === SOS) return { cls: 'mesh', text: 'قناة عامة لكل الأجهزة في المدى' };
  if (links.has(id)) return { cls: 'direct', text: 'متصل مباشرة' };
  const c = contacts[id];
  const fresh = c && c.hops < 9 && Date.now() - c.seen < (c.via && c.via !== 'ip' ? (window.WaslRadio?.KINDS[c.via]?.cardEvery || 0) * 2.5 : CARD_EVERY * 3.5);
  if (fresh) return { cls: 'mesh', text: `عبر ${c.via && c.via !== 'ip' ? VIA[c.via] : 'الشبكة'} · ${c.hops} قفزات` };
  return { cls: '', text: c ? 'خارج النطاق · تُرسل الرسائل عند الاقتراب' : '' };
}
function renderAll() {
  $('#footLinks').textContent = `${links.size} روابط مباشرة`;
  const reachable = Object.keys(contacts).filter(id => reachOf(id).cls).length;
  $('#footNodes').textContent = `${reachable} أجهزة في الشبكة`;
  renderList();
  if (!$('#vNet').hidden) renderNet();
  if (!$('#ops').hidden || !$('#vOps').hidden) renderOpsSoon();
  if (active) renderHead();
}
function lastOf(id) { const l = chats[id] || []; for (let i = l.length - 1; i >= 0; i--) if (l[i].kind !== 'sys') return l[i]; return null; }
function previewOf(m) { if (!m) return ''; if (m.kind === 'file') return (m.mine ? 'أنت: ' : '') + (m.voice ? '🎙 رسالة صوتية' : '📎 ' + m.name);
  return (m.mine ? 'أنت: ' : m.kind === 'sos' ? m.from + ': ' : '') + m.text; }
function renderList() {
  const ids = [SOS, ...new Set([...Object.keys(contacts), ...Object.keys(chats).filter(k => k !== SOS)])];
  ids.sort((a, b) => { if (a === SOS) return -1; if (b === SOS) return 1; return (lastOf(b)?.ts || contacts[b]?.seen || 0) - (lastOf(a)?.ts || contacts[a]?.seen || 0); });
  const el = $('#chatList'); el.innerHTML = '';
  if (!Object.keys(contacts).length) el.insertAdjacentHTML('beforeend', '<p class="empty">لا توجد أجهزة بعد. اضغط «+ جهاز قريب» لربط أول هاتف.</p>');
  for (const id of ids) {
    if (id !== SOS && !contacts[id]) continue;
    const last = lastOf(id), unread = (chats[id] || []).filter(m => m.unread).length, r = reachOf(id);
    const name = id === SOS ? 'قناة الطوارئ SOS' : contacts[id].name || id;
    const b = document.createElement('button'); b.className = 'item' + (id === SOS ? ' sos' : ''); b.dataset.id = id;
    b.setAttribute('aria-current', active === id);
    b.innerHTML = `<div class="avatar" style="background:${id === SOS ? 'var(--sos)' : colorOf(id)}">${id === SOS ? '!' : esc(initial(name))}</div>
      <div class="mid"><div class="row"><b>${esc(name)}</b><time>${last ? fmtTime(last.ts) : ''}</time></div>
      <div class="row"><small>${esc(previewOf(last) || r.text)}</small>${unread ? `<span class="badge">${unread}</span>` : ''}</div>
      <span class="reach"><i class="dot ${r.cls}"></i>${esc(id === SOS ? 'يصل لكل من في المدى' : r.text || id)}</span></div>`;
    b.onclick = () => openChat(id);
    el.append(b);
  }
}
function renderHead() {
  const id = active, r = reachOf(id), isSos = id === SOS, c = contacts[id];
  $('#cName').textContent = isSos ? 'قناة الطوارئ SOS' : (c?.name || id);
  $('#cStatus').textContent = isSos ? 'رسائل موقّعة تصل لكل الأجهزة في الشبكة' : `${r.text || ''} · ${id}`;
  $('#cAv').textContent = isSos ? '!' : initial(c?.name); $('#cAv').style.background = isSos ? 'var(--sos)' : colorOf(id);
  const direct = links.has(id) && !links.get(id).native;
  $('#voiceBtn').hidden = $('#videoBtn').hidden = isSos;
  $('#voiceBtn').disabled = $('#videoBtn').disabled = !direct;
  $('#directBtn').hidden = isSos || direct || !r.cls || ['hf', 'vhf'].includes(c?.via);
  $('#attachBtn').hidden = $('#micBtn').hidden = isSos; $('#bcType').hidden = !isSos;
  $('#textIn').placeholder = isSos ? 'اكتب نداء الاستغاثة: ماذا حدث وأين أنت' : 'اكتب رسالة';
  $('#sendBtn').hidden = !isSos && !$('#textIn').value.trim();
  $('#micBtn').hidden = isSos || !$('#sendBtn').hidden;
}
const urls = new WeakMap();
const urlOf = blob => { if (!urls.has(blob)) urls.set(blob, URL.createObjectURL(blob)); return urls.get(blob); };
function tick(m) { if (!m.mine || m.kind === 'sos') return '';
  return { pending: '<span class="tick">🕓</span>', queued: '<span class="tick" title="محفوظة حتى يظهر طريق">🕓</span>', sent: '<span class="tick">✓</span>',
    delivered: '<span class="tick">✓✓</span>', read: '<span class="tick read">✓✓</span>' }[m.status] || ''; }
function renderMsgs() {
  const el = $('#msgs'), list = chats[active] || [];
  const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
  el.innerHTML = '';
  if (!list.length) el.insertAdjacentHTML('beforeend', active === SOS
    ? '<p class="empty">نداءات الاستغاثة هنا تصل لكل جهاز في الشبكة، وتُوقَّع بمفتاحك حتى لا يمكن انتحالها. استخدمها فقط في الطوارئ.</p>'
    : '<p class="empty">الرسائل مشفّرة من طرف إلى طرف. الأجهزة الوسيطة تمرّرها دون أن تستطيع قراءتها.</p>');
  let day = '';
  for (const m of list) {
    const d = new Date(m.ts).toLocaleDateString('ar', { weekday: 'long', day: 'numeric', month: 'long' });
    if (d !== day) { day = d; el.insertAdjacentHTML('beforeend', `<div class="day">${esc(d)}</div>`); }
    const b = document.createElement('div');
    b.className = 'bubble ' + (m.kind === 'sys' ? 'sys' : (m.mine ? 'mine' : 'theirs') + (m.kind === 'sos' ? ' sos' : ''));
    if (m.kind === 'sys') { b.textContent = m.text; el.append(b); continue; }
    const bt = BT[m.ty || 'SOS'];
    let html = m.kind === 'sos' ? `<span class="from">${bt.e} ${esc(bt.l)}${m.mine ? '' : ' · ' + esc(m.from)}</span>` : '';
    if (m.kind === 'file') {
      if (m.blob) {
        const u = urlOf(m.blob), t = m.type || '';
        if (m.voice || t.startsWith('audio/')) html += `<audio controls src="${u}"></audio>`;
        else if (t.startsWith('image/')) html += `<a href="${u}" download="${esc(m.name)}"><img src="${u}" alt="${esc(m.name)}"></a>`;
        else if (t.startsWith('video/')) html += `<video controls src="${u}"></video>`;
        else html += `<a class="file" href="${u}" download="${esc(m.name)}">📄<span><b>${esc(m.name)}</b><small>${fmtSize(m.size)} · اضغط للحفظ</small></span></a>`;
      } else html += `<div class="file">📄<span><b>${esc(m.voice ? 'رسالة صوتية' : m.name)}</b><small>${fmtSize(m.size)}</small></span></div>`;
      if (m.progress !== undefined) html += `<div class="prog"><i style="width:${Math.round(m.progress * 100)}%"></i></div>`;
    } else html += `<span>${esc(m.text)}</span>`;
    if (m.kind === 'sos' && m.bid && ops.bc[m.bid]) { const n = Object.keys(ops.bc[m.bid].acks).length;
      html += m.mine ? `<small>أكّد الاستلام: ${n}</small>` : ops.bc[m.bid].acks[ME.id] ? '<small>أكّدتَ الاستلام ✓</small>' : `<button class="ackb" data-ack="${m.bid}">تم الاستلام</button>`; }
    html += `<span class="meta">${m.hops > 1 ? `<span title="عدد الأجهزة التي مرّت عبرها">${m.hops} قفزات</span>` : ''}<span>${fmtTime(m.ts)}</span>${tick(m)}</span>`;
    b.innerHTML = html; el.append(b);
  }
  if (atBottom || list.at(-1)?.mine) el.scrollTop = el.scrollHeight;
}
function openChat(id) {
  active = id; $('#welcome').hidden = true; $('#ops').hidden = true; $('#chat').hidden = false; $('#app').classList.add('in-chat');
  const unread = (chats[id] || []).filter(m => m.unread);
  unread.forEach(m => { delete m.unread; queueRead(id, m); }); if (unread.length) saveChats();
  renderHead(); renderMsgs(); renderList();
  if (matchMedia('(min-width:761px)').matches) $('#textIn').focus();
}
function layersHtml() {
  const lora = radios.get('lora'), hf = radios.get('hf') || radios.get('vhf');
  const caps = c => c.map(x => `<span class="cap">${x}</span>`).join('');
  const st = (cls, t) => `<span class="pill ${cls}">${t}</span>`;
  const portInfo = p => p ? `<small class="hint">أُرسل ${p.stats.txFrames} إطاراً · استُقبل ${p.stats.rxFrames}${p.stats.bad ? ` · ${p.stats.bad} تالف` : ''}${p.lastCall ? ` · آخر محطة: ${esc(p.lastCall)}` : ''}${p.queue.length ? ` · ${p.queue.length} بانتظار البث` : ''}</small>` : '';
  const rows = [
    ['Bluetooth LE', 'حتى 100 م', ['نص', 'ملفات', 'اكتشاف تلقائي'], NATIVE.on ? st('ok', `${NATIVE.links.size} أجهزة`) : st('off', 'في تطبيق الهاتف'),
      NATIVE.on ? (NATIVE.platform === 'ios' ? 'Multipeer Connectivity: الهواتف القريبة تتصل تلقائياً عبر البلوتوث.' : 'Nearby Connections: الهواتف القريبة تتصل تلقائياً عبر البلوتوث LE.')
        : 'المتصفح لا يسمح للهاتف بالبث كعقدة بلوتوث. ثبّت تطبيق وَصْل لـ Android أو iOS.'],
    ['Wi-Fi Direct / نقطة اتصال', 'حتى 100 م', ['فيديو', 'صوت', 'ملفات', 'نص'], links.size ? st('ok', `${links.size} روابط`) : st('mesh', 'جاهزة'),
      NATIVE.on ? (NATIVE.platform === 'ios' ? 'Wi-Fi نظير لنظير بلا نقطة اتصال للرسائل والملفات. للمكالمات: نقطة اتصال مشتركة.' : 'Wi-Fi Direct بلا نقطة اتصال للرسائل والملفات. للمكالمات: نقطة اتصال مشتركة ورمز QR.')
        : 'شغّل نقطة اتصال من أي هاتف واربط الأجهزة برمز QR. Wi-Fi Direct بلا نقطة اتصال في تطبيق الهاتف.'],
    ['شبكة P2P (نمط libp2p)', 'كل الطبقات', ['توجيه', 'هوية'], st('ok', 'نشطة'), 'هوية من المفتاح العام، بث Gossip مع منع التكرار، تخزين ثم تمرير. التوافق المباشر مع libp2p في النسخة الأصلية.'],
    ['مايكروويف نقطة لنقطة', 'حتى 50 كم', ['فيديو', 'صوت', 'ملفات', 'نص'], st('mesh', 'عبر IP'), 'أي رابط IP بين المواقع (مثل أجهزة 5 GHz) يحمل WebRTC كاملاً. اربط جهازاً في كل موقع بنفس الشبكة ثم «اتصال مباشر».'],
    ['WebRTC', 'فوق أي IP', ['فيديو', 'صوت', 'ملفات', 'نص'], links.size ? st('ok', `${links.size} نشطة`) : st('mesh', 'جاهزة'), 'مكالمات مشفّرة DTLS-SRTP ونقل ملفات مباشر بين جهازين.'],
    ['LoRa', 'حتى 15 كم بلا رخصة', ['نص', 'SOS', 'ملفات حتى 12KB'], lora?.state === 'on' ? st('ok', 'متصل') : st('off', 'غير متصل'),
      `جهاز LoRa بنظام RNode أو أي TNC يدعم KISS عبر USB. نحو 1.7 كيلوبت/ث، مشفّر، مع احترام حد زمن البث. ${portInfo(lora)}
       <div class="row"><button class="btn" data-radio="lora:serial">${lora?.state === 'on' ? 'إعادة الوصل' : 'وصل جهاز LoRa (USB)'}</button></div>`],
    ['HF / VHF راديو هواة', 'حتى 5000 كم (HF، برخصة هواة)', ['نص', 'SOS'], hf?.state === 'on' ? st('ok', `متصل · ${VIA[hf.kind]}`) : st('off', 'غير متصل'),
      `عبر كرت الصوت مع أي جهاز راديو (VOX) أو TNC عبر USB. 100 بت/ث على HF و600 على VHF. الرسائل موقّعة لكن غير مشفّرة، كما يشترط القانون. ${portInfo(hf)}
       <label class="hint" for="callIn">نداء الهواة (Callsign)</label><input type="text" id="callIn" value="${esc(ME.callsign || '')}" maxlength="10" placeholder="مثلاً HZ1ABC" class="mono">
       <div class="row"><select id="hfBand"><option value="hf">HF · 50 baud</option><option value="vhf">VHF/UHF FM · 300 baud</option></select>
       <button class="btn" data-radio="hf:audio">وصل عبر كرت الصوت</button><button class="btn" data-radio="hf:serial">وصل TNC (USB)</button></div>`],
  ];
  return rows.map(([n, range, c, s, desc]) => `<div class="layer"><div class="top"><b>${n}</b>${s}</div><small class="hint">${range}</small><div>${caps(c)}</div><div class="desc">${desc}</div></div>`).join('');
}
function renderNet() {
  const nodes = Object.values(contacts).sort((a, b) => (a.hops || 9) - (b.hops || 9));
  $('#netView').innerHTML = `
    <div class="stats">
      <div class="stat"><b>${links.size}</b><span>روابط مباشرة</span></div>
      <div class="stat"><b>${nodes.filter(n => reachOf(n.id).cls).length}</b><span>أجهزة يمكن الوصول إليها</span></div>
      <div class="stat"><b>${stats.relayed}</b><span>حزم مرّرتها لغيرك</span></div>
      <div class="stat"><b>${outbox.size + dtn.size}</b><span>حزم محفوظة للتمرير لاحقاً</span></div>
    </div>
    <p class="hint">كل جهاز في القائمة يمرّر الرسائل للأجهزة الأبعد. الأجهزة «عبر الشبكة» تصلها رسائلك وملفاتك، والمكالمات تحتاج رابطاً مباشراً.</p>
    <h3>طبقات الاتصال السبع</h3>
    <div class="layers">${layersHtml()}</div>
    <h3>الأجهزة المعروفة</h3>
    ${nodes.map(n => { const r = reachOf(n.id); return `<div class="node"><span><i class="dot ${r.cls}"></i> <b>${esc(n.name || 'بدون اسم')}</b><br><small class="mono">${n.id}</small></span><small>${esc(r.text)}</small></div>`; }).join('') || '<p class="empty">لا توجد أجهزة بعد</p>'}
    <h3>بصمة هويتك</h3><p class="hint">قارن هذه البصمة وجهاً لوجه مع من تتواصل معه للتأكد من عدم وجود وسيط محتال.</p>
    <div class="node"><span class="mono">${ME.id}</span></div>`;
}
async function renderChain() {
  const v = await verifyLedger(), heads = Object.entries(witness);
  $('#chainView').innerHTML = `
    <p class="hint">كل رسالة ترسلها أو تستلمها تُسجَّل كبصمة SHA-256 (بدون المحتوى) في كتل موقّعة بمفتاحك، كل كتلة تحمل بصمة السابقة. الأجهزة الأخرى تحتفظ بآخر بصمة لسجلّك، فأي محاولة لإعادة كتابة السجل تنكشف عندها.</p>
    <div class="${v.ok ? 'ok-box' : 'bad-box'}">${v.ok ? `السجل سليم: ${ledger.blocks.length} كتلة موقّعة، و${ledger.pending.length} أحداث بانتظار الختم.` : `خلل في الكتلة #${v.at}: ${v.why}`}</div>
    <div style="display:flex;gap:8px"><button class="btn primary" id="sealBtn">اختم الأحداث الآن</button></div>
    <h3>شهادتي على سجلات الآخرين</h3>
    ${heads.map(([id, w]) => `<div class="node"><span><b>${esc(contacts[id]?.name || id)}</b><br><small class="mono">#${w.i} · ${w.h.slice(0, 16)}…</small></span><small>${w.fork ? '⚠️ تعارض' : 'مطابق'}</small></div>`).join('') || '<p class="hint">لا شيء بعد</p>'}
    <h3>كتلي</h3>
    ${ledger.blocks.slice(-30).reverse().map(b => `<div class="block"><span class="k">#${b.i}</span><span class="v">${new Date(b.ts).toLocaleString('ar')} · ${b.e.length} أحداث</span>
      <span class="k">البصمة</span><span class="v mono">${b.hash.slice(0, 32)}…</span><span class="k">السابقة</span><span class="v mono">${b.prev.slice(0, 32)}…</span></div>`).join('') || '<p class="hint">لا توجد كتل بعد</p>'}`;
  $('#sealBtn').onclick = async () => { await seal(); renderChain(); };
}

/* ---------- native transport: Android Nearby Connections / iOS Multipeer Connectivity ----------
 * In the Android / iOS app, nearby phones find each other and link automatically over
 * Bluetooth LE + Wi-Fi Direct (Android) or Bluetooth + peer-to-peer Wi-Fi (iOS). No hotspot, no QR.
 * These links carry the same signed, end-to-end encrypted mesh packets as WebRTC links. */
const NATIVE = { on: false, links: new Map(), plugin: null, platform: '' };
const toStdB64 = u8 => { let s = b64e(u8).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return s; };
async function startNative() {
  const C = window.Capacitor; if (!C?.isNativePlatform?.() || !C.registerPlugin) return;
  const N = NATIVE.plugin = C.registerPlugin('WaslNearby'); NATIVE.platform = C.getPlatform?.() || '';
  const ensure = id => {         // created on 'connected', or on the first data if that event arrives first
    let link = NATIVE.links.get(id); if (link) return link;
    link = { native: true, ep: id, id: null, pc: null, call: null,
      dc: { readyState: 'open', bufferedAmount: 0, send: str => { N.send({ id, data: toStdB64(enc.encode(str)) }).catch(() => {}); } } };
    NATIVE.links.set(id, link);
    makeCard().then(card => rawSend(link, { t: 'hello', card }));
    return link;
  };
  N.addListener('connected', ({ id }) => { ensure(id); });
  N.addListener('data', ({ id, data }) => {
    const link = ensure(id);
    let m; try { m = JSON.parse(dec.decode(b64d(data))); } catch { return; }
    onLinkMsg(link, m).catch(e => console.warn(e));
  });
  N.addListener('disconnected', ({ id }) => { const l = NATIVE.links.get(id); NATIVE.links.delete(id); if (l) { l.dc.readyState = 'closed'; dropLink(l); } });
  N.addListener('error', e => console.warn('nearby', e));
  try { await N.start({ name: ME.id }); NATIVE.on = true; toast('البحث عن الأجهزة القريبة عبر البلوتوث و Wi-Fi Direct'); }
  catch { toast('لم يُمنح إذن «الأجهزة القريبة». فعّله من إعدادات الهاتف ليعمل الاتصال بلا نقطة اتصال.'); }
  renderSoon();
}

/* ---------- pairing UI ---------- */
let pairing = null, scanStream = null, scanTimer = null;
function qrSvg(text) { const q = qrcode(0, 'L'); q.addData(text); q.make(); return q.createSvgTag({ cellSize: 3, margin: 2, scalable: true }); }
function showCode(code, label) {
  $('#qrBox').innerHTML = qrSvg(code); $('#qrBox').hidden = false;
  $('#pairOut').value = code; $('#pairOut').hidden = $('#pairOutLbl').hidden = $('#outBtns').hidden = false;
  $('#pairStatus').textContent = label;
}
async function pairMode(mode) {
  stopScan();
  if (pairing?.link && !pairing.link.id) dropLink(pairing.link);
  const mine = pairing = { mode };
  $('#modeShow').setAttribute('aria-pressed', mode === 'show'); $('#modeScan').setAttribute('aria-pressed', mode === 'scan');
  $('#qrBox').hidden = $('#pairOut').hidden = $('#pairOutLbl').hidden = $('#outBtns').hidden = true; $('#pairIn').value = ''; $('#pairOut').value = ''; $('#qrBox').innerHTML = '';
  if (mode === 'show') {
    $('#pairStatus').textContent = 'جارٍ تجهيز الرمز…';
    const { link, code } = await makeOffer();
    if (pairing !== mine) { dropLink(link); return; }   // user switched mode while the code was being prepared
    pairing.link = link;
    showCode(code, '1) اجعل الطرف الآخر يمسح هذا الرمز من «أنا أمسح الرمز». 2) ثم امسح رمز الرد الذي يظهر عنده.');
    $('#pairInLbl').textContent = 'الصق رمز الرد هنا إذا تعذّر المسح:';
  } else {
    $('#pairStatus').textContent = 'امسح الرمز الظاهر على الجهاز الآخر.';
    $('#pairInLbl').textContent = 'الصق رمز الربط هنا إذا تعذّر المسح:';
  }
}
async function pairInput(code) {
  try {
    if (pairing.mode === 'show') { await acceptAnswer(pairing.link, code); $('#pairStatus').textContent = 'جارٍ الاتصال…'; }
    else { if (pairing.link) return; const mine = pairing; const { link, code: ans } = await answerOffer(code);
      if (pairing !== mine) { dropLink(link); return; } pairing.link = link;
      showCode(ans, 'اجعل الطرف الآخر يمسح رمز الرد هذا. سيتم الربط تلقائياً.'); }
    stopScan();
  } catch (e) { $('#pairStatus').textContent = 'تعذّر قراءة الرمز: ' + (e.message || e); }
}
function pairDone(c) { $('#pairStatus').textContent = `تم الربط مع ${c.name || c.id}`; setTimeout(() => { $('#pairDlg').close(); pairing = null; openChat(c.id); }, 700); }
async function startScan() {
  try { scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } }); }
  catch { $('#pairStatus').textContent = 'لا يمكن فتح الكاميرا. الصق الرمز يدوياً.'; return; }
  const v = $('#scanV'); v.srcObject = scanStream; $('#scanBox').hidden = false; await v.play();
  const cv = document.createElement('canvas'), ctx = cv.getContext('2d', { willReadFrequently: true });
  const det = 'BarcodeDetector' in window ? new BarcodeDetector({ formats: ['qr_code'] }) : null;
  scanTimer = setInterval(async () => {
    if (!v.videoWidth) return; let text = null;
    if (det) { try { const r = await det.detect(v); if (r[0]) text = r[0].rawValue; } catch {} }
    if (!text) { cv.width = v.videoWidth; cv.height = v.videoHeight; ctx.drawImage(v, 0, 0);
      const r = jsQR(ctx.getImageData(0, 0, cv.width, cv.height).data, cv.width, cv.height); if (r) text = r.data; }
    if (text && text.startsWith('WASL1.')) { stopScan(); pairInput(text); }
  }, 300);
}
function stopScan() { clearInterval(scanTimer); if (scanStream) scanStream.getTracks().forEach(t => t.stop()); scanStream = null; $('#scanBox').hidden = true; }
function openPair() { $('#pairDlg').showModal(); pairMode('show'); }

/* ---------- voice notes ---------- */
let rec = null;
async function toggleRec() {
  if (rec) { rec.stop(); return; }
  let stream; try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); } catch { return toast('لا يمكن الوصول إلى الميكروفون'); }
  const chunks = [], peer = active; rec = new MediaRecorder(stream);
  rec.ondataavailable = e => e.data.size && chunks.push(e.data);
  rec.onstop = () => { stream.getTracks().forEach(t => t.stop()); $('#micBtn').classList.remove('rec'); rec = null;
    const blob = new Blob(chunks, { type: chunks[0]?.type || 'audio/webm' });
    if (blob.size > 500) sendFile(peer, new File([blob], 'voice.webm', { type: blob.type }), true); };
  rec.start(); $('#micBtn').classList.add('rec'); toast('جارٍ التسجيل… اضغط مرة أخرى للإرسال');
  setTimeout(() => rec && rec.state === 'recording' && rec.stop(), 120000);
}

/* ---------- wiring ---------- */
function wire() {
  $('#pairBtn').onclick = $('#pairBtn2').onclick = openPair;
  $('#modeShow').onclick = () => pairMode('show');
  $('#modeScan').onclick = () => pairMode('scan');
  $('#scanStart').onclick = startScan;
  $('#pairGo').onclick = () => { const c = $('#pairIn').value.trim(); if (c) pairInput(c); };
  $('#pairClose').onclick = () => { stopScan(); if (pairing?.link && !pairing.link.id) setTimeout(() => { if (pairing?.link && !pairing.link.id) dropLink(pairing.link); }, 60000); $('#pairDlg').close(); };
  $('#pairDlg').addEventListener('close', stopScan);
  $('#copyBtn').onclick = async () => { try { await navigator.clipboard.writeText($('#pairOut').value); toast('نُسخ الرمز'); } catch { $('#pairOut').select(); } };
  $('#shareBtn').onclick = async () => { try { await navigator.share({ text: $('#pairOut').value }); } catch {} };
  document.querySelectorAll('.views button').forEach(b => b.onclick = () => {
    document.querySelectorAll('.views button').forEach(x => x.setAttribute('aria-selected', x === b));
    $('#vChats').hidden = b.dataset.v !== 'chats'; $('#vNet').hidden = b.dataset.v !== 'net'; $('#vChain').hidden = b.dataset.v !== 'chain'; $('#vOps').hidden = b.dataset.v !== 'ops';
    if (b.dataset.v === 'ops') openOps();
    if (b.dataset.v === 'net') renderNet(); if (b.dataset.v === 'chain') renderChain();
  });
  $('#backBtn').onclick = () => { active = null; $('#app').classList.remove('in-chat'); renderList(); };
  $('#textIn').oninput = () => renderHead();
  $('#composer').onsubmit = e => { e.preventDefault(); const t = $('#textIn').value.trim(); if (!t || !active) return;
    $('#textIn').value = ''; renderHead(); if (active === SOS) sendSOS(t, $('#bcType').value); else sendText(active, t); };
  $('#msgs').addEventListener('click', e => { const b = e.target.closest('[data-ack]'); if (b) { b.disabled = true; ackBroadcast(b.dataset.ack); } });
  wireOps();
  $('#netView').addEventListener('click', e => { const b = e.target.closest('[data-radio]'); if (!b) return;
    let [kind, how] = b.dataset.radio.split(':'); if (kind === 'hf') kind = $('#hfBand')?.value || 'hf'; connectRadio(kind, how); });
  $('#netView').addEventListener('change', async e => { if (e.target.id !== 'callIn') return;
    ME.callsign = e.target.value.trim().toUpperCase().replace(/[^A-Z0-9/]/g, ''); ME.idn.callsign = ME.callsign; await db.set('identity', ME.idn); toast('حُفظ نداء الهواة'); });
  $('#attachBtn').onclick = () => $('#fileIn').click();
  $('#fileIn').onchange = () => { const f = $('#fileIn').files[0]; $('#fileIn').value = ''; if (f && active) sendFile(active, f); };
  $('#micBtn').onclick = toggleRec;
  $('#voiceBtn').onclick = () => startCall(active, false);
  $('#videoBtn').onclick = () => startCall(active, true);
  $('#directBtn').onclick = () => connectDirect(active);
  $('#acceptBtn').onclick = acceptCall;
  $('#hangBtn').onclick = () => endCall(true);
  $('#muteBtn').onclick = e => { const on = e.currentTarget.getAttribute('aria-pressed') !== 'true'; e.currentTarget.setAttribute('aria-pressed', on);
    CALL.local?.getAudioTracks().forEach(t => t.enabled = !on); };
  $('#camBtn').onclick = e => { const on = e.currentTarget.getAttribute('aria-pressed') !== 'true'; e.currentTarget.setAttribute('aria-pressed', on);
    CALL.local?.getVideoTracks().forEach(t => t.enabled = !on); };
  $('#nameOk').onclick = async () => { ME.name = $('#nameIn').value.trim().slice(0, 32); ME.idn.name = ME.name; await db.set('identity', ME.idn); renderMe(); announce();
    try { if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission(); } catch {} };
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && active) openChat(active); });
}
function renderMe() {
  $('#meName').textContent = ME.name || 'أنا'; $('#meId').textContent = ME.id;
  $('#meAv').textContent = initial(ME.name || 'أ'); $('#meAv').style.background = colorOf(ME.id);
}

/* ---------- boot ---------- */
async function boot() {
  if (!crypto.subtle || (!window.RTCPeerConnection && !window.Capacitor?.isNativePlatform?.())) {
    document.body.innerHTML = '<p style="padding:24px;font-family:sans-serif">يحتاج وَصْل إلى اتصال آمن (https) ومتصفح حديث. افتح التطبيق من رابطه الآمن مرة واحدة ثم ثبّته، وبعدها يعمل بلا إنترنت.</p>'; return;
  }
  const fresh = await loadIdentity();
  contacts = (await db.get('contacts')) || {}; chats = (await db.get('chats')) || {};
  ledger = (await db.get('ledger')) || ledger; witness = (await db.get('witness')) || {};
  ops = { bc: {}, props: {}, psigs: {}, tbs: {}, ...((await db.get('ops')) || {}) };
  try { const b = await navigator.getBattery?.(); if (b) { const u = () => ME.batt = { l: Math.round(b.level * 100), c: b.charging };
    u(); b.onlevelchange = b.onchargingchange = u; } } catch {}
  for (const c of Object.values(contacts)) c.hops = 9;
  for (const l of Object.values(chats)) for (const m of l) { if (m.progress !== undefined && !m.blob) m.progress = undefined; if (m.status === 'pending') m.status = 'queued'; }
  wire(); renderMe(); renderAll();
  if (fresh) { $('#newId').textContent = ME.id; $('#nameDlg').showModal(); }
  setInterval(announce, CARD_EVERY);
  setInterval(() => { if (ledger.pending.length) seal(); }, 30000);
  setInterval(renderSoon, 10000);
  setInterval(checkTimers, 15000);
  if ('serviceWorker' in navigator && !window.Capacitor?.isNativePlatform?.()) navigator.serviceWorker.register('sw.js').catch(() => {});
  startNative();
  window.WASL = { ME, contacts, links, chats, stats, ledger: () => ledger, verifyLedger, seal, connectDirect,
    ops: () => ops, radios, NATIVE, attachRadio, sendFile, startCall,
    setCallsign: cs => { ME.callsign = cs; },
    virtualRadio: (kind, opts) => attachRadio(Object.assign(new WaslRadio.VirtualPort(kind, opts), {})), sendSOS, ackBroadcast, createProposal, signProposal, armTimer, disarmTimer, checkTimers, health };  // debug/testing hook
}
boot();
})();
