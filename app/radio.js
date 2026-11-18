/* وَصْل — narrowband radio layer (LoRa, HF, any KISS TNC, sound-card modem).
 * - Fragmentation: [0x57][ver][id:3][idx][total][payload][crc16]  (fits any MTU)
 * - KISS framing over Web Serial: RNode (LoRa) firmware, hardware HF/VHF TNCs
 * - 4-FSK audio modem over the sound card: plug a radio's audio in/out (VOX keyed), works on HF SSB and VHF FM
 * Works in the browser (window.WaslRadio) and in Node (module.exports) for testing. */
(function (root) {
'use strict';
const rnd = n => (root.crypto || globalThis.crypto).getRandomValues(new Uint8Array(n));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const hex = a => Array.from(a, b => b.toString(16).padStart(2, '0')).join('');

/* CRC-16/CCITT-FALSE */
function crc16(buf) { let c = 0xFFFF; for (const b of buf) { c ^= b << 8; for (let i = 0; i < 8; i++) c = c & 0x8000 ? ((c << 1) ^ 0x1021) & 0xFFFF : (c << 1) & 0xFFFF; } return c; }

/* KISS */
const FEND = 0xC0, FESC = 0xDB, TFEND = 0xDC, TFESC = 0xDD;
function kissEncode(data, port = 0) {
  const out = [FEND, (port << 4) & 0xF0];
  for (const b of data) { if (b === FEND) out.push(FESC, TFEND); else if (b === FESC) out.push(FESC, TFESC); else out.push(b); }
  out.push(FEND); return Uint8Array.from(out);
}
class KissDecoder {
  constructor(onFrame) { this.on = onFrame; this.buf = []; this.esc = false; }
  push(bytes) {
    for (const b of bytes) {
      if (b === FEND) { if (this.buf.length > 1 && (this.buf[0] & 0x0F) === 0) this.on(Uint8Array.from(this.buf.slice(1))); this.buf = []; this.esc = false; continue; }
      if (this.esc) { this.buf.push(b === TFEND ? FEND : b === TFESC ? FESC : b); this.esc = false; }
      else if (b === FESC) this.esc = true; else this.buf.push(b);
      if (this.buf.length > 4096) this.buf = [];
    }
  }
}

/* AX.25 UI frames: the standard for amateur packet (Direwolf, VARA, hardware TNCs). Carries the callsign in every frame. */
function ax25Addr(call, last, cmd) {
  const [c, ssid = '0'] = String(call || 'NOCALL').toUpperCase().split('-'), out = new Uint8Array(7);
  const base = c.replace(/[^A-Z0-9]/g, '').slice(0, 6).padEnd(6, ' ');
  for (let i = 0; i < 6; i++) out[i] = base.charCodeAt(i) << 1;
  out[6] = (cmd ? 0xE0 : 0x60) | ((parseInt(ssid, 10) & 0x0F) << 1) | (last ? 1 : 0);
  return out;
}
function ax25Call(b) { let c = ''; for (let i = 0; i < 6; i++) c += String.fromCharCode(b[i] >> 1); c = c.trim(); const ssid = (b[6] >> 1) & 0x0F; return ssid ? `${c}-${ssid}` : c; }
function ax25Encode(dest, src, info) {
  const f = new Uint8Array(16 + info.length);
  f.set(ax25Addr(dest, false, true), 0); f.set(ax25Addr(src, true, false), 7); f[14] = 0x03; f[15] = 0xF0; f.set(info, 16);
  return f;
}
function ax25Decode(f) {
  if (f.length < 16) return null;
  let i = 0; const calls = [];
  while (i + 7 <= f.length) { calls.push(ax25Call(f.subarray(i, i + 7))); const last = f[i + 6] & 1; i += 7; if (last) break; if (calls.length > 10) return null; }
  if (calls.length < 2 || f[i] !== 0x03 || f[i + 1] !== 0xF0) return null;
  return { dest: calls[0], src: calls[1], info: f.slice(i + 2) };
}

/* fragmentation */
const MAGIC = 0x57, VER = 1, HDR = 7;
function fragment(payload, mtu) {
  const room = mtu - HDR - 2, total = Math.max(1, Math.ceil(payload.length / room));
  if (total > 255) throw new Error('payload too large for this link');
  const id = rnd(3), frames = [];
  for (let i = 0; i < total; i++) {
    const part = payload.subarray(i * room, (i + 1) * room), f = new Uint8Array(HDR + part.length + 2);
    f[0] = MAGIC; f[1] = VER; f.set(id, 2); f[5] = i; f[6] = total; f.set(part, HDR);
    const c = crc16(f.subarray(0, HDR + part.length)); f[HDR + part.length] = c >> 8; f[HDR + part.length + 1] = c & 255;
    frames.push(f);
  }
  return frames;
}
class Reassembler {
  constructor(onMessage, ttl = 300000) { this.on = onMessage; this.ttl = ttl; this.m = new Map(); this.bad = 0; }
  push(f) {
    if (f.length < HDR + 2 || f[0] !== MAGIC || f[1] !== VER) { this.bad++; return false; }
    const n = f.length - 2;
    if (((f[n] << 8) | f[n + 1]) !== crc16(f.subarray(0, n))) { this.bad++; return false; }
    const key = hex(f.subarray(2, 5)), idx = f[5], total = f[6], now = Date.now();
    for (const [k, v] of this.m) if (now - v.ts > this.ttl) this.m.delete(k);
    const e = this.m.get(key) || { parts: [], got: 0, total, ts: now };
    if (!e.parts[idx]) { e.parts[idx] = f.slice(HDR, n); e.got++; }
    this.m.set(key, e);
    if (e.got === e.total) {
      this.m.delete(key);
      const len = e.parts.reduce((s, p) => s + p.length, 0), out = new Uint8Array(len); let o = 0;
      for (const p of e.parts) { out.set(p, o); o += p.length; }
      this.on(out);
    }
    return true;
  }
}

/* 4-FSK sound-card modem. 2 bits/symbol. Profiles: HF (SSB, 50 baud = 100 bit/s), VHF FM (300 baud = 600 bit/s). */
/* TCP modem presets (connected through the native app): real throughput is set by the modem */
const MODEMS = {
  vara: { kind: 'hf', label: 'VARA HF', port: 8100, bps: 2000, mtu: 200 },
  ardop: { kind: 'hf', label: 'ARDOP', port: 8515, bps: 800, mtu: 128 },
  direwolf: { kind: 'vhf', label: 'Direwolf (AX.25 1200)', port: 8001, bps: 1200, mtu: 200 },
};
const PROFILES = {
  hf: { tones: [1000, 1400, 1800, 2200], baud: 50 },
  vhf: { tones: [900, 1500, 2100, 2700], baud: 300 },
};
const SYNC = [1, 2, 3, 0, 2, 1, 0, 3], PRE = 24;
function modulate(bytes, sr, prof = PROFILES.hf) {
  const N = Math.round(sr / prof.baud), syms = [];
  for (let i = 0; i < PRE; i++) syms.push(i % 2 ? 3 : 0);          // preamble (also keys the radio's VOX)
  syms.push(...SYNC);
  const body = new Uint8Array(bytes.length + 4); body[0] = bytes.length >> 8; body[1] = bytes.length & 255; body.set(bytes, 2);
  const c = crc16(body.subarray(0, bytes.length + 2)); body[bytes.length + 2] = c >> 8; body[bytes.length + 3] = c & 255;
  for (const b of body) for (let s = 6; s >= 0; s -= 2) syms.push((b >> s) & 3);
  syms.push(0, 0);
  const out = new Float32Array(syms.length * N), ramp = Math.max(1, Math.round(N * 0.08)); let ph = 0;
  syms.forEach((s, k) => { const w = 2 * Math.PI * prof.tones[s] / sr;
    for (let i = 0; i < N; i++) { ph += w; let a = 0.5; if (i < ramp) a *= i / ramp; else if (i > N - ramp) a *= (N - i) / ramp; out[k * N + i] = a * Math.sin(ph); } });
  return out;
}
function demodulate(samples, sr, prof = PROFILES.hf) {
  const N = Math.round(sr / prof.baud), STEP = 8, hop = Math.max(1, Math.floor(N / STEP));
  const nh = Math.floor((samples.length - N) / hop); if (nh <= 0) return { frames: [], used: 0 };
  const coef = prof.tones.map(f => 2 * Math.cos(2 * Math.PI * f / sr)), sym = new Uint8Array(nh);
  for (let h = 0; h < nh; h++) {
    const o = h * hop; let best = -1, bi = 0;
    for (let k = 0; k < 4; k++) { const c = coef[k]; let s1 = 0, s2 = 0;
      for (let i = 0; i < N; i++) { const s0 = samples[o + i] + c * s1 - s2; s2 = s1; s1 = s0; }
      const p = s1 * s1 + s2 * s2 - c * s1 * s2; if (p > best) { best = p; bi = k; } }
    sym[h] = bi;
  }
  // coarse symbol grid (hop = N/8) only for finding the sync word; data symbols are measured at exact sample offsets
  const symAt = o => { let best = -1, bi = 0;
    for (let k = 0; k < 4; k++) { const c = coef[k]; let s1 = 0, s2 = 0;
      for (let i = 0; i < N; i++) { const s0 = samples[o + i] + c * s1 - s2; s2 = s1; s1 = s0; }
      const p = s1 * s1 + s2 * s2 - c * s1 * s2; if (p > best) { best = p; bi = k; } }
    return bi; };
  const syncAt = h => { for (let j = 0; j < SYNC.length; j++) { const o = h * hop + j * N; if (o + N > samples.length || symAt(o) !== SYNC[j]) return false; } return true; };
  const coarse = h => { for (let j = 0; j < SYNC.length; j++) { const x = h + Math.round(j * N / hop); if (x >= nh || sym[x] !== SYNC[j]) return false; } return true; };
  const readByte = o => (symAt(o) << 6) | (symAt(o + N) << 4) | (symAt(o + 2 * N) << 2) | symAt(o + 3 * N);
  const frames = []; let used = 0, h = 0;
  while (h * hop + N * (SYNC.length + 8) < samples.length) {
    if (!coarse(h) || !syncAt(h)) { h++; continue; }
    let e = h; while (e + 1 < nh && syncAt(e + 1)) e++;
    const s0 = Math.round((h + e) / 2) * hop + SYNC.length * N;      // centre of the timing window
    const len = (readByte(s0) << 8) | readByte(s0 + 4 * N), endS = s0 + (len + 4) * 4 * N;
    if (len > 2048) { h = e + 1; continue; }
    if (endS + N > samples.length) break;                           // frame not complete yet: keep buffer
    const body = new Uint8Array(len + 4);
    for (let i = 0; i < len + 4; i++) body[i] = readByte(s0 + i * 4 * N);
    if (((body[len + 2] << 8) | body[len + 3]) === crc16(body.subarray(0, len + 2))) { frames.push(body.slice(2, len + 2)); used = endS; h = Math.ceil(endS / hop); }
    else h = e + 1;
  }
  h = Math.min(h, nh);
  if (!frames.length) used = Math.max(0, (h - STEP * (PRE + SYNC.length)) * hop);
  return { frames, used };
}

/* link kinds and what each may carry */
const KINDS = {
  lora: { label: 'LoRa', mtu: 200, bps: 1760, encrypt: true, maxPkt: 6000, cardEvery: 120000, duty: 0.1 },
  hf: { label: 'HF', mtu: 64, bps: 100, encrypt: false, maxPkt: 1600, cardEvery: 600000, duty: 1 },
  vhf: { label: 'VHF/UHF', mtu: 128, bps: 600, encrypt: false, maxPkt: 3000, cardEvery: 300000, duty: 1 },
  air: { label: 'صوت عبر الهواء', mtu: 128, bps: 600, encrypt: true, maxPkt: 3000, cardEvery: 300000, duty: 1 },
};

/* a radio port: queues fragments, paces to the link's bit rate and duty cycle */
class Port {
  constructor(kind, opts = {}) {
    this.kind = kind; Object.assign(this, KINDS[kind], opts);
    this.queue = []; this.busy = false; this.onPayload = null; this.onState = null; this.state = 'off';
    this.stats = { txFrames: 0, rxFrames: 0, txBytes: 0, rxBytes: 0, bad: 0, txMs: 0 };
    this.reasm = new Reassembler(b => this.onPayload && this.onPayload(b));
    this.cardTs = {};
  }
  airtime(bytes) { return Math.ceil((bytes * 8 / this.bps) * 1000); }
  send(payload) { for (const f of fragment(payload, this.mtu)) this.queue.push(f); this.pump(); }
  async pump() {
    if (this.busy) return; this.busy = true;
    try { while (this.queue.length && this.state === 'on') {
      const raw = this.queue.shift(), t0 = Date.now();
      const f = this.ax25 ? ax25Encode('WASL', this.callsign || 'NOCALL', raw) : raw;
      await this.txFrame(f);
      this.stats.txFrames++; this.stats.txBytes += f.length;
      const air = Math.max(Date.now() - t0, this.pace ? this.airtime(f.length) : 0); this.stats.txMs += air;
      if (this.duty < 1) await sleep(air * (1 / this.duty - 1));        // legal duty-cycle wait (e.g. 10% on EU 869.5 MHz)
    } } finally { this.busy = false; }
  }
  rxFrame(f) {
    this.stats.rxFrames++; this.stats.rxBytes += f.length;
    if (this.ax25) { const a = ax25Decode(f); if (!a || a.dest !== 'WASL') { this.stats.foreign = (this.stats.foreign || 0) + 1; return; } this.lastCall = a.src; f = a.info; }
    if (!this.reasm.push(f)) this.stats.bad++;
  }
  setState(s, msg) { this.state = s; this.onState && this.onState(s, msg); if (s === 'on') this.pump(); }
}

/* KISS TNC on a serial port (USB cable): RNode LoRa boards, HF/VHF hardware TNCs */
class SerialKissPort extends Port {
  constructor(kind, opts) { super(kind, opts); this.pace = true; }
  async open(baudRate = 115200) {
    if (!('serial' in navigator)) throw new Error('هذا المتصفح لا يدعم المنفذ التسلسلي. استخدم Chrome أو Edge على الحاسوب.');
    this.port = await navigator.serial.requestPort();
    await this.port.open({ baudRate });
    this.writer = this.port.writable.getWriter();
    this.setState('on'); this.readLoop();
  }
  async readLoop() {
    const dec = new KissDecoder(f => this.rxFrame(f));
    try { this.reader = this.port.readable.getReader();
      while (true) { const { value, done } = await this.reader.read(); if (done) break; dec.push(value); } }
    catch {} finally { this.setState('off', 'انقطع الجهاز'); }
  }
  async txFrame(f) { await this.writer.write(kissEncode(f)); await sleep(this.airtime(f.length + 4)); }
  async close() { try { await this.reader?.cancel(); this.writer?.releaseLock(); await this.port?.close(); } catch {} this.setState('off'); }
}

/* sound-card modem: radio speaker -> device mic, device speaker -> radio mic (VOX) */
class AudioModemPort extends Port {
  constructor(kind, opts) { super(kind, opts); this.prof = PROFILES[kind === 'hf' ? 'hf' : 'vhf']; this.bps = this.prof.baud * 2; this.buf = []; this.bufLen = 0; }
  async open() {
    this.stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false } });
    this.ctx = new AudioContext(); this.sr = this.ctx.sampleRate;
    const src = this.ctx.createMediaStreamSource(this.stream), proc = this.ctx.createScriptProcessor(4096, 1, 1);
    proc.onaudioprocess = e => { if (this.txing) return; const d = new Float32Array(e.inputBuffer.getChannelData(0)); this.buf.push(d); this.bufLen += d.length;
      this.level = Math.sqrt(d.reduce((s, x) => s + x * x, 0) / d.length); };
    src.connect(proc); proc.connect(this.ctx.destination);
    this.timer = setInterval(() => this.scan(), 1000);
    this.setState('on');
  }
  scan() {
    if (!this.bufLen) return;
    const all = new Float32Array(this.bufLen); let o = 0; for (const b of this.buf) { all.set(b, o); o += b.length; }
    const { frames, used } = demodulate(all, this.sr, this.prof);
    frames.forEach(f => this.rxFrame(f));
    let keep = all.subarray(Math.min(used, all.length));
    const max = this.sr * 30; if (keep.length > max) keep = keep.subarray(keep.length - max);
    this.buf = [new Float32Array(keep)]; this.bufLen = keep.length;
  }
  async txFrame(f) {
    const s = modulate(f, this.sr, this.prof), b = this.ctx.createBuffer(1, s.length, this.sr); b.copyToChannel(s, 0);
    const n = this.ctx.createBufferSource(); n.buffer = b; n.connect(this.ctx.destination);
    this.txing = true; this.buf = []; this.bufLen = 0;
    await new Promise(r => { n.onended = r; n.start(); });
    await sleep(150); this.txing = false;
  }
  async close() { clearInterval(this.timer); this.stream?.getTracks().forEach(t => t.stop()); await this.ctx?.close(); this.setState('off'); }
}

/* KISS over any byte stream: TCP to VARA / Direwolf / ARDOP through the native app */
class KissStreamPort extends Port {
  constructor(kind, opts) { super(kind, opts); this.pace = true; this.dec = new KissDecoder(f => this.rxFrame(f)); this.write = opts.write; this.closeFn = opts.close; }
  async open() { this.setState('on'); }
  feed(bytes) { this.dec.push(bytes); }
  async txFrame(f) { await this.write(kissEncode(f)); await sleep(this.airtime(f.length + 4)); }
  async close() { try { await this.closeFn?.(); } catch {} this.setState('off'); }
}

/* virtual port: used by tests and simulators to bridge two devices frame by frame */
class VirtualPort extends Port {
  constructor(kind, opts) { super(kind, opts); this.pace = true; this.out = null; }
  async open() { this.setState('on'); }
  async txFrame(f) { await sleep(this.airtime(f.length)); this.out && this.out(f); }
  inject(f) { this.rxFrame(f instanceof Uint8Array ? f : Uint8Array.from(f)); }
}

const api = { crc16, kissEncode, KissDecoder, ax25Encode, ax25Decode, fragment, Reassembler, modulate, demodulate, PROFILES, KINDS, MODEMS, Port, SerialKissPort, AudioModemPort, KissStreamPort, VirtualPort };
if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.WaslRadio = api;
})(typeof window !== 'undefined' ? window : globalThis);
