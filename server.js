'use strict';
/* LARP It Till You Make It: push server. Zero dependencies (Node 18+).
   Serves the site, stores push subscriptions, and sends real Web Push
   notifications (RFC 8030 / 8291 aes128gcm / 8292 VAPID). */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@larpittillyoumakeit.com';
const ALLOW_HTTP = process.env.ALLOW_HTTP_ENDPOINTS === '1'; // tests only
const PUBLIC = path.join(__dirname, 'public');

if (ADMIN_TOKEN.length < 16) { console.error('Set ADMIN_TOKEN to a long random string (16+ chars). Example: openssl rand -hex 24'); process.exit(1); }
fs.mkdirSync(DATA_DIR, { recursive: true });

const b64u = b => Buffer.from(b).toString('base64url');
const unb64u = s => Buffer.from(String(s), 'base64url');
const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();

/* ---------- VAPID keys ---------- */
function loadVapid() {
  let j = null;
  if (process.env.VAPID_KEYS) { try { j = JSON.parse(process.env.VAPID_KEYS); } catch { console.error('VAPID_KEYS is not valid JSON'); process.exit(1); } }
  const f = path.join(DATA_DIR, 'vapid.json');
  if (!j && fs.existsSync(f)) j = JSON.parse(fs.readFileSync(f, 'utf8'));
  if (!j) {
    j = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'jwk' });
    fs.writeFileSync(f, JSON.stringify(j), { mode: 0o600 });
    console.log('Generated new VAPID keys in', f);
  }
  const priv = crypto.createPrivateKey({ key: j, format: 'jwk' });
  const pub = b64u(Buffer.concat([Buffer.from([4]), unb64u(j.x), unb64u(j.y)]));
  return { priv, pub };
}
const VAPID = loadVapid();

function vapidHeader(origin) {
  const h = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const p = b64u(JSON.stringify({ aud: origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SUBJECT }));
  const sig = crypto.sign('sha256', Buffer.from(h + '.' + p), { key: VAPID.priv, dsaEncoding: 'ieee-p1363' });
  return `vapid t=${h}.${p}.${b64u(sig)}, k=${VAPID.pub}`;
}

/* ---------- Web Push payload encryption (RFC 8291, aes128gcm) ---------- */
function encrypt(sub, plaintext) {
  const uaPub = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const as = crypto.createECDH('prime256v1'); as.generateKeys();
  const asPub = as.getPublicKey();
  const secret = as.computeSecret(uaPub);
  const salt = crypto.randomBytes(16);
  const prkKey = hmac(auth, secret);
  const ikm = hmac(prkKey, Buffer.concat([Buffer.from('WebPush: info\0'), uaPub, asPub, Buffer.from([1])]));
  const prk = hmac(salt, ikm);
  const cek = hmac(prk, Buffer.concat([Buffer.from('Content-Encoding: aes128gcm\0'), Buffer.from([1])])).subarray(0, 16);
  const nonce = hmac(prk, Buffer.concat([Buffer.from('Content-Encoding: nonce\0'), Buffer.from([1])])).subarray(0, 12);
  const c = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const ct = Buffer.concat([c.update(Buffer.concat([plaintext, Buffer.from([2])])), c.final(), c.getAuthTag()]);
  const rs = Buffer.alloc(4); rs.writeUInt32BE(4096);
  return Buffer.concat([salt, rs, Buffer.from([asPub.length]), asPub, ct]);
}

/* ---------- subscriptions ---------- */
const SUBS_FILE = path.join(DATA_DIR, 'subs.json');
let subs = {};
try { subs = JSON.parse(fs.readFileSync(SUBS_FILE, 'utf8')); } catch {}
const saveSubs = () => fs.writeFileSync(SUBS_FILE, JSON.stringify(subs));

function validSub(s) {
  try {
    if (!s || typeof s.endpoint !== 'string' || s.endpoint.length > 1000) return false;
    const u = new URL(s.endpoint);
    if (u.protocol !== 'https:' && !(ALLOW_HTTP && u.protocol === 'http:')) return false;
    return unb64u(s.keys.p256dh).length === 65 && unb64u(s.keys.auth).length === 16;
  } catch { return false; }
}

async function sendOne(sub, payload) {
  const body = encrypt(sub, Buffer.from(JSON.stringify(payload)));
  const res = await fetch(sub.endpoint, {
    method: 'POST', body, signal: AbortSignal.timeout(15000),
    headers: { 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '3600', Urgency: 'high', Authorization: vapidHeader(new URL(sub.endpoint).origin) }
  });
  return res.status;
}
async function broadcast(payload) {
  const out = { sent: 0, failed: 0, removed: 0 };
  await Promise.all(Object.values(subs).map(async ({ subscription }) => {
    try {
      const st = await sendOne(subscription, payload);
      if (st >= 200 && st < 300) out.sent++;
      else if (st === 404 || st === 410) { delete subs[subscription.endpoint]; out.removed++; }
      else out.failed++;
    } catch { out.failed++; }
  }));
  if (out.removed) saveSubs();
  return out;
}

/* ---------- fake sale generator (mirrors the site's formats) ---------- */
const NAMES = ['Alex','Sam','Priya','Jordan','Mei','Lucas','Fatima','Noah','Aisha','Diego','Emma','Rahim','Sofia','Kenji','Zara','Tanvir','Olivia','Ravi','Nadia','Liam'];
const CURRENCIES = ['$', '৳', '€', '£', '¥', '₹', 'A$', 'C$'];
const money = (n, c) => c + Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const FORMATS = {
  shopify:  o => ({ title: `New order · ${o.m}`, body: `${o.store} · #${o.n} · ${o.qty} × ${o.name}` }),
  stripe:   o => ({ title: `Payment · ${o.m}`, body: `${o.who} · ${o.name} · ${o.store}` }),
  gumroad:  o => ({ title: `New sale: ${o.name}`, body: `${o.who} paid ${o.m}${o.qty > 1 ? ` (${o.qty} ×)` : ''}` }),
  lemon:    o => ({ title: `New order: ${o.m}`, body: `${o.name} · ${o.who} · ${o.store}` }),
  appstore: o => ({ title: `Sale · ${o.m}`, body: `${o.store} · ${o.name}${o.qty > 1 ? ` × ${o.qty}` : ''}` })
};
function makeSale(job) {
  const p = job.products[Math.floor(Math.random() * job.products.length)];
  const qty = job.qtyRandom ? 1 + Math.floor(Math.random() * 3) : 1;
  const o = { name: p.name, qty, m: money(p.price * qty, job.currency), who: NAMES[Math.floor(Math.random() * NAMES.length)], store: job.store, n: job.startOrder + job.sent };
  return Object.assign(FORMATS[job.kind](o), { tag: 'sale-' + Date.now() + '-' + job.sent });
}

/* ---------- jobs (in memory; lost on restart) ---------- */
const jobs = new Map();
function cleanJob(b) {
  const num = (v, lo, hi, d) => { v = Number(v); return isFinite(v) ? Math.min(hi, Math.max(lo, v)) : d; };
  if (!FORMATS[b.kind]) throw new Error('Unknown type');
  if (!CURRENCIES.includes(b.currency)) throw new Error('Unknown currency');
  if (!Array.isArray(b.products) || !b.products.length || b.products.length > 8) throw new Error('1-8 products required');
  const products = b.products.map(p => {
    if (!p || typeof p.name !== 'string' || !p.name.trim()) throw new Error('Bad product');
    return { name: p.name.trim().slice(0, 60), price: num(p.price, 0, 1e7, 0) };
  });
  return { kind: b.kind, currency: b.currency, products, store: String(b.store || 'Online Store').slice(0, 40), qtyRandom: !!b.qtyRandom,
    startOrder: Math.floor(num(b.startOrder, 0, 1e9, 1001)), delaySec: num(b.delaySec, 0, 86400, 0), count: Math.floor(num(b.count, 1, 200, 1)), intervalSec: num(b.intervalSec, 1, 3600, 5) };
}
function runJob(job) {
  const step = async () => {
    if (job.cancelled) return;
    await broadcast(makeSale(job)).catch(() => {});
    job.sent++;
    if (job.sent >= job.count) { jobs.delete(job.id); return; }
    job.timer = setTimeout(step, job.intervalSec * 1000 * (0.6 + Math.random() * 0.8));
  };
  job.timer = setTimeout(step, job.delaySec * 1000);
}

/* ---------- http ---------- */
const authed = req => {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) return false;
  const a = crypto.createHash('sha256').update(m[1]).digest(), b = crypto.createHash('sha256').update(ADMIN_TOKEN).digest();
  return crypto.timingSafeEqual(a, b);
};
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
const readBody = req => new Promise((ok, no) => {
  let n = 0; const ch = [];
  req.on('data', c => { n += c.length; if (n > 20000) { no(new Error('Too large')); req.destroy(); } else ch.push(c); });
  req.on('end', () => { try { ok(JSON.parse(Buffer.concat(ch).toString() || '{}')); } catch { no(new Error('Bad JSON')); } });
  req.on('error', no);
});
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.png': 'image/png', '.webmanifest': 'application/manifest+json', '.json': 'application/json' };
let failTimes = [];

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer');
  const url = new URL(req.url, 'http://x'), p = url.pathname;
  try {
    if (p === '/api/vapid' && req.method === 'GET') return json(res, 200, { publicKey: VAPID.pub });
    if (p === '/api/subscribe' && req.method === 'POST') {
      const b = await readBody(req);
      if (!validSub(b.subscription)) return json(res, 400, { error: 'Invalid subscription' });
      if (!subs[b.subscription.endpoint] && Object.keys(subs).length >= 100) return json(res, 429, { error: 'Too many subscribers' });
      subs[b.subscription.endpoint] = { subscription: { endpoint: b.subscription.endpoint, keys: { p256dh: b.subscription.keys.p256dh, auth: b.subscription.keys.auth } }, added: Date.now() };
      saveSubs(); return json(res, 200, { ok: true });
    }
    if (p.startsWith('/api/')) {
      const now = Date.now(); failTimes = failTimes.filter(t => now - t < 60000);
      if (failTimes.length >= 20) return json(res, 429, { error: 'Slow down' });
      if (!authed(req)) { failTimes.push(now); return json(res, 401, { error: 'Unauthorized' }); }
      if (p === '/api/status' && req.method === 'GET') return json(res, 200, { subscribers: Object.keys(subs).length, jobs: [...jobs.values()].map(j => ({ id: j.id, kind: j.kind, sent: j.sent, count: j.count })) });
      if (p === '/api/send' && req.method === 'POST') {
        const b = await readBody(req);
        return json(res, 200, await broadcast({ title: String(b.title || 'New sale').slice(0, 100), body: String(b.body || '').slice(0, 300), tag: 'msg-' + Date.now() }));
      }
      if (p === '/api/job' && req.method === 'POST') {
        if (jobs.size >= 20) return json(res, 429, { error: 'Too many active jobs' });
        let c; try { c = cleanJob(await readBody(req)); } catch (e) { return json(res, 400, { error: e.message }); }
        const job = Object.assign(c, { id: crypto.randomBytes(4).toString('hex'), sent: 0 });
        jobs.set(job.id, job); runJob(job); return json(res, 200, { id: job.id });
      }
      if (p === '/api/cancel' && req.method === 'POST') {
        const b = await readBody(req), j = jobs.get(b.id);
        if (j) { j.cancelled = true; clearTimeout(j.timer); jobs.delete(j.id); }
        return json(res, 200, { ok: true });
      }
      return json(res, 404, { error: 'Not found' });
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    const rel = p === '/' ? 'index.html' : p === '/admin' ? 'admin.html' : decodeURIComponent(p).replace(/^\/+/, '');
    const file = path.normalize(path.join(PUBLIC, rel));
    if (!file.startsWith(PUBLIC + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); return res.end('Not found'); }
    const headers = { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' };
    if (rel === 'sw.js' || rel === 'admin.html') headers['Cache-Control'] = 'no-cache';
    res.writeHead(200, headers); fs.createReadStream(file).pipe(res);
  } catch (e) { if (!res.headersSent) json(res, 400, { error: 'Bad request' }); else res.end(); }
});
module.exports = { server, encrypt, VAPID };
if (require.main === module) server.listen(PORT, () => console.log(`LARP push server on :${PORT}  (site /, admin /admin)`));
