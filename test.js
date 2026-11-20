'use strict';
/* End-to-end check: starts the server, subscribes a fake phone whose push
   endpoint is a local mock, sends pushes, then verifies the VAPID signature
   and decrypts the payload exactly as a browser would (RFC 8291 / 8292). */
const { spawn } = require('child_process'), http = require('http'), crypto = require('crypto'), fs = require('fs'), os = require('os'), path = require('path'), assert = require('assert');
const TOKEN = 'test-token-0123456789abcdef', SP = 4599, MP = 4598, base = 'http://127.0.0.1:' + SP;
const hmac = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
const ua = crypto.createECDH('prime256v1'); ua.generateKeys(); const auth = crypto.randomBytes(16);
const received = []; let mockStatus = 201, vapidPub;

const mock = http.createServer((req, res) => {
  const ch = []; req.on('data', c => ch.push(c)); req.on('end', () => {
    const body = Buffer.concat(ch);
    try {
      const m = /^vapid t=([^,]+), k=(.+)$/.exec(req.headers.authorization); assert(m, 'vapid header');
      assert.strictEqual(m[2], vapidPub);
      const [h, p, s] = m[1].split('.'); const pub = unb(m[2]);
      const key = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b(pub.subarray(1, 33)), y: b(pub.subarray(33)) }, format: 'jwk' });
      assert(crypto.verify('sha256', Buffer.from(h + '.' + p), { key, dsaEncoding: 'ieee-p1363' }, unb(s)), 'JWT signature');
      const claims = JSON.parse(unb(p).toString()); assert.strictEqual(claims.aud, 'http://127.0.0.1:' + MP); assert(claims.exp > Date.now() / 1000);
      assert.strictEqual(req.headers['content-encoding'], 'aes128gcm');
      const salt = body.subarray(0, 16), idlen = body[20], asPub = body.subarray(21, 21 + idlen), ct = body.subarray(21 + idlen);
      const uaPub = ua.getPublicKey(), secret = ua.computeSecret(asPub);
      const ikm = hmac(hmac(auth, secret), Buffer.concat([Buffer.from('WebPush: info\0'), uaPub, asPub, Buffer.from([1])]));
      const prk = hmac(salt, ikm);
      const cek = hmac(prk, Buffer.concat([Buffer.from('Content-Encoding: aes128gcm\0'), Buffer.from([1])])).subarray(0, 16);
      const nonce = hmac(prk, Buffer.concat([Buffer.from('Content-Encoding: nonce\0'), Buffer.from([1])])).subarray(0, 12);
      const d = crypto.createDecipheriv('aes-128-gcm', cek, nonce); d.setAuthTag(ct.subarray(ct.length - 16));
      const pt = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
      assert.strictEqual(pt[pt.length - 1], 2); received.push(JSON.parse(pt.subarray(0, -1).toString()));
    } catch (e) { received.push({ error: e.message }); }
    res.writeHead(mockStatus); res.end();
  });
});
const b = x => Buffer.from(x).toString('base64url'), unb = s => Buffer.from(s, 'base64url');
const call = async (p, body, tok = TOKEN) => { const r = await fetch(base + p, { method: body ? 'POST' : 'GET', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) }); return [r.status, await r.json()]; };
const wait = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  await new Promise(r => mock.listen(MP, r));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'larp-'));
  const srv = spawn(process.execPath, ['server.js'], { env: { ...process.env, PORT: SP, ADMIN_TOKEN: TOKEN, DATA_DIR: dir, ALLOW_HTTP_ENDPOINTS: '1' }, stdio: 'inherit' });
  try {
    await wait(700);
    vapidPub = (await (await fetch(base + '/api/vapid')).json()).publicKey; assert.strictEqual(unb(vapidPub).length, 65);
    assert.strictEqual((await call('/api/status', null, 'wrong'))[0], 401);
    const sub = { endpoint: 'http://127.0.0.1:' + MP + '/push/abc', keys: { p256dh: b(ua.getPublicKey()), auth: b(auth) } };
    assert.strictEqual((await call('/api/subscribe', { subscription: { endpoint: 'x', keys: {} } }))[0], 400);
    assert.strictEqual((await call('/api/subscribe', { subscription: sub }))[0], 200);
    assert.strictEqual((await call('/api/status'))[1].subscribers, 1);

    let [, r] = await call('/api/send', { title: 'New order · ৳490.00', body: 'Online Store · #1001 · 1 × Notion Template Pack' });
    assert.strictEqual(r.sent, 1); await wait(100);
    assert.deepStrictEqual(received[0].title, 'New order · ৳490.00'); assert.strictEqual(received[0].body, 'Online Store · #1001 · 1 × Notion Template Pack');

    await call('/api/job', { kind: 'stripe', currency: '$', store: 'Acme Inc', products: [{ name: 'Pro plan', price: 29 }], count: 2, intervalSec: 1, delaySec: 0 });
    await wait(3200);
    const sales = received.slice(1); assert.strictEqual(sales.length, 2, 'two job pushes, got ' + JSON.stringify(sales));
    sales.forEach(s => { assert(!s.error, s.error); assert.strictEqual(s.title, 'Payment · $29.00'); });
    assert.strictEqual((await call('/api/job', { kind: 'nope', currency: '$', products: [{ name: 'a', price: 1 }] }))[0], 400);

    mockStatus = 410; [, r] = await call('/api/send', { title: 'x' }); await wait(100);
    assert.strictEqual(r.removed, 1); assert.strictEqual((await call('/api/status'))[1].subscribers, 0);
    console.log('\nALL TESTS PASSED: VAPID signature, aes128gcm decryption, job scheduling, 410 cleanup, auth');
  } catch (e) { console.error('\nTEST FAILED:', e); process.exitCode = 1; }
  srv.kill(); mock.close();
})();
