#!/usr/bin/env node
/**
 * Recovers the plaintext editing sources from a built index.html.
 * Requires an admin user's credentials (only admin payloads contain all panels).
 *
 *   node tools/export.mjs <admin-username> <admin-password>
 *
 * Writes content/site-src.html and content/panels/<owner>.html.
 * users.json is NOT recoverable from the build (it holds the passwords);
 * recreate it from users.example.json if missing.
 */
import { webcrypto as crypto } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const [u0, p0] = process.argv.slice(2);
if (!u0 || !p0) {
  console.error('Usage: node tools/export.mjs <admin-username> <admin-password>');
  process.exit(1);
}
const u = u0.trim().toLowerCase(), p = p0.trim().toLowerCase();

const enc = new TextEncoder(), dec = new TextDecoder();
const fromB64 = (s) => Buffer.from(s, 'base64');

const html = readFileSync(join(root, 'index.html'), 'utf8');
const m = html.match(/<script type="application\/json" id="payloads">([\s\S]*?)<\/script>/);
if (!m) { console.error('No payloads block found in index.html'); process.exit(1); }
const payloads = JSON.parse(m[1].replace(/<\\\//g, '</'));

const uh = Buffer.from(await crypto.subtle.digest('SHA-256', enc.encode(u))).toString('hex');
const rec = payloads.users[uh];
if (!rec) { console.error('Unknown username.'); process.exit(1); }

const base = await crypto.subtle.importKey('raw', enc.encode(`${u}:${p}`), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt: fromB64(rec.salt), iterations: payloads.kdf.iters, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
);

const decrypt = async (k, iv, ct) =>
  dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(iv) }, k, fromB64(ct)));

let personal;
try {
  personal = JSON.parse(await decrypt(key, rec.iv, rec.ct));
} catch {
  console.error('Wrong password (decryption failed).');
  process.exit(1);
}
if (personal.panels.length < 2) {
  console.error('This user is not an admin — their payload only contains their own panel.');
  process.exit(1);
}

const siteKey = await crypto.subtle.importKey('raw', fromB64(personal.siteKey), { name: 'AES-GCM' }, false, ['decrypt']);
const common = JSON.parse(await decrypt(siteKey, payloads.common.iv, payloads.common.ct));

mkdirSync(join(root, 'content/panels'), { recursive: true });
writeFileSync(join(root, 'content/site-src.html'), common.src);
for (const panel of personal.panels) {
  writeFileSync(join(root, 'content/panels', `${panel.owner}.html`), panel.html);
}
console.log(`Recovered content/site-src.html and ${personal.panels.length} panels to content/panels/.`);
