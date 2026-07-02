#!/usr/bin/env node
/**
 * Builds the deployable index.html:
 *   content/site-src.html + content/panels/*.html + users.json
 *   -> envelope-encrypted single-file site (login shell + AES-GCM payloads).
 *
 * Nothing confidential appears in the output in plaintext. Run from repo root:
 *   node tools/build.mjs
 */
import { webcrypto as crypto } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ITERS = 210000;

const enc = new TextEncoder();
const b64 = (buf) => Buffer.from(buf).toString('base64');

const norm = (s) => s.trim().toLowerCase();

async function sha256Hex(str) {
  const h = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Buffer.from(h).toString('hex');
}

async function deriveKey(u, p, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(`${u}:${p}`), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, true, ['encrypt']
  );
}

async function encrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  return { iv: b64(iv), ct: b64(ct) };
}

const siteSrc = readFileSync(join(root, 'content/site-src.html'), 'utf8');
const usersCfg = JSON.parse(readFileSync(join(root, 'users.json'), 'utf8'));
const shell = readFileSync(join(root, 'tools/shell.html'), 'utf8');
const authJs = readFileSync(join(root, 'tools/auth.js'), 'utf8');

const readPanel = (file) => readFileSync(join(root, 'content/panels', file), 'utf8');

/* site key + common blob (the whole site source travels encrypted) */
const siteKeyRaw = crypto.getRandomValues(new Uint8Array(32));
const siteKey = await crypto.subtle.importKey('raw', siteKeyRaw, { name: 'AES-GCM' }, true, ['encrypt']);
const common = await encrypt(siteKey, JSON.stringify({ src: siteSrc }));

/* per-user payloads */
const users = {};
for (const user of usersCfg.users) {
  const u = norm(user.u), p = norm(user.p);
  let panels;
  if (user.admin) {
    panels = [
      { owner: u, label: `${user.name} · ${user.title}`, html: readPanel(user.panel) },
      ...usersCfg.users.filter((o) => o !== user).map((o) => ({
        owner: norm(o.u),
        label: `${o.name} · ${o.title}`,
        html: readPanel(o.panel),
      })),
    ];
  } else {
    panels = [{ owner: u, label: `${user.name} · ${user.title}`, html: readPanel(user.panel) }];
  }
  const personal = JSON.stringify({
    u, first: user.first, name: user.name, title: user.title,
    siteKey: b64(siteKeyRaw), panels,
  });
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(u, p, salt);
  const { iv, ct } = await encrypt(key, personal);
  users[await sha256Hex(u)] = { salt: b64(salt), iv, ct };
}

const payloads = JSON.stringify({ v: 1, kdf: { iters: ITERS }, users, common })
  .replace(/<\//g, '<\\/');

const css = siteSrc.slice(siteSrc.indexOf('<style>') + 7, siteSrc.indexOf('</style>'));
const title = siteSrc.slice(siteSrc.indexOf('<title>') + 7, siteSrc.indexOf('</title>'));

const out = shell
  .replace('%%TITLE%%', title)
  .replace('%%CSS%%', () => css)
  .replace('%%PAYLOADS%%', () => payloads)
  .replace('%%AUTHJS%%', () => authJs);

writeFileSync(join(root, 'index.html'), out);
console.log(`Built index.html (${(out.length / 1024).toFixed(0)} KB) — ${usersCfg.users.length} users, ${ITERS} PBKDF2 iterations.`);
