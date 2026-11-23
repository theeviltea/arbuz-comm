#!/usr/bin/env node
// Шифрует страницу КП паролем (PBKDF2-SHA256 + AES-256-GCM) и собирает index.html с формой входа.
//
//   node tools/protect.mjs lock     index.src.html → index.html   (зашифровать)
//   node tools/protect.mjs unlock   index.html → index.src.html   (достать исходник для правок)
//
// Пароль берётся из переменной KP_PASSWORD или спрашивается в терминале. В репозиторий он не попадает.

import { readFile, writeFile } from 'node:fs/promises';
import { webcrypto as crypto } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(root, 'index.src.html');
const OUT = path.join(root, 'index.html');
const GATE = path.join(root, 'tools', 'gate.html');
const ITER = 300000;

const b64 = (buf) => Buffer.from(buf).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

async function password() {
  if (process.env.KP_PASSWORD) return process.env.KP_PASSWORD;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const p = await rl.question('Пароль: ');
  rl.close();
  return p;
}

async function key(pass, salt, iter) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function lock() {
  const pass = await password();
  if (!pass) throw new Error('Пустой пароль');
  const html = await readFile(SRC, 'utf8');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await key(pass, salt, ITER), new TextEncoder().encode(html));
  const payload = JSON.stringify({ v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), data: b64(data) });
  const gate = await readFile(GATE, 'utf8');
  await writeFile(OUT, gate.replace('/*PAYLOAD*/', () => payload));
  console.log(`Готово: index.html зашифрован (${(payload.length / 1024).toFixed(0)} КБ).`);
}

async function unlock() {
  const pass = await password();
  const page = await readFile(OUT, 'utf8');
  const m = page.match(/<script type="application\/json" id="payload">([\s\S]*?)<\/script>/);
  if (!m) throw new Error('В index.html нет зашифрованного блока');
  const P = JSON.parse(m[1]);
  let buf;
  try {
    buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(P.iv) }, await key(pass, unb64(P.salt), P.iter), unb64(P.data));
  } catch { throw new Error('Неверный пароль'); }
  await writeFile(SRC, new TextDecoder().decode(buf));
  console.log('Готово: исходник сохранён в index.src.html (он в .gitignore и не коммитится).');
}

const cmd = process.argv[2];
(cmd === 'lock' ? lock : cmd === 'unlock' ? unlock : () => { console.log('Использование: node tools/protect.mjs lock|unlock'); process.exit(1); })()
  .catch((e) => { console.error('Ошибка:', e.message); process.exit(1); });
