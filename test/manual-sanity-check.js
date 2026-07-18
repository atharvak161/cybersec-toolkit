/**
 * Manual sanity-check script (separate from the official node:test suite
 * in run-tests.js). Requires the same modules the browser UI uses and
 * exercises them end-to-end with realistic inputs, printing human-
 * readable before/after output for eyeballing. Covers the recipe
 * chaining feature (the standout feature) plus several other tools.
 *
 * Run with: node test/manual-sanity-check.js
 */

import { runRecipe, exportRecipe, importRecipe, buildShareableUrl } from '../js/lib/recipe.js';
import * as enc from '../js/lib/encoding.js';
import { analyzePassword } from '../js/lib/password.js';
import { calculateIpv4Subnet } from '../js/lib/cidr.js';
import { analyzeUrl } from '../js/lib/phishing.js';
import { decodeJwt } from '../js/lib/jwt.js';
import { qrEncode } from '../js/lib/qr-encode.js';
import { qrDecode } from '../js/lib/qr-decode.js';
import { identifyHash } from '../js/lib/hashing.js';

function section(title) {
  console.log('\n=== ' + title + ' ===');
}

// ---------- 1. Recipe chaining (standout feature) ----------
section('Recipe chaining: "Attack at dawn" -> Base64 -> Hex -> ROT13-of-hex-digits(no-op on hex) -> back down');
{
  const input = 'Attack at dawn';
  const steps = [{ opId: 'to-base64' }, { opId: 'to-hex' }];
  const { output, trace } = await runRecipe(steps, input);
  console.log('Input:   ', input);
  console.log('Step 1 (Base64):', trace[0].output);
  console.log('Step 2 (Hex):   ', trace[1].output);
  console.log('Final output:   ', output);

  const reversed = await runRecipe([{ opId: 'from-hex' }, { opId: 'from-base64' }], output);
  console.log('Reversed back:  ', reversed.output);
  console.log('Round trip OK:  ', reversed.output === input);

  const shareUrl = buildShareableUrl('https://atharvak161.github.io/cybersec-toolkit/', steps, input);
  console.log('Shareable URL:  ', shareUrl);
  const serialized = exportRecipe(steps);
  const restored = importRecipe(serialized);
  console.log('Export/import steps match:', JSON.stringify(restored) === JSON.stringify(steps));
}

// ---------- 2. Recipe chaining with a hashing (async) step ----------
section('Recipe chaining: trim -> uppercase -> SHA-256 (async step in the middle of a sync chain)');
{
  const { output, trace } = await runRecipe(
    [{ opId: 'trim' }, { opId: 'uppercase' }, { opId: 'sha256' }],
    '   hello world   '
  );
  console.log('Trace:', trace.map((t) => t.output));
  console.log('Final SHA-256:', output);
}

// ---------- 3. Password strength analyzer ----------
section('Password strength analyzer');
for (const pw of ['password', 'Tr0ub4dor&3', 'xK9#mQ2$vL7pR4!eZ8Wn6&', '111111']) {
  const result = analyzePassword(pw);
  console.log(`"${pw}" -> entropy=${result.entropyBits} bits, score=${result.score}/4 (${result.label}), crack time ~ ${result.crackTimeHuman}`);
  if (result.warnings.length) console.log('   warnings:', result.warnings.join(' | '));
}

// ---------- 4. CIDR / subnet calculator ----------
section('CIDR / subnet calculator');
for (const cidr of ['10.0.0.0/8', '192.168.1.130/26', '203.0.113.5/29']) {
  const r = calculateIpv4Subnet(cidr);
  console.log(`${cidr} -> network=${r.networkAddress}, broadcast=${r.broadcastAddress}, usable=${r.firstUsable}-${r.lastUsable} (${r.usableHosts} hosts)`);
}

// ---------- 5. Phishing URL heuristic checker ----------
section('Phishing URL heuristic checker');
for (const url of [
  'https://www.google.com/search?q=test',
  'http://192.168.0.1/login',
  'https://accounts-google-secure-login.verify-account.example-suspicious.com/signin',
  'https://xn--80ak6aa92e.com/'
]) {
  const r = analyzeUrl(url);
  console.log(`${url}\n   -> risk=${r.risk} (score ${r.score}): ${r.reasons.join(' | ')}`);
}

// ---------- 6. JWT decoder ----------
section('JWT decoder/inspector');
{
  const token =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
    '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const decoded = decodeJwt(token);
  console.log('Header: ', decoded.header);
  console.log('Payload:', decoded.payload);
  console.log('Warnings:', decoded.warnings.length ? decoded.warnings : 'none');

  const noneToken = enc.base64Encode(JSON.stringify({ alg: 'none', typ: 'JWT' }), true) + '.' + enc.base64Encode(JSON.stringify({ admin: true }), true) + '.';
  console.log('alg:none token warnings:', decodeJwt(noneToken).warnings);
}

// ---------- 7. Hash type identifier ----------
section('Hash type identifier');
for (const h of ['5d41402abc4b2a76b9719d911017c592', '2ef7bde608ce5404e97d5f042f95f89f1c232871', '$2b$12$KIXQ4Q3f9z8z8z8z8z8z8u']) {
  console.log(`${h} -> ${JSON.stringify(identifyHash(h))}`);
}

// ---------- 8. QR encode + decode round trip ----------
section('QR code generate + decode (hand-written encoder/decoder)');
{
  const text = 'https://atharvak161.github.io/';
  const { version, level, size, maskPattern, matrix } = qrEncode(text, 'M');
  console.log(`Encoded "${text}" as version ${version}, level ${level}, size ${size}x${size}, mask ${maskPattern}`);
  // ASCII-art preview of the matrix
  const preview = matrix.map((row) => row.map((v) => (v ? '##' : '  ')).join('')).join('\n');
  console.log(preview);
  const decoded = qrDecode(matrix);
  console.log('Decoded text:', decoded.text);
  console.log('Round trip OK:', decoded.text === text);
}

console.log('\nAll manual sanity checks completed.');
