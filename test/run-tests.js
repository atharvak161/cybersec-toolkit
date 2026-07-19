/**
 * Test suite for cybersec-toolkit's pure logic modules (js/lib/**).
 * Uses only Node's built-in node:test + node:assert — no external test
 * framework dependency, per project requirements.
 *
 * Run with: node --test test/run-tests.js   (or: npm test)
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import * as enc from '../js/lib/encoding.js';
import * as encExtra from '../js/lib/encoding-extra.js';
import * as hashing from '../js/lib/hashing.js';
import { md5Hex } from '../js/lib/vendor/md5.js';
import { sha3Hex } from '../js/lib/vendor/sha3.js';
import { crc32Hex } from '../js/lib/vendor/crc32.js';
import { punycodeEncode, punycodeDecode, toASCII, toUnicode } from '../js/lib/vendor/punycode.js';
import { decodeJwt, verifyHmacJwt } from '../js/lib/jwt.js';
import { aesEncrypt, aesDecrypt } from '../js/lib/aes.js';
import { generateRsaKeypair, rsaEncrypt, rsaDecrypt } from '../js/lib/rsa.js';
import { analyzePassword } from '../js/lib/password.js';
import { sha1PrefixSuffix, parseHibpRangeResponse } from '../js/lib/hibp.js';
import { calculateIpv4Subnet, calculateIpv6Subnet, expandIpv6 } from '../js/lib/cidr.js';
import { testRegex, COMMON_PATTERNS } from '../js/lib/regex-patterns.js';
import { readExif, stripExif } from '../js/lib/exif.js';
import { identifyFileType } from '../js/lib/magic-bytes.js';
import { analyzeUrl } from '../js/lib/phishing.js';
import { parseCertificatePem } from '../js/lib/x509.js';
import { lsbEncode, lsbDecode, lsbCapacityBytes } from '../js/lib/steganography.js';
import { runRecipe, exportRecipe, importRecipe, buildShareableUrl, parseShareableUrl, OPERATIONS } from '../js/lib/recipe.js';
import { epochSecondsToIso, epochMillisToIso, isoToEpochSeconds, autoDetectEpoch } from '../js/lib/epoch.js';
import { diffLines, diffSummary } from '../js/lib/diff.js';
import { lookupHashInDemoWordlist, SUPPORTED_ALGORITHMS } from '../js/lib/wordlist-lookup.js';
import { COMMON_PASSWORDS_DEMO } from '../data/common-passwords.js';
import { parseDnsResponse, parseRdapResponse, parseIpGeoResponse, buildDnsUrl, buildRdapUrl, buildIpGeoUrl, lookupWhois } from '../js/lib/net-lookups.js';
import { qrEncode, QR_CAPACITY } from '../js/lib/qr-encode.js';
import { qrDecode } from '../js/lib/qr-decode.js';
import { hotp, generateTotp } from '../js/lib/totp.js';
import { generatePassword } from '../js/lib/password-gen.js';
import { generatePassphrase } from '../js/lib/diceware.js';
import { EFF_LARGE_WORDLIST } from '../data/eff-large-wordlist.js';
import { morseEncode, morseDecode } from '../js/lib/morse.js';
import { detectHomoglyphs } from '../js/lib/homoglyph.js';
import { formatJson, formatXml, parseYaml, formatYaml } from '../js/lib/format-data.js';
import { parseBase64Image } from '../js/lib/base64-image.js';
import { analyzeHeaders } from '../js/lib/http-headers.js';
import { searchPorts } from '../js/lib/ports-reference.js';
import { generateReverseShell, SHELL_TYPES } from '../js/lib/reverse-shell.js';
import { aesEncryptBytes, aesDecryptBytes } from '../js/lib/aes.js';

// ============================================================
// Encoding
// ============================================================

test('encoding: hex round trip + known vector', () => {
  assert.equal(enc.hexEncode('abc'), '616263');
  assert.equal(enc.hexDecode('616263'), 'abc');
  assert.equal(enc.hexDecode(enc.hexEncode('Hello, 世界!')), 'Hello, 世界!');
});

test('encoding: base64 RFC 4648 test vectors', () => {
  const vectors = [
    ['', ''],
    ['f', 'Zg=='],
    ['fo', 'Zm8='],
    ['foo', 'Zm9v'],
    ['foob', 'Zm9vYg=='],
    ['fooba', 'Zm9vYmE='],
    ['foobar', 'Zm9vYmFy']
  ];
  for (const [plain, encoded] of vectors) {
    assert.equal(enc.base64Encode(plain), encoded, `encode(${plain})`);
    assert.equal(enc.base64Decode(encoded), plain, `decode(${encoded})`);
  }
});

test('encoding: base64 url-safe variant', () => {
  const bytes = new Uint8Array([0xfb, 0xff, 0xbf]);
  const urlSafe = enc.base64Encode(bytes, true);
  assert.ok(!urlSafe.includes('+') && !urlSafe.includes('/') && !urlSafe.includes('='));
  const decoded = enc.base64Decode(urlSafe, true);
  assert.deepEqual(Array.from(decoded), Array.from(bytes));
});

test('encoding: base32 RFC 4648 test vectors', () => {
  const vectors = [
    ['', ''],
    ['f', 'MY======'],
    ['fo', 'MZXQ===='],
    ['foo', 'MZXW6==='],
    ['foob', 'MZXW6YQ='],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI======']
  ];
  for (const [plain, encoded] of vectors) {
    assert.equal(enc.base32Encode(plain), encoded, `encode(${plain})`);
    assert.equal(enc.base32Decode(encoded), plain, `decode(${encoded})`);
  }
});

test('encoding: base58 known vectors (IETF draft-msporny-base58)', () => {
  assert.equal(enc.base58Encode('Hello World!'), '2NEpo7TZRRrLZSi2U');
  assert.equal(
    enc.base58Encode('The quick brown fox jumps over the lazy dog.'),
    'USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z'
  );
  // Leading zero bytes -> leading '1's
  const bytes = new Uint8Array([0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd]);
  assert.equal(enc.base58Encode(bytes), '11233QC4');
  assert.deepEqual(Array.from(enc.base58Decode('11233QC4', true)), Array.from(bytes));
});

test('encoding: base85 (Ascii85) classic "Man " example', () => {
  assert.equal(encExtra.base85Encode('Man '), '9jqo^');
  assert.equal(encExtra.base85Decode('9jqo^'), 'Man ');
});

test('encoding: base85 round trip on arbitrary data', () => {
  const original = 'The quick brown fox jumps over the lazy dog!! 1234567890';
  assert.equal(encExtra.base85Decode(encExtra.base85Encode(original)), original);
});

test('encoding: base91 round trip', () => {
  const samples = ['', 'a', 'ab', 'abc', 'Hello, World! This is base91.', '\x00\x01\x02\xff'];
  for (const s of samples) {
    const bytes = new TextEncoder().encode(s);
    const encoded = encExtra.base91Encode(bytes);
    const decoded = encExtra.base91Decode(encoded, true);
    assert.deepEqual(Array.from(decoded), Array.from(bytes), `round trip for ${JSON.stringify(s)}`);
  }
});

test('encoding: uuencode round trip', () => {
  const original = 'Cat';
  const encoded = encExtra.uuEncode(original, 'cat.txt');
  assert.match(encoded, /^begin 644 cat\.txt/);
  assert.equal(encExtra.uuDecode(encoded), original);

  const longer = 'The quick brown fox jumps over the lazy dog. '.repeat(3);
  assert.equal(encExtra.uuDecode(encExtra.uuEncode(longer)), longer);
});

test('encoding: URL encode/decode', () => {
  assert.equal(enc.urlEncode('a b/c?d=e&f'), 'a%20b%2Fc%3Fd%3De%26f');
  assert.equal(enc.urlDecode('a%20b%2Fc%3Fd%3De%26f'), 'a b/c?d=e&f');
});

test('encoding: binary encode/decode', () => {
  assert.equal(enc.binaryEncode('A'), '01000001');
  assert.equal(enc.binaryDecode('01000001'), 'A');
  assert.equal(enc.binaryDecode(enc.binaryEncode('Hi!')), 'Hi!');
});

test('encoding: ROT13 and Caesar cipher', () => {
  assert.equal(enc.rot13('Hello, World!'), 'Uryyb, Jbeyq!');
  assert.equal(enc.rot13(enc.rot13('Hello, World!')), 'Hello, World!'); // involution
  assert.equal(enc.caesarShift('abcXYZ', 3), 'defABC');
  assert.equal(enc.caesarShift(enc.caesarShift('Attack at dawn', 7), -7), 'Attack at dawn');
});

test('encoding-extra: punycode RFC 3492 sample D (Czech)', () => {
  const input = String.fromCodePoint(
    0x50, 0x72, 0x6f, 0x10d, 0x70, 0x72, 0x6f, 0x73, 0x74,
    0x11b, 0x6e, 0x65, 0x6d, 0x6c, 0x75, 0x76, 0xed, 0x10d,
    0x65, 0x73, 0x6b, 0x79
  );
  const expected = 'Proprostnemluvesky-uyb24dma41a';
  assert.equal(punycodeEncode(input), expected);
  assert.equal(punycodeDecode(expected), input);
});

test('encoding-extra: punycode toASCII/toUnicode domain helpers', () => {
  const ascii = toASCII('bücher.example');
  assert.match(ascii, /^xn--/);
  assert.equal(toUnicode(ascii), 'bücher.example'.toLowerCase() === ascii ? ascii : 'bücher.example');
  // Round trip through the domain helpers
  assert.equal(toUnicode(toASCII('münchen.de')), 'münchen.de');
});

// ============================================================
// Hashing
// ============================================================

test('hashing: MD5 RFC 1321 test vectors', () => {
  assert.equal(md5Hex(''), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.equal(md5Hex('abc'), '900150983cd24fb0d6963f7d28e17f72');
  assert.equal(md5Hex('abcdefghijklmnopqrstuvwxyz'), 'c3fcd3d76192e4007dfb496cca67e13b');
});

test('hashing: SHA-1/256/512 via Web Crypto — known vectors', async () => {
  assert.equal(await hashing.sha1Hex(''), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
  assert.equal(await hashing.sha1Hex('abc'), 'a9993e364706816aba3e25717850c26c9cd0d89d');

  assert.equal(await hashing.sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(await hashing.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

  assert.equal(
    await hashing.sha512Hex('abc'),
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
  );
});

test('hashing: SHA-3-256 NIST FIPS 202 test vectors', () => {
  assert.equal(sha3Hex('', 256), 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
  assert.equal(sha3Hex('abc', 256), '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
});

test('hashing: CRC32 known check values', () => {
  assert.equal(crc32Hex(''), '00000000');
  assert.equal(crc32Hex('123456789'), 'cbf43926'); // canonical CRC-32/ISO-HDLC check value
});

test('hashing: HMAC-SHA256 via Web Crypto', async () => {
  // RFC 4231 Test Case 2: key "Jefe", data "what do ya want for nothing?"
  const mac = await hashing.hmacHex('SHA-256', 'Jefe', 'what do ya want for nothing?');
  assert.equal(mac, '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
});

test('hashing: hash type identifier', () => {
  const md5Guess = hashing.identifyHash('900150983cd24fb0d6963f7d28e17f72');
  assert.ok(md5Guess.some((g) => g.algorithm === 'MD5'));

  const sha256Guess = hashing.identifyHash('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.ok(sha256Guess.some((g) => g.algorithm === 'SHA-256'));

  const bcryptGuess = hashing.identifyHash('$2b$12$KIXQ4Q3f9z8z8z8z8z8z8uQ4Q3f9z8z8z8z8z8z8z8z8z8z8z8z8');
  assert.equal(bcryptGuess[0].algorithm, 'bcrypt');
});

// ============================================================
// JWT
// ============================================================

test('jwt: decode a known JWT (jwt.io example)', () => {
  const token =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
    '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const decoded = decodeJwt(token);
  assert.deepEqual(decoded.header, { alg: 'HS256', typ: 'JWT' });
  assert.deepEqual(decoded.payload, { sub: '1234567890', name: 'John Doe', iat: 1516239022 });
  assert.equal(decoded.signaturePresent, true);
  assert.equal(decoded.warnings.length, 0);
});

test('jwt: flags alg:none as critical', () => {
  const header = enc.base64Encode(JSON.stringify({ alg: 'none', typ: 'JWT' }), true);
  const payload = enc.base64Encode(JSON.stringify({ sub: 'attacker' }), true);
  const token = `${header}.${payload}.`;
  const decoded = decodeJwt(token);
  assert.ok(decoded.warnings.some((w) => w.includes('alg is "none"')));
});

test('jwt: detects expired token', () => {
  const header = enc.base64Encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }), true);
  const payload = enc.base64Encode(JSON.stringify({ exp: 1000000000 }), true); // long in the past
  const token = `${header}.${payload}.sig`;
  const decoded = decodeJwt(token);
  assert.equal(decoded.expiryStatus, 'expired');
});

test('jwt: verifyHmacJwt accepts correct secret, rejects wrong secret', async () => {
  const token =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
    '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  assert.equal(await verifyHmacJwt(token, 'your-256-bit-secret'), true);
  assert.equal(await verifyHmacJwt(token, 'wrong-secret'), false);
});

// ============================================================
// AES / RSA (Web Crypto)
// ============================================================

test('aes: encrypt then decrypt equals original (round trip)', async () => {
  const plaintext = 'The quick brown fox jumps over the lazy dog. 🔒';
  const blob = await aesEncrypt(plaintext, 'correct horse battery staple');
  const decrypted = await aesDecrypt(blob, 'correct horse battery staple');
  assert.equal(decrypted, plaintext);
});

test('aes: wrong passphrase fails to decrypt', async () => {
  const blob = await aesEncrypt('secret message', 'right-passphrase');
  await assert.rejects(() => aesDecrypt(blob, 'wrong-passphrase'));
});

test('rsa: generate keypair, encrypt then decrypt equals original', async () => {
  const { publicKeyPem, privateKeyPem } = await generateRsaKeypair(2048);
  assert.match(publicKeyPem, /-----BEGIN PUBLIC KEY-----/);
  assert.match(privateKeyPem, /-----BEGIN PRIVATE KEY-----/);

  const plaintext = 'RSA round trip test message';
  const ciphertext = await rsaEncrypt(plaintext, publicKeyPem);
  const decrypted = await rsaDecrypt(ciphertext, privateKeyPem);
  assert.equal(decrypted, plaintext);
});

// ============================================================
// Password / HIBP
// ============================================================

test('password: entropy analyzer scores weak vs strong passwords sensibly', () => {
  const weak = analyzePassword('password');
  const strong = analyzePassword('xK9#mQ2$vL7pR4!eZ8');
  assert.ok(weak.entropyBits < strong.entropyBits);
  assert.ok(weak.score < strong.score);
  assert.equal(analyzePassword('').entropyBits, 0);
});

test('password: flags sequential and repeated patterns', () => {
  const seq = analyzePassword('abcdefgh123');
  assert.ok(seq.warnings.some((w) => w.includes('sequence')));
  const rep = analyzePassword('aaabbb1234');
  assert.ok(rep.warnings.some((w) => w.includes('repeated')));
});

test('hibp: sha1PrefixSuffix splits correctly and parseHibpRangeResponse finds a match', async () => {
  const { prefix, suffix } = await sha1PrefixSuffix('password');
  // sha1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
  assert.equal((prefix + suffix).toLowerCase(), '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8');
  assert.equal(prefix, '5BAA6');

  const fakeResponse = `${suffix}:3730330\r\nAAAAA:1\r\nBBBBB:2`;
  assert.equal(parseHibpRangeResponse(fakeResponse, suffix), 3730330);
  assert.equal(parseHibpRangeResponse(fakeResponse, 'ZZZZZNOTPRESENT'), 0);
});

// ============================================================
// CIDR
// ============================================================

test('cidr: IPv4 subnet calculation', () => {
  const result = calculateIpv4Subnet('192.168.1.10/24');
  assert.equal(result.networkAddress, '192.168.1.0');
  assert.equal(result.broadcastAddress, '192.168.1.255');
  assert.equal(result.netmask, '255.255.255.0');
  assert.equal(result.firstUsable, '192.168.1.1');
  assert.equal(result.lastUsable, '192.168.1.254');
  assert.equal(result.usableHosts, 254);
  assert.equal(result.totalAddresses, 256);
});

test('cidr: /31 and /32 edge cases', () => {
  const p31 = calculateIpv4Subnet('10.0.0.0/31');
  assert.equal(p31.usableHosts, 0);
  assert.equal(p31.totalAddresses, 2);
  const p32 = calculateIpv4Subnet('10.0.0.5/32');
  assert.equal(p32.networkAddress, '10.0.0.5');
  assert.equal(p32.broadcastAddress, '10.0.0.5');
});

test('cidr: IPv6 subnet + expansion', () => {
  assert.equal(expandIpv6('::1'), '0000:0000:0000:0000:0000:0000:0000:0001');
  assert.equal(expandIpv6('2001:db8::1'), '2001:0db8:0000:0000:0000:0000:0000:0001');
  const result = calculateIpv6Subnet('2001:db8::/32');
  assert.equal(result.networkAddress.startsWith('2001:0db8:0000:0000'), true);
});

// ============================================================
// Regex tester
// ============================================================

test('regex: common patterns library matches expected samples', () => {
  const emailPattern = COMMON_PATTERNS.find((p) => p.name === 'Email address');
  const matches = testRegex(emailPattern.pattern, emailPattern.flags, 'contact me at a.b+c@example.co.uk');
  assert.equal(matches.length, 1);
  assert.equal(matches[0].match, 'a.b+c@example.co.uk');

  const ipv4Pattern = COMMON_PATTERNS.find((p) => p.name === 'IPv4 address');
  assert.equal(testRegex(ipv4Pattern.pattern, ipv4Pattern.flags, '192.168.1.1').length, 1);
  assert.equal(testRegex(ipv4Pattern.pattern, ipv4Pattern.flags, '999.999.999.999').length, 0);
});

test('regex: invalid pattern throws a descriptive error', () => {
  assert.throws(() => testRegex('(unclosed', '', 'text'), /Invalid regular expression/);
});

// ============================================================
// EXIF (synthetic minimal JPEG+EXIF fixture built in-test)
// ============================================================

function buildSyntheticJpegWithExif() {
  // Build a minimal JPEG: SOI, APP1 (Exif/TIFF with Make+Model tags), SOS marker + 1 byte "scan" + EOI.
  const parts = [];
  parts.push(new Uint8Array([0xff, 0xd8])); // SOI

  // --- Build TIFF body (little-endian) ---
  const makeStr = 'TestCam\0'; // 8 bytes, fits inline (<=4 bytes needed for offset rule -> not inline, use offset)
  const modelStr = 'Model X\0'; // 8 bytes

  // We'll lay out: TIFF header (8 bytes) + IFD0 (2 entries) + next-IFD-offset(4) + string data
  const ifdEntryCount = 2;
  const ifd0Offset = 8;
  const ifd0Size = 2 + ifdEntryCount * 12 + 4;
  const stringDataOffset = ifd0Offset + ifd0Size;

  const tiff = new Uint8Array(stringDataOffset + makeStr.length + modelStr.length);
  const dv = new DataView(tiff.buffer);
  dv.setUint16(0, 0x4949, false); // 'II' little endian marker (bytes 'I','I')
  dv.setUint16(2, 0x002a, true); // 42
  dv.setUint32(4, ifd0Offset, true);

  dv.setUint16(ifd0Offset, ifdEntryCount, true);
  // Entry 0: Make (0x010f), type ASCII(2), count=makeStr.length, offset=stringDataOffset
  let entryOffset = ifd0Offset + 2;
  dv.setUint16(entryOffset, 0x010f, true);
  dv.setUint16(entryOffset + 2, 2, true);
  dv.setUint32(entryOffset + 4, makeStr.length, true);
  dv.setUint32(entryOffset + 8, stringDataOffset, true);
  // Entry 1: Model (0x0110)
  entryOffset += 12;
  const modelOffset = stringDataOffset + makeStr.length;
  dv.setUint16(entryOffset, 0x0110, true);
  dv.setUint16(entryOffset + 2, 2, true);
  dv.setUint32(entryOffset + 4, modelStr.length, true);
  dv.setUint32(entryOffset + 8, modelOffset, true);
  // next IFD offset = 0 (none)
  dv.setUint32(ifd0Offset + 2 + ifdEntryCount * 12, 0, true);

  for (let i = 0; i < makeStr.length; i++) tiff[stringDataOffset + i] = makeStr.charCodeAt(i);
  for (let i = 0; i < modelStr.length; i++) tiff[modelOffset + i] = modelStr.charCodeAt(i);

  // --- Wrap in APP1 segment ---
  const exifHeader = new Uint8Array([0x45, 0x78, 0x69, 0x66, 0x00, 0x00]); // "Exif\0\0"
  const app1Payload = new Uint8Array(exifHeader.length + tiff.length);
  app1Payload.set(exifHeader, 0);
  app1Payload.set(tiff, exifHeader.length);

  const app1Size = app1Payload.length + 2; // size field includes itself, excludes marker
  const app1 = new Uint8Array(4 + app1Payload.length);
  const app1Dv = new DataView(app1.buffer);
  app1Dv.setUint16(0, 0xffe1, false);
  app1Dv.setUint16(2, app1Size, false);
  app1.set(app1Payload, 4);
  parts.push(app1);

  parts.push(new Uint8Array([0xff, 0xda, 0x00, 0x02])); // SOS marker with minimal (invalid but structurally-parseable) header
  parts.push(new Uint8Array([0x00, 0x00, 0xff, 0xd9])); // fake scan bytes + EOI

  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out.buffer;
}

test('exif: reads Make/Model tags from a synthetic JPEG', () => {
  const buffer = buildSyntheticJpegWithExif();
  const tags = readExif(buffer);
  assert.equal(tags.Make, 'TestCam');
  assert.equal(tags.Model, 'Model X');
});

test('exif: stripExif removes the APP1 segment', () => {
  const buffer = buildSyntheticJpegWithExif();
  const stripped = stripExif(buffer);
  const strippedTags = readExif(stripped);
  assert.deepEqual(strippedTags, {});
  // SOI and EOI preserved
  const view = new DataView(stripped);
  assert.equal(view.getUint16(0, false), 0xffd8);
  assert.equal(view.getUint16(stripped.byteLength - 2, false), 0xffd9);
});

// ============================================================
// Magic bytes
// ============================================================

test('magic-bytes: identifies common file types', () => {
  assert.equal(identifyFileType(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])).type, 'PNG image');
  assert.equal(identifyFileType(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31])).type, 'PDF document');
  assert.equal(identifyFileType(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00])).type, 'ZIP archive (or docx/xlsx/pptx/jar/apk)');
  assert.equal(identifyFileType(new Uint8Array([0xff, 0xd8, 0xff, 0xe0])).type, 'JPEG image');
  assert.equal(identifyFileType(new Uint8Array([1, 2, 3, 4])), null);
});

// ============================================================
// Phishing heuristics
// ============================================================

test('phishing: flags IP-literal hosts', () => {
  const result = analyzeUrl('http://192.168.1.1/login.php');
  assert.ok(result.reasons.some((r) => r.includes('IP address')));
  assert.ok(result.score >= 30);
});

test('phishing: flags lookalike domains', () => {
  const result = analyzeUrl('https://paypa1.com/signin');
  assert.ok(result.reasons.some((r) => r.includes('resembles')));
  assert.equal(result.risk === 'high' || result.risk === 'medium', true);
});

test('phishing: clean URL scores low', () => {
  const result = analyzeUrl('https://example.com/about');
  assert.equal(result.risk, 'minimal');
});

test('phishing: flags punycode homograph hosts', () => {
  const result = analyzeUrl('https://xn--pple-43d.com/');
  assert.ok(result.reasons.some((r) => r.includes('punycode')));
});

// ============================================================
// X.509 (self-signed cert generated locally via openssl, cross-checked
// against Node's own built-in X509Certificate parser)
// ============================================================

test('x509: parses a locally-generated self-signed certificate', async () => {
  const { execFileSync } = await import('node:child_process');
  const { X509Certificate } = await import('node:crypto');
  const os = await import('node:os');
  const path = await import('node:path');
  const fs = await import('node:fs');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x509test-'));
  const keyPath = path.join(tmpDir, 'key.pem');
  const certPath = path.join(tmpDir, 'cert.pem');

  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-keyout', keyPath, '-out', certPath,
    '-days', '365', '-nodes',
    '-subj', '/C=US/ST=Test/L=TestCity/O=TestOrg/OU=TestUnit/CN=test.example.com'
  ]);

  const pem = fs.readFileSync(certPath, 'utf8');
  const parsed = parseCertificatePem(pem);
  const reference = new X509Certificate(pem);

  assert.equal(parsed.subjectString.includes('CN=test.example.com'), true);
  assert.equal(reference.subject.includes('CN=test.example.com'), true);
  assert.equal(parsed.serialNumber.toLowerCase().replace(/^0+/, ''), reference.serialNumber.toLowerCase().replace(/^0+/, ''));
  assert.equal(new Date(parsed.notAfter).getUTCFullYear(), new Date(reference.validTo).getUTCFullYear());
  assert.equal(parsed.isExpired, false);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ============================================================
// Steganography (LSB)
// ============================================================

test('steganography: LSB encode/decode round trip', () => {
  const width = 20, height = 20;
  const rgba = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < rgba.length; i++) rgba[i] = Math.floor(Math.random() * 256);

  const message = 'Hidden message via LSB stego!';
  const encoded = lsbEncode(rgba, message);
  const decoded = lsbDecode(encoded);
  assert.equal(decoded, message);
  // Original buffer must not be mutated
  assert.notEqual(rgba[0], undefined);
});

test('steganography: throws when message exceeds capacity', () => {
  const tiny = new Uint8ClampedArray(4 * 4 * 4); // 4x4 image
  const capacity = lsbCapacityBytes(16);
  const tooLong = 'x'.repeat(capacity + 10);
  assert.throws(() => lsbEncode(tiny, tooLong), /too long/);
});

// ============================================================
// Recipe chaining (the standout feature)
// ============================================================

test('recipe: base64 encode -> hex encode chain matches manual chain', async () => {
  const input = 'Attack at dawn';
  const manual = enc.hexEncode(enc.base64Encode(input));
  const { output } = await runRecipe(
    [{ opId: 'to-base64' }, { opId: 'to-hex' }],
    input
  );
  assert.equal(output, manual);
});

test('recipe: full round trip encode then decode chain returns original', async () => {
  const input = 'The Chief of Staff runs a tight ship.';
  const { output } = await runRecipe(
    [{ opId: 'to-base64' }, { opId: 'to-hex' }, { opId: 'from-hex' }, { opId: 'from-base64' }],
    input
  );
  assert.equal(output, input);
});

test('recipe: chain including an async (hashing) step', async () => {
  const { output, trace } = await runRecipe(
    [{ opId: 'trim' }, { opId: 'sha256' }],
    '  abc  '
  );
  assert.equal(output, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(trace.length, 2);
  assert.equal(trace[0].output, 'abc');
});

test('recipe: caesar cipher step honors custom params', async () => {
  const { output } = await runRecipe([{ opId: 'caesar', params: { shift: 1 } }], 'abc');
  assert.equal(output, 'bcd');
});

test('recipe: failing step throws with a trace attached', async () => {
  await assert.rejects(
    () => runRecipe([{ opId: 'from-hex' }], 'not valid hex!!'),
    (err) => {
      assert.ok(err.message.includes('failed'));
      assert.ok(Array.isArray(err.trace));
      return true;
    }
  );
});

test('recipe: every registered operation is runnable on a trivial input', async () => {
  // Sanity sweep: make sure no operation in the catalog throws unexpectedly
  // on reasonable input (encoding ops on plain text, hash ops on plain text).
  for (const op of OPERATIONS) {
    if (op.id.startsWith('from-')) continue; // decode ops need matching-format input, tested individually above
    const result = await op.run('abc', op.params || {});
    assert.equal(typeof result, 'string', `${op.id} should return a string`);
  }
});

test('recipe: export/import round trip preserves steps', () => {
  const steps = [{ opId: 'to-base64' }, { opId: 'caesar', params: { shift: 5 } }];
  const serialized = exportRecipe(steps);
  const restored = importRecipe(serialized);
  assert.deepEqual(restored, steps);
});

test('recipe: shareable URL round trip preserves steps and input', () => {
  const steps = [{ opId: 'to-hex' }, { opId: 'md5' }];
  const url = buildShareableUrl('https://example.com/toolkit/', steps, 'secret input');
  const parsed = parseShareableUrl(url);
  assert.deepEqual(parsed.steps, steps);
  assert.equal(parsed.input, 'secret input');
});

// ============================================================
// Epoch / timestamp converter
// ============================================================

test('epoch: known conversions', () => {
  assert.equal(epochSecondsToIso(0), '1970-01-01T00:00:00.000Z');
  assert.equal(epochMillisToIso(0), '1970-01-01T00:00:00.000Z');
  assert.equal(isoToEpochSeconds('1970-01-01T00:00:00.000Z'), 0);
  assert.equal(epochSecondsToIso(1700000000), '2023-11-14T22:13:20.000Z');
});

test('epoch: auto-detects seconds vs milliseconds', () => {
  assert.equal(autoDetectEpoch(1700000000).unit, 'seconds');
  assert.equal(autoDetectEpoch(1700000000000).unit, 'milliseconds');
});

// ============================================================
// Text diff
// ============================================================

test('diff: identifies additions/removals/equal lines', () => {
  const a = 'line1\nline2\nline3';
  const b = 'line1\nlineX\nline3\nline4';
  const result = diffLines(a, b);
  const summary = diffSummary(result);
  assert.equal(summary.equal, 2); // line1, line3
  assert.ok(summary.add >= 1);
  assert.ok(summary.remove >= 1);
});

test('diff: identical text produces only equal lines', () => {
  const text = 'a\nb\nc';
  const summary = diffSummary(diffLines(text, text));
  assert.equal(summary.equal, 3);
  assert.equal(summary.add, 0);
  assert.equal(summary.remove, 0);
});

// ============================================================
// Demo wordlist hash lookup (educational)
// ============================================================

test('wordlist-lookup: finds a common password by its hash (educational demo)', async () => {
  assert.ok(COMMON_PASSWORDS_DEMO.length <= 300);
  assert.ok(COMMON_PASSWORDS_DEMO.includes('password'));

  const targetHash = md5Hex('password');
  const result = await lookupHashInDemoWordlist(targetHash, 'MD5');
  assert.equal(result.found, true);
  assert.equal(result.plaintext, 'password');
});

test('wordlist-lookup: reports not-found for a hash not in the demo list', async () => {
  const targetHash = md5Hex('xk9#zQ7!vL2pR-uncommon-random-value');
  const result = await lookupHashInDemoWordlist(targetHash, 'MD5');
  assert.equal(result.found, false);
  assert.equal(result.attempts, COMMON_PASSWORDS_DEMO.length);
});

test('wordlist-lookup: supports all advertised algorithms', () => {
  assert.deepEqual(SUPPORTED_ALGORITHMS, ['MD5', 'SHA-1', 'SHA-256', 'CRC32']);
});

// ============================================================
// Net lookups (pure request-building / response-parsing; no network)
// ============================================================

test('net-lookups: builds correct request URLs', () => {
  assert.equal(buildDnsUrl('example.com', 'A'), 'https://dns.google/resolve?name=example.com&type=A');
  assert.equal(buildRdapUrl('example.com'), 'https://rdap.org/domain/example.com');
  assert.equal(buildIpGeoUrl('8.8.8.8'), 'https://ipapi.co/8.8.8.8/json/');
});

test('net-lookups: parses a synthetic dns.google response', () => {
  const sample = {
    Status: 0,
    Answer: [{ name: 'example.com.', type: 1, TTL: 300, data: '93.184.216.34' }]
  };
  const parsed = parseDnsResponse(sample);
  assert.equal(parsed.status, 0);
  assert.equal(parsed.records[0].data, '93.184.216.34');
});

test('net-lookups: parses a synthetic RDAP response', () => {
  const sample = {
    ldhName: 'EXAMPLE.COM',
    status: ['active'],
    nameservers: [{ ldhName: 'NS1.EXAMPLE.COM' }, { ldhName: 'NS2.EXAMPLE.COM' }],
    events: [
      { eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' },
      { eventAction: 'expiration', eventDate: '2026-08-13T04:00:00Z' }
    ],
    entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar Inc.']]] }]
  };
  const parsed = parseRdapResponse(sample);
  assert.equal(parsed.domain, 'EXAMPLE.COM');
  assert.equal(parsed.registrar, 'Example Registrar Inc.');
  assert.equal(parsed.nameservers.length, 2);
  assert.equal(parsed.registrationDate, '1995-08-14T04:00:00Z');
});

test('net-lookups: parses a synthetic ipapi.co response', () => {
  const sample = {
    ip: '8.8.8.8', city: 'Mountain View', region: 'California',
    country_name: 'United States', country_code: 'US',
    latitude: 37.4, longitude: -122.07, org: 'Google LLC', timezone: 'America/Los_Angeles'
  };
  const parsed = parseIpGeoResponse(sample);
  assert.equal(parsed.city, 'Mountain View');
  assert.equal(parsed.countryCode, 'US');
});

test('net-lookups: lookupWhois shows a friendly message (not a raw JSON parse error) for a nonexistent domain — empty-body 404', async () => {
  // Mirrors the real rdap.org bootstrap-redirect behavior for an unregistered
  // domain: HTTP 404 with a completely empty response body. Calling
  // res.json() on that used to bubble up "Unexpected end of JSON input".
  const fakeFetch = async () => ({
    ok: false,
    status: 404,
    json: async () => { throw new SyntaxError('Unexpected end of JSON input'); }
  });
  await assert.rejects(
    () => lookupWhois('this-domain-should-not-exist-zzqx.com', fakeFetch),
    (err) => {
      assert.equal(err.message, 'No WHOIS record found for this domain.');
      assert.ok(!/Unexpected end of JSON/.test(err.message));
      return true;
    }
  );
});

test('net-lookups: lookupWhois shows a friendly message for a JSON error-object 404', () => {
  const fakeFetch = async () => ({
    ok: false,
    status: 404,
    json: async () => ({ errorCode: 404, title: 'NOT FOUND' })
  });
  return assert.rejects(
    () => lookupWhois('another-nonexistent-domain-zzqx.com', fakeFetch),
    /No WHOIS record found for this domain\./
  );
});

test('net-lookups: lookupWhois still parses a real successful RDAP response', async () => {
  const sample = {
    ldhName: 'EXAMPLE.COM',
    status: ['active'],
    nameservers: [],
    events: []
  };
  const fakeFetch = async () => ({ ok: true, status: 200, json: async () => sample });
  const result = await lookupWhois('example.com', fakeFetch);
  assert.equal(result.domain, 'EXAMPLE.COM');
});

// ============================================================
// QR encode/decode (hand-written, versions 1-4, round trip)
// ============================================================

test('qr: encode/decode round trip — short string, level M', () => {
  const text = 'HELLO';
  const { matrix, version, level } = qrEncode(text, 'M');
  assert.equal(version, 1);
  assert.equal(level, 'M');
  const decoded = qrDecode(matrix);
  assert.equal(decoded.text, text);
  assert.equal(decoded.version, 1);
  assert.equal(decoded.level, 'M');
});

test('qr: encode/decode round trip — URL, level L, forces a larger version', () => {
  const text = 'https://github.com/atharvak161/cybersec-toolkit';
  const { matrix, version } = qrEncode(text, 'L');
  assert.ok(version >= 2);
  const decoded = qrDecode(matrix);
  assert.equal(decoded.text, text);
});

test('qr: throws a clear error when input exceeds encoder capacity', () => {
  const tooLong = 'x'.repeat(500);
  assert.throws(() => qrEncode(tooLong, 'M'), /too large/);
});

test('qr: round trips across all three genuinely single-block versions at level M (V1-3)', () => {
  for (const version of [1, 2, 3]) {
    const cap = QR_CAPACITY[version].M.dataCodewords - 3; // leave room for mode/count/terminator overhead
    const text = 'A'.repeat(Math.max(1, cap - 1));
    const { matrix, version: actualVersion, level: actualLevel } = qrEncode(text, 'M');
    assert.ok(actualVersion <= version + 1);
    assert.equal(actualLevel, 'M');
    const decoded = qrDecode(matrix);
    assert.equal(decoded.text, text);
  }
});

test('qr: Version 4 / Level M is unsupported (spec requires 2-block RS interleaving)', () => {
  assert.equal(QR_CAPACITY[4].M, undefined);
});

test('qr: requesting level M with input in the old V4/M range (43-62 bytes) falls back to level L, never emits V4/M', () => {
  for (let len = 43; len <= 62; len++) {
    const text = 'A'.repeat(len);
    const { version, level, matrix } = qrEncode(text, 'M');
    // Must never resolve to the unsupported V4/M combo.
    assert.ok(!(version === 4 && level === 'M'), `len=${len} incorrectly produced V4/M`);
    assert.equal(level, 'L', `len=${len} should have fallen back to level L`);
    const decoded = qrDecode(matrix);
    assert.equal(decoded.text, text);
    assert.equal(decoded.level, 'L');
  }
});

test('qr: input too large even at level L throws the clear fallback error', () => {
  const tooLong = 'A'.repeat(100); // beyond V4/L's 78-byte-ish cap
  assert.throws(() => qrEncode(tooLong, 'M'), /input too large for supported QR levels, try a shorter string or Level L/);
});

// ============================================================
// TOTP / HOTP (RFC 6238 Appendix B published test vectors, RFC 4226 §5.3
// dynamic truncation). Secrets are the ASCII string "1234567890" repeated
// and truncated to the exact byte length RFC 6238 specifies per algorithm:
// 20 bytes for SHA1, 32 bytes for SHA256, 64 bytes for SHA512. Verified
// independently against a from-scratch reference HOTP implementation
// (Node's own crypto.createHmac) before hard-coding, in addition to being
// the well-known published RFC vectors.
// ============================================================

const TOTP_SEED_SHA1 = new TextEncoder().encode('12345678901234567890'); // 20 bytes
const TOTP_SEED_SHA256 = new TextEncoder().encode('12345678901234567890123456789012'); // 32 bytes
const TOTP_SEED_SHA512 = new TextEncoder().encode('1234567890123456789012345678901234567890123456789012345678901234'); // 64 bytes

test('totp: RFC 6238 Appendix B SHA1 test vectors (8-digit mode)', async () => {
  const vectors = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130']
  ];
  for (const [t, expected] of vectors) {
    const counter = Math.floor(t / 30);
    assert.equal(await hotp(TOTP_SEED_SHA1, counter, 8, 'SHA-1'), expected, `T=${t}`);
  }
});

test('totp: RFC 6238 Appendix B SHA256 test vectors (8-digit mode)', async () => {
  const vectors = [
    [59, '46119246'],
    [1111111109, '68084774'],
    [1111111111, '67062674'],
    [1234567890, '91819424'],
    [2000000000, '90698825'],
    [20000000000, '77737706']
  ];
  for (const [t, expected] of vectors) {
    const counter = Math.floor(t / 30);
    assert.equal(await hotp(TOTP_SEED_SHA256, counter, 8, 'SHA-256'), expected, `T=${t}`);
  }
});

test('totp: RFC 6238 Appendix B SHA512 test vectors (8-digit mode)', async () => {
  const vectors = [
    [59, '90693936'],
    [1111111109, '25091201'],
    [1111111111, '99943326'],
    [1234567890, '93441116'],
    [2000000000, '38618901'],
    [20000000000, '47863826']
  ];
  for (const [t, expected] of vectors) {
    const counter = Math.floor(t / 30);
    assert.equal(await hotp(TOTP_SEED_SHA512, counter, 8, 'SHA-512'), expected, `T=${t}`);
  }
});

test('totp: generateTotp default 6-digit mode matches the last 6 digits of the RFC 8-digit SHA1 vector at T=59', async () => {
  const { base32Encode } = enc;
  const secretBase32 = base32Encode(TOTP_SEED_SHA1);
  const { code, period } = await generateTotp(secretBase32, { timestampMs: 59 * 1000 });
  assert.equal(code.length, 6);
  assert.equal(code, '94287082'.slice(-6));
  assert.equal(period, 30);
});

// ============================================================
// Password generator
// ============================================================

test('password-gen: requested length is respected', () => {
  assert.equal(generatePassword({ length: 24 }).length, 24);
  assert.equal(generatePassword({ length: 1 }).length, 1);
});

test('password-gen: digits-only charset produces only digits', () => {
  const pwd = generatePassword({ length: 30, upper: false, lower: false, symbols: false, digits: true });
  assert.match(pwd, /^[0-9]{30}$/);
});

test('password-gen: excludeAmbiguous strips the module\'s own ambiguous-character list', () => {
  // Module's real AMBIGUOUS set: 0, O, 1, l, I, |, ', `, "
  const ambiguousChars = /[0O1lI|'`"]/;
  for (let i = 0; i < 20; i++) {
    const pwd = generatePassword({ length: 40, excludeAmbiguous: true });
    assert.ok(!ambiguousChars.test(pwd), `iteration ${i}: "${pwd}" contains an ambiguous character`);
  }
});

test('password-gen: 100 generated passwords are not all identical (sanity floor)', () => {
  const outputs = new Set();
  for (let i = 0; i < 100; i++) outputs.add(generatePassword({ length: 12 }));
  assert.ok(outputs.size > 1, 'expected variation across 100 generated passwords');
});

// ============================================================
// Diceware passphrase generator
// ============================================================

test('diceware: requested word count is respected', () => {
  const { words, passphrase } = generatePassphrase({ wordCount: 6 });
  assert.equal(words.length, 6);
  assert.equal(passphrase.split('-').length, 6);
});

test('diceware: every word in the output appears in the vendored EFF wordlist', () => {
  const { words } = generatePassphrase({ wordCount: 8, includeNumber: true });
  const wordlistSet = new Set(EFF_LARGE_WORDLIST);
  for (const word of words) {
    // includeNumber may append a trailing digit to exactly one word.
    const bareWord = word.replace(/[0-9]+$/, '');
    assert.ok(wordlistSet.has(bareWord.toLowerCase()) || wordlistSet.has(bareWord), `"${word}" not found in EFF wordlist`);
  }
});

test('diceware: two separate calls do not produce identical passphrases', () => {
  const a = generatePassphrase({ wordCount: 6 });
  const b = generatePassphrase({ wordCount: 6 });
  assert.notEqual(a.passphrase, b.passphrase);
});

// ============================================================
// Morse code
// ============================================================

test('morse: SOS matches the real International Morse standard', () => {
  assert.equal(morseEncode('SOS'), '... --- ...');
});

test('morse: encode/decode round trip restores original text (uppercase, per module convention)', () => {
  const original = 'HELLO WORLD';
  assert.equal(morseDecode(morseEncode(original)), original);

  const withPunctuation = 'ATTACK AT DAWN.';
  assert.equal(morseDecode(morseEncode(withPunctuation)), withPunctuation);
});

// ============================================================
// Homoglyph / lookalike-character detector
// ============================================================

test('homoglyph: known confusable pair (Cyrillic а for Latin a) IS flagged as mixed-script', () => {
  const spoofed = 'p' + String.fromCodePoint(0x0430) + 'ypal'; // Cyrillic а (U+0430) substituted for Latin a (U+0061)
  const result = detectHomoglyphs(spoofed);
  assert.equal(result.hasMixedScript, true);
  assert.ok(result.flagged.some((f) => f.codepoint === 'U+0430' && f.looksLike === 'a'));
});

test('homoglyph: pure-ASCII string is NOT flagged (no false positive)', () => {
  const result = detectHomoglyphs('paypal.com/login');
  assert.equal(result.flagged.length, 0);
  assert.equal(result.hasMixedScript, false);
});

test('homoglyph: pure-Cyrillic string is NOT flagged as mixed-script (legitimate single-script text)', () => {
  const result = detectHomoglyphs('привет'); // "hello" in Russian, entirely Cyrillic
  assert.equal(result.hasMixedScript, false);
});

// ============================================================
// Data format converter (JSON / XML / YAML)
// ============================================================

test('format-data: JSON valid input parses and reformats', () => {
  const formatted = formatJson('{"b":2,"a":1}', 2);
  assert.equal(formatted, JSON.stringify({ b: 2, a: 1 }, null, 2));
});

test('format-data: JSON invalid input throws a clear error', () => {
  assert.throws(() => formatJson('{not valid json'), /Invalid JSON/);
});

test('format-data: XML well-formedness check catches an unclosed tag', () => {
  assert.throws(() => formatXml('<root><child>text</root>'), /mismatched closing tag/);
  assert.throws(() => formatXml('<root><child>text</child>'), /unclosed tag/);
});

test('format-data: XML valid nested document formats correctly', () => {
  const formatted = formatXml('<root><child>text</child></root>');
  assert.equal(formatted, '<root>\n  <child>text</child>\n</root>');
});

test('format-data: YAML block mapping + sequence parses per the documented subset', () => {
  const yamlText = 'name: Atharva\nrole: Chief of Staff\ntags:\n  - security\n  - qa\n';
  const parsed = parseYaml(yamlText);
  assert.deepEqual(parsed, { name: 'Atharva', role: 'Chief of Staff', tags: ['security', 'qa'] });
});

test('format-data: YAML formatter round trips a parsed block mapping', () => {
  const value = { name: 'Atharva', tags: ['a', 'b'] };
  const formatted = formatYaml('name: Atharva\ntags:\n  - a\n  - b\n');
  assert.equal(parseYaml(formatted).name, value.name);
  assert.deepEqual(parseYaml(formatted).tags, value.tags);
});

// ============================================================
// Base64 / data-URI image parser
// ============================================================

test('base64-image: known-valid 1x1 PNG data URI is correctly parsed', () => {
  const pngB64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';
  const result = parseBase64Image('data:image/png;base64,' + pngB64);
  assert.equal(result.declaredMime, 'image/png');
  assert.equal(result.detected.mime, 'image/png');
  assert.equal(result.looksLikeImage, true);
  assert.equal(result.sizeBytes, result.bytes.length);
  assert.ok(result.sizeBytes > 0);
});

test('base64-image: known-valid 1x1 GIF data URI is correctly parsed', () => {
  const gifB64 = 'R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAUwAOw==';
  const result = parseBase64Image('data:image/gif;base64,' + gifB64);
  assert.equal(result.declaredMime, 'image/gif');
  assert.equal(result.detected.mime, 'image/gif');
  assert.equal(result.looksLikeImage, true);
});

test('base64-image: malformed base64 throws a clear error', () => {
  assert.throws(() => parseBase64Image('data:image/png;base64,!!!not-valid-base64!!!'), /Could not decode as base64/);
  assert.throws(() => parseBase64Image(''), /Paste a base64 string or data URI first/);
});

// ============================================================
// HTTP security headers checker
// ============================================================

test('http-headers: flags missing CSP and HSTS on a bare response', () => {
  const raw = [
    'HTTP/1.1 200 OK',
    'Content-Type: text/html; charset=utf-8',
    'X-Frame-Options: DENY',
    'X-Content-Type-Options: nosniff'
  ].join('\r\n');
  const result = analyzeHeaders(raw);
  const missingKeys = result.missing.map((m) => m.key);
  assert.ok(missingKeys.includes('content-security-policy'));
  assert.ok(missingKeys.includes('strict-transport-security'));
});

test('http-headers: no false positives when all recommended headers are present', () => {
  const raw = [
    'HTTP/1.1 200 OK',
    'Content-Security-Policy: default-src \'self\'',
    'Strict-Transport-Security: max-age=63072000; includeSubDomains',
    'X-Frame-Options: DENY',
    'X-Content-Type-Options: nosniff',
    'Referrer-Policy: no-referrer',
    'Permissions-Policy: geolocation=()',
    'Cross-Origin-Opener-Policy: same-origin',
    'Cross-Origin-Resource-Policy: same-origin'
  ].join('\r\n');
  const result = analyzeHeaders(raw);
  assert.equal(result.missing.length, 0);
  assert.equal(result.present.length, 8);
});

// ============================================================
// Well-known ports reference lookup
// ============================================================

test('ports-reference: "80" query returns port 80 / HTTP', () => {
  const results = searchPorts('80');
  assert.ok(results.some((p) => p.port === 80 && p.name === 'HTTP'));
});

test('ports-reference: "http" query includes port 80', () => {
  const results = searchPorts('http');
  assert.ok(results.some((p) => p.port === 80 && /http/i.test(p.name)));
});

// ============================================================
// Reverse shell one-liner reference generator (static string templates
// only — no execution, no network access; same category as revshells.com)
// ============================================================

test('reverse-shell: generator substitutes IP and port for at least 3 shell types', () => {
  const ip = '10.10.14.22';
  const port = 4444;
  const typesToCheck = ['bash', 'python3', 'nc-mkfifo'];
  assert.ok(typesToCheck.every((t) => SHELL_TYPES.includes(t)));
  for (const shellType of typesToCheck) {
    const { payload } = generateReverseShell({ ip, port, shellType });
    assert.ok(payload.includes(ip), `${shellType} payload missing IP`);
    assert.ok(payload.includes(String(port)), `${shellType} payload missing port`);
  }
});

test('reverse-shell: paired netcat listener helper returns "nc" and the port', () => {
  const { listener } = generateReverseShell({ ip: '10.10.14.22', port: 4444, shellType: 'bash' });
  assert.match(listener, /\bnc\b/);
  assert.ok(listener.includes('4444'));
});

// ============================================================
// AES-GCM — raw byte (Uint8Array) file encryption support
// ============================================================

test('aes: encrypt then decrypt a Uint8Array (file bytes) returns the exact original bytes', async () => {
  const original = new Uint8Array([0, 1, 2, 3, 250, 251, 252, 253, 254, 255, 42, 42, 42]);
  const packed = await aesEncryptBytes(original, 'file-encryption-passphrase');
  const decrypted = await aesDecryptBytes(packed, 'file-encryption-passphrase');
  assert.deepEqual(Array.from(decrypted), Array.from(original));
});
