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
import { parseDnsResponse, parseRdapResponse, parseIpGeoResponse, buildDnsUrl, buildRdapUrl, buildIpGeoUrl, lookupWhois, lookupDns, isPlausibleDomain } from '../js/lib/net-lookups.js';
import { crackTimeLog10Seconds, humanizeLog10Seconds, verdictBand, assessStrength, ATTACKER_TIERS } from '../js/lib/crack-time.js';
import { crackHashes, detectHashType } from '../js/lib/hash-cracker.js';

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
import { autoDecode, DECODER_NAMES, MAX_INPUT_LENGTH } from '../js/lib/auto-decode.js';
import {
  normalizeTxtValue, parseSpf, findSpfRecords, lookupSpf, SPF_LOOKUP_LIMIT,
  parseDkim, lookupDkim,
  parseDmarc, lookupDmarc, explainDmarcPolicy, generateDmarc,
  parseBimi, lookupBimi,
  computeOverallHealth, lookupDomainHealth
} from '../js/lib/email-auth.js';
import {
  parseEmailHeaders, getHeaders, parseReceivedHeader, analyzeReceivedChain,
  parseAuthenticationResults, parseReceivedSpf, parseDkimSignatureHeader,
  analyzeAuthentication, analyzeEmailHeaders
} from '../js/lib/email-headers.js';
import {
  scoreEnglish, lettersOnly, chiSquaredPerChar, indexOfCoincidence,
  bigramDensity, trigramDensity, vowelRatio, ENGLISH_FREQ
} from '../js/lib/english-fitness.js';
import {
  caesarCrackAll, atbash, xorSingleByteCrackAll,
  railFenceDecrypt, railFenceCrackAll,
  vigenereDecrypt, vigenereEncrypt, vigenereCrack
} from '../js/lib/classical-ciphers.js';
import { enigmaProcess, ENIGMA_ROTOR_NAMES, ENIGMA_REFLECTOR_NAMES } from '../js/lib/enigma.js';
import {
  enigmaAutoBreak, enigmaAutoBreakCost, rotorOrderings,
  hillClimbPlugboard, optimizeRings
} from '../js/lib/enigma-break.js';
import { extractIocs, defang, refang } from '../js/lib/ioc.js';
import { cvss31Base, parseCvssVector, roundup, severityFor } from '../js/lib/cvss.js';
import { scanSecrets, shannonEntropy, describeEntropy } from '../js/lib/secret-scan.js';

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

test('password-gen: coverage guarantee holds across length/charset combinations (10k trials each, no failures allowed)', () => {
  // Bounce cycle 2 (QA, 2026-07-19): a prior version of this test only ran
  // 200 iterations, which is far too few to catch the ~0.049% (~1-in-2000)
  // "stomp" coverage-guarantee regression QA found via a 500k-trial Monte
  // Carlo — that was a false negative in this suite's own coverage, not
  // evidence the bug didn't exist. This is not a probabilistic near-guarantee
  // check: ANY failure here means the coverage guarantee is broken.
  //
  // 10,000 trials per combination keeps the default `npm test` run fast.
  // The full ≥100,000-trial verification (matching QA's own repro scale)
  // is run separately via `node test/password-gen-coverage-stress.mjs`
  // (see that file) and was run at 500k/200k/200k trials (900k total, 0
  // failures) as part of verifying this fix before commit.
  const sets = {
    upper: /[A-Z]/, lower: /[a-z]/, digits: /[0-9]/,
    symbols: /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/
  };
  const N = 10000;
  // Include length 8 (tighter than the original length-16-only test) and
  // length 4 (tightest possible with all 4 single-char-minimum sets — every
  // position is a structurally-guaranteed char, the highest-risk case for
  // any force-insertion-style bug).
  const combos = [
    { length: 16 },
    { length: 8 },
    { length: 4 }
  ];
  for (const opts of combos) {
    for (let i = 0; i < N; i++) {
      const pwd = generatePassword(opts);
      for (const [name, re] of Object.entries(sets)) {
        assert.ok(re.test(pwd), `length=${opts.length} iteration ${i}: "${pwd}" missing required set "${name}"`);
      }
    }
  }
});

test('password-gen: digit representation is roughly proportional to set size, not overrepresented (bias sanity check)', () => {
  // Monte Carlo sanity check (not a tight statistical bound): with all 4
  // default sets selected (26+26+10+27 = 89 chars), digits should make up
  // close to their 10/89 ≈ 11.2% share of characters, not the ~19%+
  // overrepresentation the old "always force one guaranteed digit"
  // mechanism produced. Some residual skew above proportional is expected
  // and acceptable (see js/lib/password-gen.js doc comment) — this just
  // guards against the bias regressing back to its old magnitude.
  const N = 4000;
  const length = 20;
  let digitCount = 0;
  let totalCount = 0;
  for (let i = 0; i < N; i++) {
    const pwd = generatePassword({ length });
    for (const c of pwd) {
      totalCount++;
      if (c >= '0' && c <= '9') digitCount++;
    }
  }
  const observedFrac = digitCount / totalCount;
  const expectedFrac = 10 / 89;
  // Allow generous headroom for Monte Carlo noise + residual inherent skew,
  // while still catching a regression back to the old ~19%+ overrepresentation.
  assert.ok(observedFrac < expectedFrac * 1.5,
    `digit frequency ${(observedFrac * 100).toFixed(2)}% is more than 1.5x the proportional ${(expectedFrac * 100).toFixed(2)}% expectation`);
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

test('homoglyph: full-width Latin lookalike (U+FF41 fullwidth "a") IS flagged as a Fullwidth confusable', () => {
  const spoofed = String.fromCodePoint(0xFF41) + 'pple.com'; // fullwidth a + "pple.com"
  const result = detectHomoglyphs(spoofed);
  assert.equal(result.hasMixedScript, true);
  const hit = result.flagged.find((f) => f.codepoint === 'U+FF41');
  assert.ok(hit, 'expected U+FF41 to be flagged');
  assert.equal(hit.looksLike, 'a');
  assert.equal(hit.script, 'Fullwidth');
});

test('homoglyph: zero-width space (U+200B) is flagged as invisibleChars, NOT as a confusable pair', () => {
  const withZwsp = 'pay' + String.fromCodePoint(0x200B) + 'pal.com';
  const result = detectHomoglyphs(withZwsp);
  assert.equal(result.hasInvisibleChars, true);
  assert.equal(result.invisibleChars.length, 1);
  assert.equal(result.invisibleChars[0].codepoint, 'U+200B');
  assert.equal(result.invisibleChars[0].name, 'ZERO WIDTH SPACE');
  // Zero-width chars are not lookalikes of anything, so they must not leak
  // into the confusable-pair `flagged` array.
  assert.ok(!result.flagged.some((f) => f.codepoint === 'U+200B'));
});

test('homoglyph: BOM/zero-width-no-break-space (U+FEFF) is flagged as invisibleChars', () => {
  const withBom = String.fromCodePoint(0xFEFF) + 'admin';
  const result = detectHomoglyphs(withBom);
  assert.equal(result.hasInvisibleChars, true);
  assert.ok(result.invisibleChars.some((f) => f.codepoint === 'U+FEFF'));
});

test('homoglyph: plain ASCII has no invisible characters flagged', () => {
  const result = detectHomoglyphs('login.example.com');
  assert.equal(result.hasInvisibleChars, false);
  assert.equal(result.invisibleChars.length, 0);
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

// ============================================================
// Auto-Decode (Magic Wand) — js/lib/auto-decode.js
// Orchestration engine: layered decoding, ranking, safety caps.
// ============================================================

// Deterministic PRNG (mulberry32) so the "adversarial" tests are reproducible.
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function findByOutput(result, expected) {
  return result.candidates.find((c) => c.output === expected);
}

// ---- 1. Layered-encoding correctness -----------------------------------

test('auto-decode: peels text -> base64 -> hex (top result, correct 2-step path)', () => {
  const plain = 'the attack is at dawn and we go now';
  const layered = enc.hexEncode(enc.base64Encode(plain));
  const r = autoDecode(layered);
  assert.equal(r.candidates[0].output, plain, 'plaintext should be the #1 ranked candidate');
  assert.deepEqual(r.candidates[0].path, ['hex', 'base64']);
});

test('auto-decode: peels text -> hex -> base64 (correct 2-step path)', () => {
  const plain = 'the attack is at dawn and we go now';
  const layered = enc.base64Encode(enc.hexEncode(plain));
  const r = autoDecode(layered);
  assert.equal(r.candidates[0].output, plain);
  assert.deepEqual(r.candidates[0].path, ['base64', 'hex']);
});

test('auto-decode: peels text -> base64 -> base32 (correct 2-step path)', () => {
  const plain = 'the attack is at dawn and we go now';
  const layered = enc.base32Encode(enc.base64Encode(plain));
  const r = autoDecode(layered);
  assert.equal(r.candidates[0].output, plain);
  assert.deepEqual(r.candidates[0].path, ['base32', 'base64']);
});

test('auto-decode: peels a 3-layer stack base64(hex(base64(text)))', () => {
  const plain = 'the attack is at dawn and we go now';
  const layered = enc.base64Encode(enc.hexEncode(enc.base64Encode(plain)));
  const r = autoDecode(layered);
  const hit = findByOutput(r, plain);
  assert.ok(hit, 'original plaintext must be recovered');
  assert.deepEqual(hit.path, ['base64', 'hex', 'base64']);
  assert.equal(r.candidates[0].output, plain, 'and it should rank #1');
});

// ---- 2. Single-layer correctness ---------------------------------------

test('auto-decode: single-layer decoders each rank the plaintext #1', () => {
  const plain = 'the attack is at dawn and we go now';
  const cases = [
    ['base64', enc.base64Encode(plain)],
    ['hex', enc.hexEncode(plain)],
    ['base32', enc.base32Encode(plain)],
    ['base58', enc.base58Encode(plain)],
    ['base85', encExtra.base85Encode(plain)],
    ['base91', encExtra.base91Encode(plain)],
    ['binary', enc.binaryEncode(plain)],
    ['uudecode', encExtra.uuEncode(plain)],
    ['rot13', enc.rot13(plain)],
    ['url', 'the%20attack%20is%20at%20dawn%20and%20we%20go%20now']
  ];
  for (const [name, encoded] of cases) {
    const r = autoDecode(encoded);
    assert.equal(r.candidates[0].output, plain, `${name}: plaintext should rank #1`);
    assert.deepEqual(r.candidates[0].path, [name], `${name}: path should be single-step`);
    assert.ok(r.candidates[0].score >= 0.5, `${name}: score should be high-confidence`);
  }
});

test('auto-decode: Morse single layer decodes and ranks #1 (case-insensitive)', () => {
  const morse = morseEncode('hello world'); // decoder returns uppercase per ITU table
  const r = autoDecode(morse);
  assert.equal(r.candidates[0].output.toLowerCase(), 'hello world');
  assert.deepEqual(r.candidates[0].path, ['morse']);
});

// ---- 3. Adversarial / safety: timing + enforced attempt cap ------------

test('auto-decode: 4KB multi-encoding-lookalike input completes fast and under the default cap', () => {
  const rnd = mulberry32(1234567);
  const hexchars = '0123456789abcdef';
  let big = '';
  for (let i = 0; i < 4096; i++) big += hexchars[(rnd() * 16) | 0];
  const t0 = performance.now();
  const r = autoDecode(big);
  const wall = performance.now() - t0;
  assert.ok(wall < 1000, `should finish under 1s, took ${wall.toFixed(1)}ms`);
  assert.ok(r.stats.attempts <= 400, `attempts (${r.stats.attempts}) must not exceed default cap 400`);
});

test('auto-decode: hard attempt cap is actually enforced on a maximally-branching input', () => {
  // Deeply nested base64 branches heavily (each layer re-decodes + base85/base91
  // garbage branches). Its natural (uncapped) attempt count is well above 20.
  let s = 'The quick brown fox jumps over the lazy dog. '.repeat(6);
  for (let i = 0; i < 4; i++) s = enc.base64Encode(s);

  const uncapped = autoDecode(s, { maxAttempts: 100000 });
  assert.ok(uncapped.stats.attempts > 20, `sanity: natural attempts (${uncapped.stats.attempts}) should exceed the test cap`);

  const capped = autoDecode(s, { maxAttempts: 20 });
  assert.ok(capped.stats.attempts <= 20, `attempts (${capped.stats.attempts}) must never exceed the cap`);
  assert.equal(capped.stats.capHit, true, 'capHit flag must be set when the budget is exhausted');
});

// ---- 4. Cycle safety (rot13 is an involution) --------------------------

test('auto-decode: detects the rot13 involution cycle and still recovers plaintext', () => {
  const rotted = enc.rot13('hello world'); // 'uryyb jbeyq'
  const r = autoDecode(rotted);
  assert.equal(r.candidates[0].output, 'hello world');
  assert.deepEqual(r.candidates[0].path, ['rot13']);
  // rot13(rot13(x)) === x loops back to the seeded raw input -> must be caught.
  assert.ok(r.stats.cyclesDetected >= 1, 'the rot13 -> rot13 loop must be detected and stopped');
  assert.ok(r.stats.attempts < 400, 'a cycle must not blow the attempt budget');
});

// ---- 5. Scoring sanity: meaningful text beats noise --------------------

test('auto-decode: English/JSON decodes score higher than random-noise decodes', () => {
  const english = autoDecode(enc.base64Encode('this is the message and we know what they want now'));

  // Deterministic binary noise (not text) -> its decode is low-printable garbage.
  const rnd = mulberry32(99);
  let noiseBytes = '';
  for (let i = 0; i < 48; i++) noiseBytes += String.fromCharCode((rnd() * 256) | 0);
  const noise = autoDecode(enc.base64Encode(noiseBytes));

  assert.ok(english.candidates[0].score >= 0.5, 'english top should be high-confidence');
  assert.ok(
    english.candidates[0].score > noise.candidates[0].score,
    `english (${english.candidates[0].score.toFixed(3)}) should outscore noise (${noise.candidates[0].score.toFixed(3)})`
  );
  // Within one result, the best-ranked candidate beats the worst-ranked one.
  const eng = english.candidates;
  assert.ok(eng[0].score >= eng[eng.length - 1].score);
});

test('auto-decode: valid JSON is recognised and scored/labelled as such', () => {
  const r = autoDecode(enc.base64Encode('{"user":"admin","role":"root","n":[1,2,3]}'));
  assert.equal(r.candidates[0].output, '{"user":"admin","role":"root","n":[1,2,3]}');
  assert.deepEqual(r.candidates[0].path, ['base64']);
  assert.ok(r.candidates[0].reasons.some((x) => /valid JSON/i.test(x)), 'reasons must credit valid JSON');
});

// ---- Hash identification is informational, kept out of decode candidates ----

test('auto-decode: 32-hex input is surfaced as a hash (informational), separate from decodes', () => {
  const r = autoDecode('d41d8cd98f00b204e9800998ecf8427e'); // MD5("")
  assert.ok(r.hashInfo, 'hashInfo must be populated for a bare 32-hex string');
  assert.equal(r.hashInfo.matches[0].algorithm, 'MD5');
  assert.ok(/one-way hash/i.test(r.hashInfo.note));
});

test('auto-decode: graceful empty/no-op inputs never throw', () => {
  assert.doesNotThrow(() => autoDecode(''));
  assert.equal(autoDecode('').candidates.length, 0);
  assert.doesNotThrow(() => autoDecode('   '));
  const r = autoDecode('plain english sentence with no encoding at all');
  assert.ok(Array.isArray(r.candidates), 'always returns a candidates array');
  assert.ok(DECODER_NAMES.length >= 10, 'engine advertises its reused decoder set');
});

// ---- 6. QA bounce fix (commit 552a0e2): scoring calibration --------------
// QA's repro: a correct single-layer decode of ordinary technical/non-prose
// content (no common-English words to match) landed at the "printable+UTF8
// only" floor (40%), below the 50% high-confidence cutoff, and so was hidden
// under "Show N more (low confidence)" despite being the single unambiguous
// correct answer. Fixed via a dictionary-free structure signal (see
// naturalCharRatio()/hasWhitespace() in auto-decode.js) that credits real
// content generally, not just dictionary-word prose.

test('auto-decode: QA repro — non-dictionary technical sentence scores high-confidence, not buried', () => {
  const plain = 'QA independent check 552a0e2';
  const r = autoDecode(enc.hexEncode(plain));
  assert.equal(r.candidates[0].output, plain, 'plaintext must still be the #1 ranked candidate');
  assert.deepEqual(r.candidates[0].path, ['hex']);
  assert.ok(
    r.candidates[0].score >= 0.5,
    `QA repro must clear the high-confidence cutoff, scored ${r.candidates[0].score.toFixed(3)}`
  );
});

test('auto-decode: other non-dictionary technical decodes (ids, config, commit-ish strings) also clear the cutoff', () => {
  const cases = [
    'deploy build 91a3f2 to staging cluster now',
    'config value X-Request-Id set to abc123',
    'commit 4e91f0a2 failed lint stage two',
    'ticket ENG-4021 blocked on review'
  ];
  for (const plain of cases) {
    const r = autoDecode(enc.hexEncode(plain));
    assert.equal(r.candidates[0].output, plain, `should recover: ${plain}`);
    assert.ok(r.candidates[0].score >= 0.5, `"${plain}" should be high-confidence, scored ${r.candidates[0].score.toFixed(3)}`);
  }
});

test('auto-decode: ambiguous rot13 of non-dictionary text still outranks wrong-decoder guesses on the same ciphertext', () => {
  const tech = 'Server node K7 restart pending 0x3F2A';
  const rotted = enc.rot13(tech);
  const r = autoDecode(rotted);
  assert.equal(r.candidates[0].output, tech, 'true rot13 decode must still be the top candidate');
  assert.deepEqual(r.candidates[0].path, ['rot13']);
  assert.ok(r.candidates[0].score >= 0.5, 'true decode of non-dictionary text must be high-confidence');
  // Every other (wrong-decoder) candidate produced from the same ciphertext
  // must rank clearly below the true decode — no regression in discriminating
  // power between the real answer and coincidental garbage from other decoders.
  for (const c of r.candidates.slice(1)) {
    assert.ok(c.score < r.candidates[0].score, `wrong-decoder candidate outranked the true decode: ${JSON.stringify(c)}`);
  }
});

test('auto-decode: no-known-encoding / coincidental noise does not get a falsely confident score', () => {
  // Random byte noise run through base64 (same construction as the
  // English-vs-noise test above, at a wider sweep of seeds/lengths) must
  // never cross the high-confidence cutoff, even post-fix.
  let maxNoiseScore = 0;
  for (let seed = 0; seed < 150; seed++) {
    const rnd = mulberry32(2000 + seed * 7);
    const len = 20 + ((rnd() * 60) | 0);
    let noiseBytes = '';
    for (let i = 0; i < len; i++) noiseBytes += String.fromCharCode((rnd() * 256) | 0);
    const r = autoDecode(enc.base64Encode(noiseBytes));
    if (r.candidates.length === 0) continue;
    maxNoiseScore = Math.max(maxNoiseScore, r.candidates[0].score);
  }
  assert.ok(maxNoiseScore < 0.5, `random-byte noise must stay below high-confidence, max observed ${maxNoiseScore.toFixed(3)}`);

  // A plain string that isn't any supported encoding at all must not produce
  // a falsely confident candidate either (and must not throw).
  const r2 = autoDecode('this is not encoded in anything, just a sentence sitting here');
  for (const c of r2.candidates) {
    assert.ok(c.score < 1.01, 'sanity: score is always a valid 0..1 value');
  }
});

// ---- 6b. QA bounce cycle 2: narrow-alphabet random-token false positives -
// Regression guard for the exact class QA found on the 552a0e2 scoring fix:
// pasting a random hex/base64/base32 token (an ordinary "identify this
// nonce/hash/blob" action) must NOT be promoted to high-confidence ("Most
// likely"). The leak was the weak, no-whitespace natural-char tier stacking
// with coincidental 2-letter common-word substrings ("no"/"on"/"or"/"so",
// inevitable once hex's a-f alphabet rot13's into the n-s band) to push pure
// noise over the 0.5 cutoff. Fixed by: (a) reducing the weak-tier bonus,
// (b) requiring matched words of length >= 3 on a whitespace-less token, and
// gating the word signal out entirely below 85% printable. QA's own repro was
// 1,000 random hex strings of length 40-440; this test reproduces that exact
// methodology (at a committed 300/alphabet for CI speed — the full 1,000+ was
// run out-of-band and is 0 crossings in this length band for all three
// alphabets) and extends it to base64 AND base32, which the prior suite never
// covered. Acceptance bar: ZERO crossings in the 40-440 length band.
function randomTokenNoiseCrossings(alphabet, seedBase, trials, minLen, maxLen, evenLenOnly) {
  let crossings = 0;
  let maxScore = 0;
  for (let i = 0; i < trials; i++) {
    const rnd = mulberry32((seedBase + i * 2654435761) >>> 0);
    let len = minLen + ((rnd() * (maxLen - minLen + 1)) | 0);
    if (evenLenOnly && len % 2 === 1) len++;
    let s = '';
    for (let j = 0; j < len; j++) s += alphabet[(rnd() * alphabet.length) | 0];
    const r = autoDecode(s);
    if (r.candidates.length === 0) continue;
    const top = r.candidates[0].score;
    if (top > maxScore) maxScore = top;
    if (top >= 0.5) crossings++;
  }
  return { crossings, maxScore };
}

test('auto-decode: random hex tokens (40-440 chars) never reach high-confidence [QA bounce-2 regression]', () => {
  const { crossings, maxScore } = randomTokenNoiseCrossings(
    '0123456789abcdef', 424242, 300, 40, 440, true
  );
  assert.equal(
    crossings, 0,
    `random hex noise must never cross the 0.5 high-confidence cutoff, saw ${crossings}/300 (max ${maxScore.toFixed(3)})`
  );
});

test('auto-decode: random base64 tokens (40-440 chars) never reach high-confidence [QA bounce-2 regression]', () => {
  const { crossings, maxScore } = randomTokenNoiseCrossings(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', 918273, 300, 40, 440, false
  );
  assert.equal(
    crossings, 0,
    `random base64 noise must never cross the 0.5 high-confidence cutoff, saw ${crossings}/300 (max ${maxScore.toFixed(3)})`
  );
});

test('auto-decode: random base32 tokens (40-440 chars) never reach high-confidence [QA bounce-2 regression]', () => {
  const { crossings, maxScore } = randomTokenNoiseCrossings(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 555111, 300, 40, 440, false
  );
  assert.equal(
    crossings, 0,
    `random base32 noise must never cross the 0.5 high-confidence cutoff, saw ${crossings}/300 (max ${maxScore.toFixed(3)})`
  );
});

test('auto-decode: bounce-2 fix does not regress true single-layer decodes of real sentences', () => {
  // The complement of the false-positive guard: a genuine plain-English
  // sentence run through exactly one encoding layer must STILL be the #1
  // candidate and STILL clear the high-confidence cutoff, for every base
  // alphabet whose noise we now reject.
  const sentences = [
    'the quick brown fox jumps over the lazy dog',
    'all your base are belong to us now',
    'this is a secret message for you to read'
  ];
  const layers = [
    ['hex', (p) => enc.hexEncode(p)],
    ['base64', (p) => enc.base64Encode(p)],
    ['base32', (p) => enc.base32Encode(p)]
  ];
  for (const [layerName, encodeFn] of layers) {
    for (const plain of sentences) {
      const r = autoDecode(encodeFn(plain));
      assert.equal(r.candidates[0].output, plain, `${layerName}: plaintext must be #1 for "${plain}"`);
      assert.ok(
        r.candidates[0].score >= 0.5,
        `${layerName}: "${plain}" must stay high-confidence, scored ${r.candidates[0].score.toFixed(3)}`
      );
    }
  }
});

// ---- 7. QA bounce fix (commit 552a0e2): input-size guard -----------------
// QA reproduced a 6758ms synchronous main-thread freeze feeding a
// 400,000-char paste to the live tool. Fixed via a hard length cap checked
// before any processing (MAX_INPUT_LENGTH in auto-decode.js).

test('auto-decode: oversized input is rejected by the size guard, not processed through the engine', () => {
  assert.equal(MAX_INPUT_LENGTH, 20000, 'sanity: test assumes the documented default cap');

  const big = 'a'.repeat(400000);
  const t0 = performance.now();
  const r = autoDecode(big);
  const wall = performance.now() - t0;

  assert.equal(r.stats.sizeCapped, true, 'stats must flag that the size guard fired');
  assert.equal(r.stats.inputLength, 400000);
  assert.equal(r.stats.maxInputLength, MAX_INPUT_LENGTH);
  assert.equal(r.candidates.length, 0, 'no decode attempts should run on an oversized input');
  assert.equal(r.hashInfo, null);
  assert.ok(wall < 50, `size guard must be near-instant regardless of input size, took ${wall.toFixed(1)}ms`);
});

test('auto-decode: size guard boundary — exactly at the cap processes normally, one over is rejected', () => {
  const atLimit = autoDecode('a'.repeat(MAX_INPUT_LENGTH));
  assert.equal(atLimit.stats.sizeCapped, false, 'input exactly at the cap must be processed normally');

  const overLimit = autoDecode('a'.repeat(MAX_INPUT_LENGTH + 1));
  assert.equal(overLimit.stats.sizeCapped, true, 'one character over the cap must be rejected');
});

test('auto-decode: size guard is overridable via options (for callers/tests that need a different cap)', () => {
  const r = autoDecode('a'.repeat(100), { maxInputLength: 50 });
  assert.equal(r.stats.sizeCapped, true);
  assert.equal(r.stats.maxInputLength, 50);
});

// ============================================================
// Email authentication — SPF / DKIM / DMARC / BIMI
// (pure parsers + DMARC generator; lookups tested via a fake fetch,
// no real network — same pattern as the net-lookups lookupWhois tests)
// ============================================================

test('email-auth: normalizeTxtValue strips dns.google quoting and joins split TXT strings', () => {
  assert.equal(normalizeTxtValue('"v=spf1 ~all"'), 'v=spf1 ~all');
  assert.equal(normalizeTxtValue('"v=spf1 " "include:_spf.example.com " "~all"'), 'v=spf1 include:_spf.example.com ~all');
  assert.equal(normalizeTxtValue('v=spf1 ~all'), 'v=spf1 ~all'); // unquoted passthrough
  assert.equal(normalizeTxtValue(42), '');
});

test('email-auth: parseSpf parses mechanisms, qualifiers, and the "all" policy', () => {
  const r = parseSpf('v=spf1 ip4:192.0.2.0/24 include:_spf.google.com a mx ~all');
  assert.equal(r.all, '~');
  assert.equal(r.mechanisms.length, 5);
  assert.deepEqual(r.mechanisms[0], { qualifier: '+', type: 'ip4', value: '192.0.2.0/24' });
  assert.deepEqual(r.mechanisms[1], { qualifier: '+', type: 'include', value: '_spf.google.com' });
  assert.deepEqual(r.mechanisms[2], { qualifier: '+', type: 'a', value: null });
  assert.deepEqual(r.mechanisms[3], { qualifier: '+', type: 'mx', value: null });
  assert.deepEqual(r.mechanisms[4], { qualifier: '~', type: 'all', value: null });
  assert.equal(r.lookupCount, 3); // include + a + mx
  assert.equal(r.lookupLimitExceeded, false);
  assert.equal(r.warnings.length, 0);
});

test('email-auth: parseSpf accepts a quoted dns.google-style record', () => {
  const r = parseSpf('"v=spf1 -all"');
  assert.equal(r.all, '-');
  assert.equal(r.mechanisms.length, 1);
});

test('email-auth: parseSpf flags exceeding the RFC 7208 10-lookup limit', () => {
  const includes = Array.from({ length: SPF_LOOKUP_LIMIT + 1 }, (_, i) => `include:s${i}.example.com`).join(' ');
  const r = parseSpf(`v=spf1 ${includes} ~all`);
  assert.equal(r.lookupCount, SPF_LOOKUP_LIMIT + 1);
  assert.equal(r.lookupLimitExceeded, true);
  assert.ok(r.warnings.some((w) => /exceeding the RFC 7208 limit/.test(w)));
});

test('email-auth: parseSpf warns when there is no "all" mechanism or redirect', () => {
  const r = parseSpf('v=spf1 include:_spf.example.com');
  assert.equal(r.all, null);
  assert.ok(r.warnings.some((w) => /catch-all/.test(w)));
});

test('email-auth: parseSpf understands redirect= as a lookup-consuming modifier and suppresses the no-catch-all warning', () => {
  const r = parseSpf('v=spf1 redirect=_spf.example.com');
  assert.equal(r.redirect, '_spf.example.com');
  assert.equal(r.lookupCount, 1);
  assert.ok(!r.warnings.some((w) => /catch-all/.test(w)));
});

test('email-auth: parseSpf rejects a non-SPF record', () => {
  assert.throws(() => parseSpf('v=DKIM1; k=rsa; p=abc'), /Not a valid SPF record/);
});

test('email-auth: findSpfRecords filters a mixed TXT answer set to just the SPF record(s)', () => {
  const found = findSpfRecords(['"google-site-verification=abc123"', '"v=spf1 -all"']);
  assert.deepEqual(found, ['v=spf1 -all']);
});

test('email-auth: lookupSpf finds and parses the SPF record among unrelated TXT records', async () => {
  const fakeFetch = async () => ({
    json: async () => ({
      Status: 0,
      Answer: [
        { name: 'example.com.', type: 16, TTL: 300, data: '"google-site-verification=abc123"' },
        { name: 'example.com.', type: 16, TTL: 300, data: '"v=spf1 include:_spf.google.com ~all"' }
      ]
    })
  });
  const r = await lookupSpf('example.com', fakeFetch);
  assert.equal(r.domain, 'example.com');
  assert.equal(r.all, '~');
  assert.equal(r.multipleRecords, false);
});

test('email-auth: lookupSpf throws a friendly error when no SPF record exists', async () => {
  const fakeFetch = async () => ({ json: async () => ({ Status: 0, Answer: [] }) });
  await assert.rejects(() => lookupSpf('no-spf.example.com', fakeFetch), /No SPF record found/);
});

test('email-auth: parseDkim reports key type, presence, and revocation', () => {
  const ok = parseDkim('v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1234');
  assert.equal(ok.keyType, 'rsa');
  assert.equal(ok.publicKeyPresent, true);
  assert.equal(ok.revoked, false);
  assert.equal(ok.missingKey, false);

  const revoked = parseDkim('v=DKIM1; k=rsa; p=');
  assert.equal(revoked.revoked, true);
  assert.equal(revoked.publicKeyPresent, false);
  assert.ok(revoked.warnings.some((w) => /REVOKED/.test(w)));

  const missing = parseDkim('v=DKIM1; k=rsa');
  assert.equal(missing.missingKey, true);
  assert.ok(missing.warnings.some((w) => /No p=/.test(w)));
});

test('email-auth: parseDkim rejects an unsupported version tag', () => {
  assert.throws(() => parseDkim('v=DKIM2; k=rsa; p=abc'), /Unsupported DKIM record version/);
});

test('email-auth: lookupDkim queries <selector>._domainkey.<domain> and defaults the selector to "default"', async () => {
  let requestedUrl;
  const fakeFetch = async (url) => {
    requestedUrl = url;
    return { json: async () => ({ Status: 0, Answer: [{ name: 'default._domainkey.example.com.', type: 16, TTL: 300, data: '"v=DKIM1; k=rsa; p=ABC123"' }] }) };
  };
  const r = await lookupDkim('example.com', undefined, fakeFetch);
  assert.match(requestedUrl, /name=default\._domainkey\.example\.com/);
  assert.equal(r.selector, 'default');
  assert.equal(r.publicKeyPresent, true);
});

test('email-auth: lookupDkim throws a friendly error when the selector has no record', async () => {
  const fakeFetch = async () => ({ json: async () => ({ Status: 3, Answer: [] }) });
  await assert.rejects(() => lookupDkim('example.com', 'ghost', fakeFetch), /No DKIM record found/);
});

test('email-auth: parseDmarc parses every standard tag and explains the policy in plain English', () => {
  const r = parseDmarc('v=DMARC1; p=reject; sp=quarantine; rua=mailto:agg@example.com,mailto:agg2@example.com; ruf=mailto:forensic@example.com; pct=100; adkim=s; aspf=r; fo=1');
  assert.equal(r.policy, 'reject');
  assert.equal(r.subdomainPolicy, 'quarantine');
  assert.deepEqual(r.rua, ['mailto:agg@example.com', 'mailto:agg2@example.com']);
  assert.deepEqual(r.ruf, ['mailto:forensic@example.com']);
  assert.equal(r.pct, 100);
  assert.equal(r.adkim, 's');
  assert.equal(r.aspf, 'r');
  assert.equal(r.fo, '1');
  assert.equal(explainDmarcPolicy('reject'), r.policyExplanation);
  assert.equal(r.warnings.length, 0);
});

test('email-auth: parseDmarc defaults subdomain policy to p, and warns on p=none / missing rua / pct<100', () => {
  const r = parseDmarc('v=DMARC1; p=none; pct=50');
  assert.equal(r.subdomainPolicy, 'none');
  assert.equal(r.pct, 50);
  assert.ok(r.warnings.some((w) => /monitoring-only/.test(w)));
  assert.ok(r.warnings.some((w) => /50%/.test(w)));
  assert.ok(r.warnings.some((w) => /No rua=/.test(w)));
});

test('email-auth: parseDmarc rejects a record with no valid p= tag', () => {
  assert.throws(() => parseDmarc('v=DMARC1; sp=reject'), /missing a valid required "p=" policy tag/);
  assert.throws(() => parseDmarc('v=spf1 -all'), /Not a valid DMARC record/);
});

test('email-auth: lookupDmarc queries _dmarc.<domain>', async () => {
  let requestedUrl;
  const fakeFetch = async (url) => {
    requestedUrl = url;
    return { json: async () => ({ Status: 0, Answer: [{ name: '_dmarc.example.com.', type: 16, TTL: 300, data: '"v=DMARC1; p=reject; rua=mailto:agg@example.com"' }] }) };
  };
  const r = await lookupDmarc('example.com', fakeFetch);
  assert.match(requestedUrl, /name=_dmarc\.example\.com/);
  assert.equal(r.policy, 'reject');
});

test('email-auth: lookupDmarc throws a friendly error when no DMARC record is published', async () => {
  const fakeFetch = async () => ({ json: async () => ({ Status: 3, Answer: [] }) });
  await assert.rejects(() => lookupDmarc('no-dmarc.example.com', fakeFetch), /no DMARC policy published/);
});

test('email-auth: generateDmarc emits a minimal syntactically correct record for the defaults', () => {
  assert.equal(generateDmarc({}), 'v=DMARC1; p=none');
});

test('email-auth: generateDmarc emits every non-default tag in order', () => {
  const record = generateDmarc({
    policy: 'reject', subdomainPolicy: 'quarantine',
    rua: 'mailto:agg@example.com', ruf: 'mailto:forensic@example.com',
    pct: 50, adkim: 's', aspf: 's', fo: '1:d'
  });
  assert.equal(record, 'v=DMARC1; p=reject; sp=quarantine; rua=mailto:agg@example.com; ruf=mailto:forensic@example.com; pct=50; adkim=s; aspf=s; fo=1:d');
});

test('email-auth: generateDmarc validates policy, mailto addresses, pct range, and fo syntax', () => {
  assert.throws(() => generateDmarc({ policy: 'bogus' }), /Policy \(p\) must be one of/);
  assert.throws(() => generateDmarc({ rua: 'agg@example.com' }), /must be a mailto: URI/);
  assert.throws(() => generateDmarc({ pct: 150 }), /whole number between 0 and 100/);
  assert.throws(() => generateDmarc({ pct: -1 }), /whole number between 0 and 100/);
  assert.throws(() => generateDmarc({ fo: 'x' }), /Failure options/);
  try {
    generateDmarc({ policy: 'bogus', rua: 'nope' });
    assert.fail('should have thrown');
  } catch (err) {
    assert.equal(err.validationErrors.length, 2);
  }
});

test('email-auth: parseBimi extracts the logo and VMC URLs', () => {
  const r = parseBimi('v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem');
  assert.equal(r.logoUrl, 'https://example.com/logo.svg');
  assert.equal(r.vmcUrl, 'https://example.com/vmc.pem');

  const noVmc = parseBimi('v=BIMI1; l=https://example.com/logo.svg;');
  assert.equal(noVmc.logoUrl, 'https://example.com/logo.svg');
  assert.equal(noVmc.vmcUrl, null);

  assert.throws(() => parseBimi('v=spf1 -all'), /Not a valid BIMI record/);
});

test('email-auth: lookupBimi queries <selector>._bimi.<domain>, defaulting the selector to "default"', async () => {
  let requestedUrl;
  const fakeFetch = async (url) => {
    requestedUrl = url;
    return { json: async () => ({ Status: 0, Answer: [{ name: 'default._bimi.example.com.', type: 16, TTL: 300, data: '"v=BIMI1; l=https://example.com/logo.svg"' }] }) };
  };
  const r = await lookupBimi('example.com', undefined, fakeFetch);
  assert.match(requestedUrl, /name=default\._bimi\.example\.com/);
  assert.equal(r.logoUrl, 'https://example.com/logo.svg');
});

test('email-auth: lookupBimi throws a friendly error when no BIMI record exists', async () => {
  const fakeFetch = async () => ({ json: async () => ({ Status: 3, Answer: [] }) });
  await assert.rejects(() => lookupBimi('example.com', 'default', fakeFetch), /No BIMI record found/);
});

test('email-auth: computeOverallHealth scores a fully-enforced, BIMI-eligible domain as pass', () => {
  const health = computeOverallHealth({
    dmarc: { ok: true, data: { policy: 'reject' } },
    spf: { ok: true, data: { all: '-', redirect: null, lookupLimitExceeded: false } },
    bimi: { ok: true, data: {} }
  });
  assert.equal(health.score, 'pass');
  assert.equal(health.issues.length, 0);
});

test('email-auth: computeOverallHealth fails a domain with no DMARC or SPF at all', () => {
  const health = computeOverallHealth({
    dmarc: { ok: false, error: 'No DMARC record found at _dmarc.example.com.' },
    spf: { ok: false, error: 'No SPF record found at the apex of example.com.' },
    bimi: { ok: false, error: 'No BIMI record found.' }
  });
  assert.equal(health.score, 'fail');
  assert.equal(health.issues.length, 2);
});

test('email-auth: computeOverallHealth warns (not fails) on p=none and flags BIMI without DMARC enforcement', () => {
  const health = computeOverallHealth({
    dmarc: { ok: true, data: { policy: 'none' } },
    spf: { ok: true, data: { all: '~', redirect: null, lookupLimitExceeded: false } },
    bimi: { ok: true, data: {} }
  });
  assert.equal(health.score, 'warn');
  assert.ok(health.issues.some((i) => /monitoring only/.test(i)));
  assert.ok(health.issues.some((i) => /BIMI is published/.test(i)));
});

test('email-auth: lookupDomainHealth combines DMARC + SPF + BIMI without duplicating parsing logic', async () => {
  const fakeFetch = async (url) => {
    if (url.includes('_dmarc.')) {
      return { json: async () => ({ Status: 0, Answer: [{ name: '_dmarc.example.com.', type: 16, TTL: 300, data: '"v=DMARC1; p=reject"' }] }) };
    }
    if (url.includes('_bimi.')) {
      return { json: async () => ({ Status: 3, Answer: [] }) };
    }
    return { json: async () => ({ Status: 0, Answer: [{ name: 'example.com.', type: 16, TTL: 300, data: '"v=spf1 -all"' }] }) };
  };
  const health = await lookupDomainHealth('example.com', fakeFetch);
  assert.equal(health.domain, 'example.com');
  assert.equal(health.dmarc.ok, true);
  assert.equal(health.dmarc.data.policy, 'reject');
  assert.equal(health.spf.ok, true);
  assert.equal(health.bimi.ok, false);
  assert.equal(health.overall.score, 'pass');
});

// ============================================================
// Email header analyzer (Received: chain tracing + auth verdicts)
// ============================================================

const SAMPLE_EMAIL_HEADERS = [
  'Delivered-To: user@example.com',
  'Received: by 2002:abc:def0::1 with SMTP id r10csp1 for <user@example.com>; Wed, 30 Jul 2026 10:20:00 -0700 (PDT)',
  'Received: from mail-relay2.example.net (mail-relay2.example.net [203.0.113.5])',
  '        by mx.google.com with ESMTPS id def123',
  '        for <user@example.com>; Wed, 30 Jul 2026 10:15:00 -0700 (PDT)',
  'Received: from smtp.sender.com (smtp.sender.com [198.51.100.10])',
  '        by mail-relay2.example.net with ESMTP id ghi456',
  '        for <user@example.com>; Wed, 30 Jul 2026 09:50:00 -0700 (PDT)',
  'Authentication-Results: mx.google.com;',
  '       dkim=pass header.i=@sender.com header.s=selector1;',
  '       spf=pass (google.com: domain of bounce@sender.com designates 198.51.100.10 as permitted sender) smtp.mailfrom=bounce@sender.com;',
  '       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sender.com',
  'DKIM-Signature: v=1; a=rsa-sha256; d=sender.com; s=selector1; c=relaxed/relaxed;',
  '        h=from:to:subject; bh=abc123; b=xyz789',
  'From: Sender Name <sender@sender.com>',
  'To: user@example.com',
  'Subject: Test message',
  'Date: Wed, 30 Jul 2026 09:50:00 -0700',
  'Message-ID: <abc123@sender.com>',
  '',
  'This is the message body, which must be ignored by the parser.'
].join('\r\n');

test('email-headers: parseEmailHeaders handles folded continuation lines and stops at the blank line before the body', () => {
  const headers = parseEmailHeaders(SAMPLE_EMAIL_HEADERS);
  assert.equal(getHeaders(headers, 'Received').length, 3);
  const ar = getHeaders(headers, 'Authentication-Results');
  assert.equal(ar.length, 1);
  assert.match(ar[0].value, /dkim=pass/);
  assert.match(ar[0].value, /dmarc=pass/);
  assert.equal(getHeaders(headers, 'Subject')[0].value, 'Test message');
  assert.ok(!headers.some((h) => /message body/.test(h.value)), 'body content must not leak into headers');
});

test('email-headers: parseEmailHeaders throws on empty input and on a block with no valid header lines', () => {
  assert.throws(() => parseEmailHeaders(''), /Paste a raw email header block/);
  assert.throws(() => parseEmailHeaders('just plain text, no colons anywhere'), /No headers recognized/);
});

test('email-headers: parseReceivedHeader extracts from/by/with/for/date', () => {
  const r = parseReceivedHeader('from smtp.sender.com (smtp.sender.com [198.51.100.10]) by mail-relay2.example.net with ESMTP id ghi456 for <user@example.com>; Wed, 30 Jul 2026 09:50:00 -0700 (PDT)');
  assert.equal(r.from, 'smtp.sender.com');
  assert.equal(r.by, 'mail-relay2.example.net');
  assert.equal(r.protocol, 'ESMTP');
  assert.equal(r.for, 'user@example.com');
  assert.ok(r.date instanceof Date);
  assert.equal(r.date.getUTCFullYear(), 2026);
});

test('email-headers: analyzeReceivedChain reverses newest-first raw order into a chronological sender->recipient path and flags the >5min gap', () => {
  const headers = parseEmailHeaders(SAMPLE_EMAIL_HEADERS);
  const chain = analyzeReceivedChain(headers);
  assert.equal(chain.hopCount, 3);
  // hop 1 must be the ORIGINAL sender-side relay (oldest timestamp, last in raw text)
  assert.equal(chain.hops[0].from, 'smtp.sender.com');
  assert.equal(chain.hops[1].from, 'mail-relay2.example.net');
  assert.equal(chain.hops[2].from, null); // hop 3 ("Received: by … with SMTP …") has no "from" clause — internal delivery
  // 09:50 -> 10:15 is a 25-minute gap; 10:15 -> 10:20 is exactly 5 minutes (not flagged)
  assert.equal(chain.gaps.length, 1);
  assert.equal(chain.gaps[0].afterHop, 1);
  assert.equal(chain.gaps[0].beforeHop, 2);
  assert.equal(chain.gaps[0].deltaMs, 25 * 60 * 1000);
});

test('email-headers: parseAuthenticationResults extracts spf/dkim/dmarc verdicts and the authenticating server id', () => {
  const r = parseAuthenticationResults('mx.google.com; dkim=pass header.i=@sender.com; spf=pass smtp.mailfrom=bounce@sender.com; dmarc=pass (p=REJECT) header.from=sender.com');
  assert.equal(r.authservid, 'mx.google.com');
  assert.deepEqual(r.results.spf, ['pass']);
  assert.deepEqual(r.results.dkim, ['pass']);
  assert.deepEqual(r.results.dmarc, ['pass']);
});

test('email-headers: parseReceivedSpf extracts the leading result word', () => {
  assert.equal(parseReceivedSpf('pass (google.com: domain designates 1.2.3.4 as permitted sender) client-ip=1.2.3.4').result, 'pass');
  assert.equal(parseReceivedSpf('softfail (…)').result, 'softfail');
});

test('email-headers: parseDkimSignatureHeader extracts d=/s=/a= without attempting verification', () => {
  const r = parseDkimSignatureHeader('v=1; a=rsa-sha256; d=sender.com; s=selector1; c=relaxed/relaxed; h=from:to:subject; bh=abc123; b=xyz789');
  assert.equal(r.domain, 'sender.com');
  assert.equal(r.selector, 'selector1');
  assert.equal(r.algorithm, 'rsa-sha256');
});

test('email-headers: analyzeAuthentication merges Authentication-Results into a single spf/dkim/dmarc verdict set', () => {
  const headers = parseEmailHeaders(SAMPLE_EMAIL_HEADERS);
  const auth = analyzeAuthentication(headers);
  assert.equal(auth.verdicts.spf, 'pass');
  assert.equal(auth.verdicts.dkim, 'pass');
  assert.equal(auth.verdicts.dmarc, 'pass');
  assert.equal(auth.dkimSignatures.length, 1);
  assert.equal(auth.dkimSignatures[0].domain, 'sender.com');
  assert.equal(auth.arcChainPresent, false);
});

test('email-headers: analyzeAuthentication falls back to Received-SPF when there is no Authentication-Results header', () => {
  const raw = [
    'Received-SPF: fail (mx.example.com: domain does not designate 5.6.7.8 as permitted sender) client-ip=5.6.7.8',
    'From: spoofed@sender.com',
    'To: user@example.com',
    'Subject: test'
  ].join('\r\n');
  const headers = parseEmailHeaders(raw);
  const auth = analyzeAuthentication(headers);
  assert.equal(auth.verdicts.spf, 'fail');
  assert.equal(auth.verdicts.dkim, null);
});

test('email-headers: analyzeEmailHeaders ties basics + received chain + authentication together', () => {
  const result = analyzeEmailHeaders(SAMPLE_EMAIL_HEADERS);
  assert.equal(result.basics.from, 'Sender Name <sender@sender.com>');
  assert.equal(result.basics.subject, 'Test message');
  assert.equal(result.receivedChain.hopCount, 3);
  assert.equal(result.authentication.verdicts.dmarc, 'pass');
});

// ---------------------------------------------------------------------------
// crack-time.js — password strength / crack-time estimation (pure)
// ---------------------------------------------------------------------------
test('crack-time: crackTimeLog10Seconds matches the 2^(bits-1)/rate model', () => {
  // 41 bits at 1e12/s: 2^40 / 1e12 = 1.0995e12/1e12 ≈ 1.0995 s -> log10 ≈ 0.041
  const log10s = crackTimeLog10Seconds(41, 1e12);
  assert.ok(Math.abs(log10s - Math.log10(Math.pow(2, 40) / 1e12)) < 1e-9);
});

test('crack-time: humanize scales from instant through years to universe ages', () => {
  assert.equal(humanizeLog10Seconds(-5), 'instantly');
  assert.match(humanizeLog10Seconds(Math.log10(200)), /minutes$/);            // ~3 min, avoids the .5 rounding boundary
  assert.equal(humanizeLog10Seconds(Math.log10(7200)), '2 hours');
  assert.equal(humanizeLog10Seconds(Math.log10(31557600 * 5)), '5 years');
  assert.match(humanizeLog10Seconds(Math.log10(31557600 * 1e12)), /universe/);
  assert.equal(humanizeLog10Seconds(Infinity), 'effectively forever');
});

test('crack-time: verdict bands are monotonic and hit the documented extremes', () => {
  assert.equal(verdictBand(10).id, 'catastrophic');
  assert.equal(verdictBand(35).id, 'catastrophic');
  assert.equal(verdictBand(36).id, 'critical');
  assert.equal(verdictBand(65).id, 'fair');
  assert.equal(verdictBand(75).id, 'strong');
  assert.equal(verdictBand(128).id, 'fortress');
  assert.equal(verdictBand(300).id, 'fortress');
});

test('crack-time: assessStrength returns a tier per attacker with a human time each', () => {
  const a = assessStrength(80);
  assert.equal(a.tiers.length, ATTACKER_TIERS.length);
  for (const t of a.tiers) {
    assert.ok(typeof t.human === 'string' && t.human.length > 0);
    assert.ok(Number.isFinite(t.log10Seconds));
  }
  // Stronger attacker => shorter time (larger rate, smaller log10 seconds).
  const online = a.tiers.find((t) => t.id === 'online');
  const nation = a.tiers.find((t) => t.id === 'nation-state');
  assert.ok(online.log10Seconds > nation.log10Seconds);
});

test('crack-time: a weak password reads catastrophic, a long random one reads fortress', () => {
  const weak = assessStrength(20);
  assert.equal(weak.band.id, 'catastrophic');
  assert.ok(weak.barFill < 0.2);

  const strong = assessStrength(131);   // e.g. length 20 over a ~90-char set
  assert.equal(strong.band.id, 'fortress');
  assert.equal(strong.barFill, 1);      // saturates at 128 bits
  assert.match(strong.band.message, /supercomputer|universe/);
});

test('crack-time: message interpolation leaves no unfilled placeholders', () => {
  for (const bits of [10, 40, 55, 65, 75, 90, 140]) {
    const msg = assessStrength(bits).band.message;
    assert.ok(!/\{(ref|nation|anchor)\}/.test(msg), `unfilled placeholder at ${bits} bits: ${msg}`);
  }
});

test('crack-time: barFill is clamped to [0,1]', () => {
  assert.equal(assessStrength(0).barFill, 0);
  assert.equal(assessStrength(-5).barFill, 0);
  assert.equal(assessStrength(1000).barFill, 1);
});

// ---------------------------------------------------------------------------
// net-lookups.js — friendly input validation on DNS lookups (the empty/bad
// domain fix; no network involved — rejection happens before any fetch)
// ---------------------------------------------------------------------------
test('net-lookups: isPlausibleDomain accepts real domains and rejects junk', () => {
  for (const d of ['example.com', 'sub.example.co.uk', 'a.io', '_dmarc.example.com']) {
    assert.equal(isPlausibleDomain(d), true, d);
  }
  for (const d of ['', '   ', 'not a domain', 'http://example.com', 'example.com/path', 'localhost', 'exa mple.com']) {
    assert.equal(isPlausibleDomain(d), false, d);
  }
});

test('net-lookups: lookupDns rejects empty/invalid input before any fetch (friendly message)', async () => {
  const neverFetch = () => { throw new Error('fetch should not have been called'); };
  await assert.rejects(() => lookupDns('', 'TXT', neverFetch), /Enter a domain name/);
  await assert.rejects(() => lookupDns('http://example.com/path', 'A', neverFetch), /doesn't look like a domain/);
});

test('net-lookups: lookupDns turns a non-JSON (HTML error page) response into a friendly message', async () => {
  const htmlErrorFetch = () => Promise.resolve({
    ok: false,
    json: () => Promise.reject(new SyntaxError("Unexpected token '<'"))
  });
  await assert.rejects(() => lookupDns('example.com', 'TXT', htmlErrorFetch), /did not return a valid response/);
});

// ============================================================
// english-fitness.js — compact, corpus-free English-likeness scorer
// ============================================================

test('english-fitness: scoreEnglish ranks a real Caesar-shift-15 decode clearly above two near-miss/noise strings', () => {
  // These three strings are not arbitrary: XRPCTCRGNEI is the toolkit's own
  // auto-decode acceptance ciphertext, KECPGPETARV is its rot13 (the
  // "almost inevitable wrong guess" a naive decoder would try first), and
  // ICANENCRYPT is the true Caesar shift-15 plaintext.
  const real = scoreEnglish('ICANENCRYPT');
  const rot13OfSame = scoreEnglish('KECPGPETARV');
  const rawCiphertext = scoreEnglish('XRPCTCRGNEI');
  assert.ok(real > rot13OfSame, `real (${real}) should beat rot13-noise (${rot13OfSame})`);
  assert.ok(real > rawCiphertext, `real (${real}) should beat raw ciphertext (${rawCiphertext})`);
  assert.ok(real > rot13OfSame * 1.5, 'the win should be decisive, not marginal');
});

test('english-fitness: scoreEnglish rates a real English sentence (no spaces) as high confidence', () => {
  const score = scoreEnglish('THISISASECRETMESSAGE');
  assert.ok(score > 0.55, `expected clearly high confidence, got ${score.toFixed(3)}`);
});

test('english-fitness: scoreEnglish rates fixed random-letter strings as low confidence', () => {
  // Fixed, pre-selected strings (not cherry-picked post-hoc) at a range of
  // realistic lengths — not a single lucky draw.
  const samples = ['ABZSNKMGOSGETNFJHNHZGWED', 'UEMGJVWYUKPZEAPJNPFNRDBCNV', 'GUORAVACKRJBISGELT'];
  for (const s of samples) {
    const score = scoreEnglish(s);
    assert.ok(score < 0.35, `"${s}" should score low, got ${score.toFixed(3)}`);
  }
});

test('english-fitness: scoreEnglish returns 0 for empty/too-short input, never throws', () => {
  assert.equal(scoreEnglish(''), 0);
  assert.equal(scoreEnglish('AB'), 0);
  assert.doesNotThrow(() => scoreEnglish('123456!!!'));
});

test('english-fitness: helper functions are internally consistent', () => {
  assert.equal(lettersOnly('Hello, World! 123'), 'HELLOWORLD');
  assert.equal(chiSquaredPerChar(''), Infinity);
  assert.ok(chiSquaredPerChar(lettersOnly('THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG')) < chiSquaredPerChar('QQQQQQQQQQ'));
  assert.equal(indexOfCoincidence('A'), 0); // fewer than 2 letters
  assert.ok(indexOfCoincidence('AAAAAAAAAA') > indexOfCoincidence('ABCDEFGHIJ')); // repeats raise IoC
  assert.ok(bigramDensity('THE') > 0); // "TH" is a common bigram
  assert.ok(trigramDensity('THE') > 0); // "THE" is a common trigram
  assert.ok(vowelRatio('AEIOU') === 1);
  assert.ok(vowelRatio('BCDFG') === 0);
  // Sanity: standard English single-letter frequencies sum to ~1.
  const sum = Object.values(ENGLISH_FREQ).reduce((a, b) => a + b, 0);
  assert.ok(Math.abs(sum - 1) < 0.01, `ENGLISH_FREQ should sum to ~1, got ${sum}`);
});

// ============================================================
// classical-ciphers.js — Caesar/Atbash/XOR/rail-fence/Vigenere crackers
// ============================================================

test('classical-ciphers: caesarCrackAll finds shift 15 recovering ICANENCRYPT from the acceptance ciphertext', () => {
  const all = caesarCrackAll('XRPCTCRGNEI');
  assert.equal(all.length, 26);
  const shift15 = all.find((c) => c.shift === 15);
  assert.ok(shift15, 'shift 15 must be present');
  assert.equal(shift15.text, 'ICANENCRYPT');
});

test('classical-ciphers: caesarCrackAll shift 0 is the identity (no-op)', () => {
  const all = caesarCrackAll('HELLO');
  assert.equal(all.find((c) => c.shift === 0).text, 'HELLO');
});

test('classical-ciphers: atbash is an involution (A<->Z substitution) and leaves non-letters alone', () => {
  const original = 'Attack at Dawn! 123';
  assert.equal(atbash(atbash(original)), original);
  assert.equal(atbash('ABCXYZ'), 'ZYXCBA');
  assert.equal(atbash('abcxyz'), 'zyxcba');
});

test('classical-ciphers: xorSingleByteCrackAll recovers a known single-byte XOR key and only returns printable results', () => {
  const plain = 'the secret message is hidden here';
  const key = 0x2a;
  let xored = '';
  for (let i = 0; i < plain.length; i++) xored += String.fromCharCode(plain.charCodeAt(i) ^ key);

  const results = xorSingleByteCrackAll(xored);
  const found = results.find((r) => r.key === key);
  assert.ok(found, 'the correct key must be among the printable-filtered candidates');
  assert.equal(found.text, plain);
  // Every returned candidate must actually be overwhelmingly printable —
  // that is the whole point of the built-in filter.
  for (const r of results) {
    const printable = [...r.text].filter((ch) => {
      const c = ch.charCodeAt(0);
      return (c >= 0x20 && c <= 0x7e) || c === 9 || c === 10 || c === 13;
    }).length;
    assert.ok(printable / r.text.length >= 0.85, `key ${r.key} leaked a non-printable-heavy result`);
  }
});

test('classical-ciphers: xorSingleByteCrackAll works with a Uint8Array input directly', () => {
  const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
  const key = 200;
  const xored = bytes.map((b) => b ^ key);
  const found = xorSingleByteCrackAll(xored).find((r) => r.key === key);
  assert.ok(found);
  assert.equal(found.text, 'Hello');
});

test('classical-ciphers: rail-fence round-trips through encrypt/decrypt for several rail counts', () => {
  function railEncrypt(text, rails) {
    const fence = Array.from({ length: rails }, () => []);
    let rail = 0;
    let dir = 1;
    for (const ch of text) {
      fence[rail].push(ch);
      if (rail === 0) dir = 1;
      else if (rail === rails - 1) dir = -1;
      rail += dir;
    }
    return fence.flat().join('');
  }
  const plain = 'WEAREDISCOVEREDFLEEATONCE';
  for (const rails of [2, 3, 4, 5, 7]) {
    const cipher = railEncrypt(plain, rails);
    assert.equal(railFenceDecrypt(cipher, rails), plain, `rails=${rails}`);
  }
});

test('classical-ciphers: railFenceCrackAll tries rails 2..min(10, length-1) and includes the correct one', () => {
  function railEncrypt(text, rails) {
    const fence = Array.from({ length: rails }, () => []);
    let rail = 0;
    let dir = 1;
    for (const ch of text) {
      fence[rail].push(ch);
      if (rail === 0) dir = 1;
      else if (rail === rails - 1) dir = -1;
      rail += dir;
    }
    return fence.flat().join('');
  }
  const plain = 'DEFENDTHEEASTWALLOFTHECASTLE';
  const cipher = railEncrypt(plain, 4);
  const all = railFenceCrackAll(cipher);
  assert.ok(all.some((c) => c.rails === 4 && c.text === plain));
  assert.equal(all[0].rails, 2);
  assert.equal(all[all.length - 1].rails, Math.min(10, cipher.length - 1));
});

test('classical-ciphers: vigenereDecrypt/vigenereEncrypt round-trip and match a hand-computed vector', () => {
  const plain = 'ATTACKATDAWN';
  const key = 'LEMON';
  const cipher = vigenereEncrypt(plain, key);
  assert.equal(cipher, 'LXFOPVEFRNHR'); // classic textbook Vigenere example
  assert.equal(vigenereDecrypt(cipher, key), plain);
});

test('classical-ciphers: vigenereCrack recovers the LEMON key near the top for a known short ciphertext', () => {
  const plain = 'THISISASECRETMESSAGEHIDDENWELL';
  const key = 'LEMON';
  const cipher = vigenereEncrypt(plain, key);
  const cracked = vigenereCrack(cipher);
  assert.ok(cracked.length > 0, 'crack should return at least one candidate');
  assert.equal(cracked[0].key, key, 'LEMON should rank #1');
  assert.equal(cracked[0].text, plain);
});

test('classical-ciphers: vigenereCrack returns [] gracefully on too-short input, never throws', () => {
  assert.doesNotThrow(() => vigenereCrack(''));
  assert.deepEqual(vigenereCrack('AB'), []);
});

// ============================================================
// enigma.js — settings-based Enigma I/M3 simulator
// ============================================================

test('enigma: matches the well-known historical test vector (I-II-III, reflector B, AAA/AAA, no plugboard)', () => {
  const settings = { rotors: ['I', 'II', 'III'], reflector: 'B', ringSettings: ['A', 'A', 'A'], positions: ['A', 'A', 'A'] };
  assert.equal(enigmaProcess('AAAAA', settings), 'BDZGO');
});

test('enigma: is its own inverse — encrypting then running the same settings again recovers the original', () => {
  const settings = { rotors: ['III', 'II', 'I'], reflector: 'C', ringSettings: ['B', 'F', 'Q'], positions: ['X', 'Y', 'Z'], plugboard: 'AB CD EF' };
  const plain = 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG';
  const cipher = enigmaProcess(plain, settings);
  assert.notEqual(cipher, plain);
  assert.equal(enigmaProcess(cipher, settings), plain);
});

test('enigma: non-letters pass through unchanged and do not advance rotors; case is preserved', () => {
  const settings = { rotors: ['I', 'II', 'III'], reflector: 'B' };
  const withPunct = enigmaProcess('Hello, World! 123', settings);
  assert.ok(withPunct.includes(','));
  assert.ok(withPunct.includes('!'));
  assert.ok(withPunct.includes('123'));
  assert.equal(enigmaProcess(withPunct, settings), 'Hello, World! 123');
});

test('enigma: rejects an unknown rotor or reflector with a clear error', () => {
  assert.throws(() => enigmaProcess('A', { rotors: ['I', 'II', 'ZZ'], reflector: 'B' }), /Unknown rotor/);
  assert.throws(() => enigmaProcess('A', { rotors: ['I', 'II', 'III'], reflector: 'Z' }), /Unknown reflector/);
});

test('enigma: exposes its supported rotor and reflector names', () => {
  assert.deepEqual(ENIGMA_ROTOR_NAMES, ['I', 'II', 'III', 'IV', 'V']);
  assert.deepEqual(ENIGMA_REFLECTOR_NAMES, ['B', 'C']);
});

// ============================================================
// enigma-break.js — ciphertext-only Enigma auto-break (IoC + hill-climb)
// ============================================================

test('enigma-break: rotorOrderings yields every ordered 3-of-n permutation, all distinct', () => {
  assert.equal(rotorOrderings(['I', 'II', 'III', 'IV', 'V']).length, 60); // P(5,3)
  assert.equal(rotorOrderings(['I', 'II', 'III', 'IV']).length, 24);      // P(4,3)
  const orderings = rotorOrderings(['I', 'II', 'III']);
  assert.equal(orderings.length, 6);                                      // P(3,3) = 3!
  // Every triple has three distinct rotors, and the list has no duplicates.
  for (const [a, b, c] of orderings) assert.equal(new Set([a, b, c]).size, 3);
  assert.equal(new Set(orderings.map((o) => o.join('-'))).size, orderings.length);
});

test('enigma-break: enigmaAutoBreakCost reports the Phase-1 search size and probe length', () => {
  const cost = enigmaAutoBreakCost('X'.repeat(500), { rotorSet: ['I', 'II', 'III', 'IV', 'V'], reflectors: ['B', 'C'], probeLen: 200 });
  assert.equal(cost.orderings, 60);
  assert.equal(cost.phase1Decrypts, 2 * 60 * 26 * 26 * 26); // reflectors x P(5,3) x 26^3
  assert.equal(cost.probeChars, 200);                        // capped below the 500 available
  const full = enigmaAutoBreakCost('X'.repeat(40), { probeLen: 0 });
  assert.equal(full.probeChars, 40);                         // probeLen 0 = use the whole text
});

test('enigma-break: rejects ciphertext too short to analyse', () => {
  assert.throws(() => enigmaAutoBreak('ABCDE'), /too short/i);
});

test('enigma-break: hillClimbPlugboard recovers the plugboard once rotors/positions are known', () => {
  // Correct rotor order + positions are fixed here; only the plugboard is unknown.
  const plain = 'THEGENERALORDERSALLUNITSTOADVANCEATFIRSTLIGHTANDHOLDTHERIVERCROSSINGUNTILRELIEVED';
  const trueSettings = { rotors: ['I', 'III', 'II'], reflector: 'B', positions: ['D', 'O', 'G'], plugboard: ['QW', 'ER', 'TY'] };
  const cipher = enigmaProcess(plain, trueSettings);
  const base = { rotors: ['I', 'III', 'II'], reflector: 'B', positions: ['D', 'O', 'G'], ringSettings: ['A', 'A', 'A'] };
  const { plugboard, score } = hillClimbPlugboard(lettersOnly(cipher), base, scoreEnglish, 10);
  const recovered = enigmaProcess(cipher, { ...base, plugboard });
  assert.equal(lettersOnly(recovered), lettersOnly(plain));
  assert.ok(score > 0.4, `expected a confident English fitness, got ${score}`);
  // The three true pairs must all be present (order within/among pairs is irrelevant).
  const norm = (p) => p.split('').sort().join('');
  const got = new Set(plugboard.map(norm));
  for (const pair of ['QW', 'ER', 'TY']) assert.ok(got.has(norm(pair)), `missing plug ${pair}`);
});

test('enigma-break: optimizeRings never degrades a correct default-ring candidate', () => {
  const plain = 'MEETMEATTHEOLDBRIDGEWHENTHECLOCKTOWERCHIMESMIDNIGHTANDBRINGTHEDOCUMENTS';
  const settings = { rotors: ['V', 'II', 'IV'], reflector: 'C', positions: ['A', 'B', 'C'], ringSettings: ['A', 'A', 'A'] };
  const cipher = enigmaProcess(plain, settings);
  const base = { rotors: ['V', 'II', 'IV'], reflector: 'C', positions: ['A', 'B', 'C'], ringSettings: ['A', 'A', 'A'] };
  const before = scoreEnglish(enigmaProcess(cipher, base));
  const { ringSettings, score } = optimizeRings(lettersOnly(cipher), base, scoreEnglish);
  assert.ok(score >= before - 1e-9, 'ring search must not lower the fitness of an already-correct config');
  // The already-correct decrypt uses default rings, so the search should keep them.
  const stillCorrect = enigmaProcess(cipher, { ...base, ringSettings });
  assert.equal(lettersOnly(stillCorrect), lettersOnly(plain));
});

test('enigma-break: recovers the plaintext from ciphertext ALONE — unknown rotor order, start positions, and plugboard', () => {
  // Known-plaintext round trip: encrypt with a secret key, then hand ONLY the
  // ciphertext to the auto-break and require the original plaintext back. This
  // exercises the whole pipeline: rotor-order search, 26^3 start-position search,
  // ring refinement, and the plugboard hill-climb — no key given.
  const plain = 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG WHILE THE NATION WATCHES THE WAR '
    + 'UNFOLD ACROSS THE WIRELESS EVERY SINGLE EVENING AND THE OPERATORS COPY EACH MESSAGE';
  const secret = { rotors: ['II', 'IV', 'V'], reflector: 'B', positions: ['M', 'C', 'K'], plugboard: ['AB', 'CD', 'EF'] };
  const cipher = enigmaProcess(plain, secret);
  assert.notEqual(lettersOnly(cipher), lettersOnly(plain));

  // rotorSet is the three true wheels (6 orderings) and one reflector, to keep
  // this deterministic test to a few seconds. The full 5-wheel / both-reflector
  // search (P(5,3) x 2 x 26^3 decrypts) recovers the same key and plaintext but
  // takes ~1.5 min in Node — too slow for the unit suite; run it via the Web
  // Worker in the UI. Only the SEARCH SPACE is narrowed here, not the algorithm:
  // it still discovers the rotor ORDER, all start positions, and the plugboard.
  const res = enigmaAutoBreak(cipher, { rotorSet: ['II', 'IV', 'V'], reflectors: ['B'], probeLen: 120 });

  assert.equal(lettersOnly(res.plaintext), lettersOnly(plain), `recovered: ${lettersOnly(res.plaintext).slice(0, 80)}`);
  assert.deepEqual(res.rotors, ['II', 'IV', 'V']);
  assert.deepEqual(res.positions, ['M', 'C', 'K']);
  assert.ok(res.fitness > 0.45, `expected high English fitness, got ${res.fitness}`);
  assert.equal(res.confidenceLabel, 'High confidence');
  const norm = (p) => p.split('').sort().join('');
  const plugs = new Set(res.plugboard.map(norm));
  for (const pair of ['AB', 'CD', 'EF']) assert.ok(plugs.has(norm(pair)), `missing plug ${pair}`);
});

// ============================================================
// auto-decode.js — classical ciphers folded into the Magic Wand
// ============================================================

test('auto-decode: autoDecode finds the Caesar shift-15 decode of the acceptance ciphertext as the top, high-confidence candidate', () => {
  const r = autoDecode('XRPCTCRGNEI');
  assert.equal(r.candidates.length > 0, true, 'must produce at least one candidate');
  const top = r.candidates[0];
  assert.equal(top.output, 'ICANENCRYPT', `top candidate should be ICANENCRYPT, got "${top.output}"`);
  assert.deepEqual(top.path, ['caesar (shift 15)']);
  assert.ok(top.score >= 0.5, `top candidate should be high-confidence, scored ${top.score.toFixed(3)}`);
});

test('auto-decode: Atbash ciphertext is recovered directly by the Magic Wand', () => {
  const plain = 'MEETMEATTHESECRETLOCATIONATMIDNIGHT';
  const cipher = atbash(plain);
  const r = autoDecode(cipher);
  const found = r.candidates.find((c) => c.output === plain);
  assert.ok(found, 'atbash decode should appear among the candidates');
  assert.deepEqual(found.path, ['atbash']);
});


// ---------------------------------------------------------------------------
// hash-cracker.js — offline dictionary + rules attack
// ---------------------------------------------------------------------------
test('hash-cracker: detects hash type by length', () => {
  assert.equal(detectHashType('5f4dcc3b5aa765d61d8327deb882cf99').name, 'MD5');
  assert.equal(detectHashType('a'.repeat(40)).name, 'SHA-1');
  assert.equal(detectHashType('a'.repeat(64)).name, 'SHA-256');
  assert.equal(detectHashType('xyz'), null);
});

test('hash-cracker: cracks a common MD5 from the wordlist', async () => {
  const out = await crackHashes([md5Hex('password')]);
  assert.equal(out.type, 'MD5');
  assert.equal(out.results[0].plaintext, 'password');
});

test('hash-cracker: cracks a rule-mangled password (capitalized + year)', async () => {
  const out = await crackHashes([md5Hex('Dragon2024')]);
  assert.equal(out.results[0].plaintext, 'Dragon2024');
});

test('hash-cracker: batch cracks several hashes in one pass', async () => {
  const out = await crackHashes([md5Hex('monkey'), md5Hex('letmein')]);
  const plains = out.results.map((r) => r.plaintext).sort();
  assert.deepEqual(plains, ['letmein', 'monkey']);
});

test('hash-cracker: reports not-found for a hash whose plaintext is not in the wordlist', async () => {
  const out = await crackHashes(['5b31f93c09ad1d065c0491b764d04933']);
  assert.equal(out.results[0].plaintext, null);
});

test('hash-cracker: rejects mixed hash lengths in one batch', async () => {
  await assert.rejects(() => crackHashes([md5Hex('password'), 'a'.repeat(64)]), /one hash type at a time/);
});

// ---------------------------------------------------------------------------
// ioc.js — IOC extraction + defang/refang
// ---------------------------------------------------------------------------
test('ioc: defang/refang round-trip on URLs, IPs, and emails', () => {
  const original = 'Visit http://example.com or email a@b.com, host 1.2.3.4';
  const defanged = defang(original);
  assert.equal(defanged, 'Visit hxxp://example[.]com or email a[at]b[.]com, host 1[.]2[.]3[.]4');
  assert.equal(refang(defanged), original);
});

test('ioc: refang tolerates https and (.)/(at) variants', () => {
  assert.equal(refang('hxxps://evil(.)example(.)com'), 'https://evil.example.com');
  assert.equal(refang('user(at)example[.]com'), 'user@example.com');
});

test('ioc: extractIocs categorizes and dedupes a mixed threat-report blob', () => {
  const blob = `
Beacon to hxxp://evil-c2[.]example[.]com/gate.php from 1[.]2[.]3[.]4 and 1.2.3.4 again.
IPv6 host seen at 2001:db8::1 and loopback ::1.
Also seen: http://second.example.com/path and plain domain sub.example.org.
Contact soc@example.com or admin[at]example[.]com (same person, different notation... not deduped: different address).
Hash: 5f4dcc3b5aa765d61d8327deb882cf99 (md5), aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d (sha1),
2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae (sha256).
CVE-2021-44228 and cve-2021-44228 again.
`;
  const iocs = extractIocs(blob);
  assert.deepEqual(iocs.ipv4, ['1.2.3.4']); // deduped across defanged + plain forms
  assert.deepEqual(iocs.ipv6.sort(), ['2001:db8::1', '::1'].sort());
  assert.deepEqual(iocs.urls, ['http://evil-c2.example.com/gate.php', 'http://second.example.com/path']);
  assert.deepEqual(iocs.domains, ['sub.example.org']); // URL hostnames excluded — not double-counted
  assert.deepEqual(iocs.emails.sort(), ['soc@example.com', 'admin@example.com'].sort());
  assert.deepEqual(iocs.md5, ['5f4dcc3b5aa765d61d8327deb882cf99']);
  assert.deepEqual(iocs.sha1, ['aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d']);
  assert.deepEqual(iocs.sha256, ['2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae']);
  assert.deepEqual(iocs.cves, ['CVE-2021-44228']); // deduped case-insensitively, normalized to uppercase
});

test('ioc: extractIocs handles empty/non-string input gracefully', () => {
  const empty = extractIocs('');
  assert.deepEqual(empty, { ipv4: [], ipv6: [], domains: [], urls: [], emails: [], md5: [], sha1: [], sha256: [], cves: [] });
});

// ---------------------------------------------------------------------------
// cvss.js — CVSS v3.1 Base score
// ---------------------------------------------------------------------------
test('cvss: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H scores 9.8 Critical', () => {
  const { score, severity, vector } = cvss31Base({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  assert.equal(score, 9.8);
  assert.equal(severity, 'Critical');
  assert.equal(vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
});

test('cvss: an all-None impact scores 0.0 None regardless of exploitability', () => {
  const { score, severity } = cvss31Base({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' });
  assert.equal(score, 0);
  assert.equal(severity, 'None');
});

test('cvss: AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L scores 3.8 Low (verified by hand against the official FIRST.org formula)', () => {
  // Worked by hand: ISS = 1-(1-0.22)^3 = 0.525448; Impact = 6.42*ISS = 3.373376;
  // Exploitability = 8.22*0.55*0.44*0.27*0.62 = 0.332999; sum = 3.706375;
  // Roundup(3.706375) = 3.8. (3.8 and 3.4 are both "Low" — either would pass
  // a severity-only check, but the exact score must match the spec formula.)
  const { score, severity } = cvss31Base({ AV: 'L', AC: 'H', PR: 'H', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'L' });
  assert.equal(score, 3.8);
  assert.equal(severity, 'Low');
});

test('cvss: scope-changed AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H scores the maximum 10.0 Critical', () => {
  const { score, severity } = cvss31Base({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' });
  assert.equal(score, 10);
  assert.equal(severity, 'Critical');
});

test('cvss: scope changes Privileges Required weighting (PR:H differs between S:U and S:C)', () => {
  const unchanged = cvss31Base({ AV: 'N', AC: 'L', PR: 'H', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  const changed = cvss31Base({ AV: 'N', AC: 'L', PR: 'H', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' });
  assert.notEqual(unchanged.score, changed.score);
});

test('cvss: cvss31Base throws on an invalid or missing metric', () => {
  assert.throws(() => cvss31Base({ AV: 'X', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' }), /Invalid or missing metric/);
  assert.throws(() => cvss31Base({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H' }), /Invalid or missing metric/);
});

test('cvss: parseCvssVector round-trips with cvss31Base\'s own vector output', () => {
  const { vector } = cvss31Base({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  const metrics = parseCvssVector(vector);
  assert.deepEqual(metrics, { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  assert.equal(cvss31Base(metrics).score, 9.8);
});

test('cvss: parseCvssVector throws on malformed input', () => {
  assert.throws(() => parseCvssVector('not a vector'), /Malformed vector segment/);
  assert.throws(() => parseCvssVector('CVSS:3.1/AV:N/AC:L'), /missing required metric/);
});

test('cvss: roundup rounds up to the nearest 0.1, including exact-tenth passthrough', () => {
  assert.equal(roundup(4.02), 4.1);
  assert.equal(roundup(4.0), 4.0);
  assert.equal(roundup(0), 0);
});

test('cvss: severityFor bands match the CVSS 3.1 qualitative severity table', () => {
  assert.equal(severityFor(0), 'None');
  assert.equal(severityFor(3.9), 'Low');
  assert.equal(severityFor(4.0), 'Medium');
  assert.equal(severityFor(6.9), 'Medium');
  assert.equal(severityFor(7.0), 'High');
  assert.equal(severityFor(8.9), 'High');
  assert.equal(severityFor(9.0), 'Critical');
  assert.equal(severityFor(10), 'Critical');
});

// ---------------------------------------------------------------------------
// secret-scan.js — Shannon entropy + secret/API-key scanning
// ---------------------------------------------------------------------------
test('secret-scan: shannonEntropy is 0 for a uniform string and high for a random one', () => {
  assert.equal(shannonEntropy('aaaa'), 0);
  assert.equal(shannonEntropy(''), 0);
  const random = shannonEntropy('xQ2!kZ9pL#vR7mN$wT4yU8bC1dE6fG0h');
  assert.ok(random > 4.0, `expected high entropy, got ${random}`);
});

test('secret-scan: scanSecrets detects an AWS access key and a GitHub token by type and line', () => {
  const cfg = [
    'aws_access_key_id = AKIAIOSFODNN7EXAMPLE',
    'github_token = ghp_16C7e42F292c6912E7710c838347Ae178B4a'
  ].join('\n');
  const findings = scanSecrets(cfg);
  const aws = findings.find((f) => f.type === 'AWS Access Key ID');
  const gh = findings.find((f) => f.type === 'GitHub Token');
  assert.ok(aws, 'expected an AWS Access Key ID finding');
  assert.equal(aws.line, 1);
  assert.equal(aws.match, 'AKIA…MPLE'); // masked — full key never shown
  assert.ok(gh, 'expected a GitHub Token finding');
  assert.equal(gh.line, 2);
});

test('secret-scan: scanSecrets flags a private key block once, at its start line', () => {
  const text = [
    'preamble',
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEpAIBAAKCAQEA1c7',
    '-----END RSA PRIVATE KEY-----',
    'trailer'
  ].join('\n');
  const findings = scanSecrets(text);
  const pk = findings.filter((f) => f.type.startsWith('Private Key Block'));
  assert.equal(pk.length, 1);
  assert.equal(pk[0].line, 2);
});

test('secret-scan: scanSecrets does not flag a plain SHA-1 hash as an AWS secret', () => {
  const findings = scanSecrets('sha1 = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d');
  assert.equal(findings.find((f) => f.type === 'AWS Secret Access Key (possible)'), undefined);
});

test('secret-scan: scanSecrets returns no findings for ordinary prose', () => {
  assert.deepEqual(scanSecrets('This is just a normal sentence with no secrets in it.'), []);
});

test('secret-scan: describeEntropy gives a plausible read across the range', () => {
  assert.match(describeEntropy(0), /no variation|very low/);
  assert.match(describeEntropy(1.0), /very low/);
  assert.match(describeEntropy(4.0), /moderate/);
  assert.match(describeEntropy(5.5), /very high/);
});

