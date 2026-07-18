/**
 * Core text/byte encodings: Hex, Base64, Base32, Base58, URL, Binary,
 * ROT13/Caesar. Pure, dependency-free, works identically in browser and
 * Node. These are standard textbook encodings (not cryptography), so
 * hand-rolled implementations are appropriate here.
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function strToBytes(str) {
  return textEncoder.encode(str);
}

export function bytesToStr(bytes) {
  return textDecoder.decode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
}

// ---------- Hex ----------

export function hexEncode(input) {
  const bytes = typeof input === 'string' ? strToBytes(input) : new Uint8Array(input);
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function hexDecode(hex, asBytes = false) {
  const clean = hex.trim().replace(/\s+/g, '').replace(/^0x/i, '');
  if (clean.length % 2 !== 0) throw new Error('Hex string must have an even number of digits');
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('Invalid hex characters');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return asBytes ? bytes : bytesToStr(bytes);
}

// ---------- Base64 (standard, RFC 4648) ----------

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function base64Encode(input, urlSafe = false) {
  const bytes = typeof input === 'string' ? strToBytes(input) : new Uint8Array(input);
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : undefined;

    const c0 = b0 >> 2;
    const c1 = ((b0 & 0x03) << 4) | (b1 !== undefined ? (b1 >> 4) : 0);
    const c2 = b1 !== undefined ? (((b1 & 0x0f) << 2) | (b2 !== undefined ? (b2 >> 6) : 0)) : 64;
    const c3 = b2 !== undefined ? (b2 & 0x3f) : 64;

    out += B64_CHARS[c0] + B64_CHARS[c1] + (c2 === 64 ? '=' : B64_CHARS[c2]) + (c3 === 64 ? '=' : B64_CHARS[c3]);
  }
  if (urlSafe) out = out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return out;
}

export function base64Decode(input, asBytes = false) {
  let clean = input.trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  while (clean.length % 4 !== 0) clean += '=';
  if (!/^[A-Za-z0-9+/]*=*$/.test(clean)) throw new Error('Invalid base64 characters');

  const lookup = {};
  for (let i = 0; i < B64_CHARS.length; i++) lookup[B64_CHARS[i]] = i;

  const bytesOut = [];
  for (let i = 0; i < clean.length; i += 4) {
    const chars = clean.slice(i, i + 4);
    const pad = (chars.match(/=/g) || []).length;
    const vals = chars.split('').map((c) => (c === '=' ? 0 : lookup[c]));
    if (vals.some((v) => v === undefined)) throw new Error('Invalid base64 string');

    const n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
    bytesOut.push((n >> 16) & 0xff);
    if (pad < 2) bytesOut.push((n >> 8) & 0xff);
    if (pad < 1) bytesOut.push(n & 0xff);
  }
  const bytes = new Uint8Array(bytesOut);
  return asBytes ? bytes : bytesToStr(bytes);
}

// ---------- Base32 (RFC 4648) ----------

const B32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(input) {
  const bytes = typeof input === 'string' ? strToBytes(input) : new Uint8Array(input);
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += B32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += B32_CHARS[(value << (5 - bits)) & 31];
  }
  while (out.length % 8 !== 0) out += '=';
  return out;
}

export function base32Decode(input, asBytes = false) {
  const clean = input.trim().toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  const lookup = {};
  for (let i = 0; i < B32_CHARS.length; i++) lookup[B32_CHARS[i]] = i;

  let bits = 0;
  let value = 0;
  const bytesOut = [];
  for (const ch of clean) {
    const v = lookup[ch];
    if (v === undefined) throw new Error('Invalid base32 character: ' + ch);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bytesOut.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  const bytes = new Uint8Array(bytesOut);
  return asBytes ? bytes : bytesToStr(bytes);
}

// ---------- Base58 (Bitcoin alphabet) ----------

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(input) {
  const bytes = typeof input === 'string' ? strToBytes(input) : new Uint8Array(input);
  if (bytes.length === 0) return '';

  // Count leading zero bytes -> leading '1's
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Big-number base conversion (base256 -> base58) using arrays of digits
  const digits = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58_ALPHABET[digits[i]];
  return out;
}

export function base58Decode(input, asBytes = false) {
  const clean = input.trim();
  if (clean.length === 0) return asBytes ? new Uint8Array(0) : '';

  let zeros = 0;
  while (zeros < clean.length && clean[zeros] === '1') zeros++;

  const bytesArr = [0];
  for (let i = zeros; i < clean.length; i++) {
    const idx = B58_ALPHABET.indexOf(clean[i]);
    if (idx === -1) throw new Error('Invalid base58 character: ' + clean[i]);
    let carry = idx;
    for (let j = 0; j < bytesArr.length; j++) {
      carry += bytesArr[j] * 58;
      bytesArr[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytesArr.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + bytesArr.length);
  for (let i = 0; i < bytesArr.length; i++) out[zeros + bytesArr.length - 1 - i] = bytesArr[i];
  return asBytes ? out : bytesToStr(out);
}

// ---------- URL encoding ----------

export function urlEncode(str) {
  return encodeURIComponent(str);
}

export function urlDecode(str) {
  return decodeURIComponent(str);
}

// ---------- Binary (8-bit groups) ----------

export function binaryEncode(input) {
  const bytes = typeof input === 'string' ? strToBytes(input) : new Uint8Array(input);
  return Array.from(bytes).map((b) => b.toString(2).padStart(8, '0')).join(' ');
}

export function binaryDecode(input, asBytes = false) {
  const groups = input.trim().split(/\s+/).filter(Boolean);
  const bytes = new Uint8Array(groups.length);
  for (let i = 0; i < groups.length; i++) {
    if (!/^[01]{1,8}$/.test(groups[i])) throw new Error('Invalid binary group: ' + groups[i]);
    bytes[i] = parseInt(groups[i], 2);
  }
  return asBytes ? bytes : bytesToStr(bytes);
}

// ---------- ROT13 / Caesar cipher ----------

export function caesarShift(str, shift) {
  const n = ((shift % 26) + 26) % 26;
  return str.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + n) % 26) + base);
  });
}

export function rot13(str) {
  return caesarShift(str, 13);
}
