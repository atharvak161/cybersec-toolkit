/**
 * v2 encodings: Base85 (Ascii85/Adobe variant), Base91 (basE91), UUEncode.
 * Pure, dependency-free.
 */

import { strToBytes, bytesToStr } from './encoding.js';

// ---------- Base85 (Ascii85, Adobe variant, '<~' '~>' delimiters optional) ----------

export function base85Encode(input, withDelimiters = false) {
  const bytes = typeof input === 'string' ? strToBytes(input) : new Uint8Array(input);
  let out = '';
  let i = 0;
  for (; i + 4 <= bytes.length; i += 4) {
    const n = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
    if (n === 0) {
      out += 'z';
      continue;
    }
    const chars = new Array(5);
    let val = n;
    for (let j = 4; j >= 0; j--) {
      chars[j] = String.fromCharCode((val % 85) + 33);
      val = Math.floor(val / 85);
    }
    out += chars.join('');
  }
  const remaining = bytes.length - i;
  if (remaining > 0) {
    const padded = new Uint8Array(4);
    for (let k = 0; k < remaining; k++) padded[k] = bytes[i + k];
    const n = ((padded[0] << 24) | (padded[1] << 16) | (padded[2] << 8) | padded[3]) >>> 0;
    const chars = new Array(5);
    let val = n;
    for (let j = 4; j >= 0; j--) {
      chars[j] = String.fromCharCode((val % 85) + 33);
      val = Math.floor(val / 85);
    }
    out += chars.slice(0, remaining + 1).join('');
  }
  return withDelimiters ? '<~' + out + '~>' : out;
}

export function base85Decode(input, asBytes = false) {
  let clean = input.trim();
  if (clean.startsWith('<~')) clean = clean.slice(2);
  if (clean.endsWith('~>')) clean = clean.slice(0, -2);
  clean = clean.replace(/\s+/g, '');

  const bytesOut = [];
  let i = 0;
  while (i < clean.length) {
    if (clean[i] === 'z') {
      bytesOut.push(0, 0, 0, 0);
      i++;
      continue;
    }
    let group = clean.slice(i, i + 5);
    const groupLen = group.length;
    if (groupLen < 5) {
      group = group.padEnd(5, 'u'); // 'u' = 84, max digit, standard padding approach
    }
    let n = 0;
    for (let j = 0; j < 5; j++) {
      const code = group.charCodeAt(j) - 33;
      if (code < 0 || code > 84) throw new Error('Invalid base85 character');
      n = n * 85 + code;
    }
    n = n >>> 0;
    const b = [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
    bytesOut.push(...b.slice(0, groupLen - 1));
    i += groupLen;
  }
  const bytes = new Uint8Array(bytesOut);
  return asBytes ? bytes : bytesToStr(bytes);
}

// ---------- Base91 (basE91) ----------

const B91_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' +
  '!#$%&()*+,./:;<=>?@[]^_`{|}~"';

export function base91Encode(input) {
  const bytes = typeof input === 'string' ? strToBytes(input) : new Uint8Array(input);
  let bitBuf = 0;
  let bitCount = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    bitBuf |= bytes[i] << bitCount;
    bitCount += 8;
    if (bitCount > 13) {
      let val = bitBuf & 8191;
      if (val > 88) {
        bitBuf >>= 13;
        bitCount -= 13;
      } else {
        val = bitBuf & 16383;
        bitBuf >>= 14;
        bitCount -= 14;
      }
      out += B91_ALPHABET[val % 91] + B91_ALPHABET[Math.floor(val / 91)];
    }
  }
  if (bitCount > 0) {
    out += B91_ALPHABET[bitBuf % 91];
    if (bitCount > 7 || bitBuf > 90) {
      out += B91_ALPHABET[Math.floor(bitBuf / 91)];
    }
  }
  return out;
}

export function base91Decode(input, asBytes = false) {
  const clean = input.trim();
  const lookup = {};
  for (let i = 0; i < B91_ALPHABET.length; i++) lookup[B91_ALPHABET[i]] = i;

  let bitBuf = 0;
  let bitCount = 0;
  let val = -1;
  const bytesOut = [];

  for (const ch of clean) {
    const d = lookup[ch];
    if (d === undefined) throw new Error('Invalid base91 character: ' + ch);
    if (val < 0) {
      val = d;
    } else {
      val += d * 91;
      bitBuf |= val << bitCount;
      bitCount += (val & 8191) > 88 ? 13 : 14;
      while (bitCount >= 8) {
        bytesOut.push(bitBuf & 0xff);
        bitBuf >>= 8;
        bitCount -= 8;
      }
      val = -1;
    }
  }
  if (val >= 0) {
    bitBuf |= val << bitCount;
    bitCount += 7;
  }
  while (bitCount >= 8) {
    bytesOut.push(bitBuf & 0xff);
    bitBuf >>= 8;
    bitCount -= 8;
  }

  const bytes = new Uint8Array(bytesOut);
  return asBytes ? bytes : bytesToStr(bytes);
}

// ---------- UUEncode ----------

function uuEncodeChar(n) {
  n &= 0x3f;
  return n === 0 ? '`' : String.fromCharCode(n + 32);
}

function uuDecodeChar(ch) {
  const c = ch.charCodeAt(0);
  if (ch === '`') return 0;
  return (c - 32) & 0x3f;
}

export function uuEncode(input, filename = 'data.txt', mode = '644') {
  const bytes = typeof input === 'string' ? strToBytes(input) : new Uint8Array(input);
  const lines = [`begin ${mode} ${filename}`];
  for (let i = 0; i < bytes.length; i += 45) {
    const chunk = bytes.slice(i, i + 45);
    let line = uuEncodeChar(chunk.length);
    for (let j = 0; j < chunk.length; j += 3) {
      const b0 = chunk[j] || 0;
      const b1 = chunk[j + 1] || 0;
      const b2 = chunk[j + 2] || 0;
      line += uuEncodeChar(b0 >> 2);
      line += uuEncodeChar(((b0 << 4) | (b1 >> 4)) & 0x3f);
      line += uuEncodeChar(((b1 << 2) | (b2 >> 6)) & 0x3f);
      line += uuEncodeChar(b2 & 0x3f);
    }
    lines.push(line);
  }
  lines.push('`');
  lines.push('end');
  return lines.join('\n');
}

export function uuDecode(input, asBytes = false) {
  const lines = input.split('\n').map((l) => l.replace(/\r$/, ''));
  const bytesOut = [];
  for (const line of lines) {
    if (line.startsWith('begin') || line.startsWith('end') || line.length === 0) continue;
    const declaredLen = uuDecodeChar(line[0]);
    if (declaredLen === 0) break;
    const dataChars = line.slice(1);
    const lineBytes = [];
    for (let j = 0; j + 4 <= dataChars.length; j += 4) {
      const c0 = uuDecodeChar(dataChars[j]);
      const c1 = uuDecodeChar(dataChars[j + 1]);
      const c2 = uuDecodeChar(dataChars[j + 2]);
      const c3 = uuDecodeChar(dataChars[j + 3]);
      lineBytes.push((c0 << 2) | (c1 >> 4));
      lineBytes.push(((c1 << 4) | (c2 >> 2)) & 0xff);
      lineBytes.push(((c2 << 6) | c3) & 0xff);
    }
    bytesOut.push(...lineBytes.slice(0, declaredLen));
  }
  const bytes = new Uint8Array(bytesOut);
  return asBytes ? bytes : bytesToStr(bytes);
}
