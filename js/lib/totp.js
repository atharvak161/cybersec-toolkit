/**
 * TOTP — Time-based One-Time Password (RFC 6238), built on HOTP (RFC
 * 4226). Uses the native Web Crypto API for HMAC only — no hand-rolled
 * crypto. The moving factor (counter) is derived from wall-clock time,
 * matching the same algorithm authenticator apps (Google Authenticator,
 * Authy, etc.) implement.
 */

import { base32Decode } from './encoding.js';

function getSubtle() {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error('Web Crypto API (crypto.subtle) is not available in this environment');
  return subtle;
}

const HMAC_ALGOS = { 'SHA-1': 'SHA-1', 'SHA-256': 'SHA-256', 'SHA-512': 'SHA-512' };

function counterToBytes(counter) {
  // 8-byte big-endian counter, per RFC 4226 §5.2. JS numbers are safe
  // integers well beyond any realistic TOTP counter value (counters this
  // large would be ~2^33 * period seconds away — not a real concern).
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  const high = Math.floor(counter / 2 ** 32);
  const low = counter % 2 ** 32;
  view.setUint32(0, high);
  view.setUint32(4, low);
  return new Uint8Array(buf);
}

/**
 * HOTP: compute the one-time password for an explicit counter value.
 * @param {Uint8Array} keyBytes decoded shared secret
 * @param {number} counter moving factor
 * @param {number} digits number of output digits (default 6)
 * @param {string} algorithm 'SHA-1' | 'SHA-256' | 'SHA-512'
 */
export async function hotp(keyBytes, counter, digits = 6, algorithm = 'SHA-1') {
  const hashName = HMAC_ALGOS[algorithm];
  if (!hashName) throw new Error('Unsupported TOTP/HOTP algorithm: ' + algorithm);

  const key = await getSubtle().importKey('raw', keyBytes, { name: 'HMAC', hash: hashName }, false, ['sign']);
  const sigBuf = await getSubtle().sign('HMAC', key, counterToBytes(counter));
  const sig = new Uint8Array(sigBuf);

  // Dynamic truncation (RFC 4226 §5.3).
  const offset = sig[sig.length - 1] & 0x0f;
  const binCode =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);

  const code = (binCode % 10 ** digits).toString().padStart(digits, '0');
  return code;
}

/**
 * TOTP: compute the current time-based code from a Base32 shared secret.
 * @param {string} secretBase32 the shared secret, as shown by most 2FA setup screens
 * @param {{ period?: number, digits?: number, algorithm?: string, timestampMs?: number }} opts
 * @returns {{ code: string, counter: number, secondsRemaining: number, period: number }}
 */
export async function generateTotp(secretBase32, opts = {}) {
  const { period = 30, digits = 6, algorithm = 'SHA-1', timestampMs = Date.now() } = opts;
  const cleanSecret = secretBase32.trim().replace(/\s+/g, '').toUpperCase();
  if (!cleanSecret) throw new Error('Enter a Base32 secret');

  const keyBytes = base32Decode(cleanSecret, true);
  if (keyBytes.length === 0) throw new Error('Secret decoded to zero bytes — check the Base32 value');

  const timeSeconds = Math.floor(timestampMs / 1000);
  const counter = Math.floor(timeSeconds / period);
  const code = await hotp(keyBytes, counter, digits, algorithm);
  const secondsRemaining = period - (timeSeconds % period);

  return { code, counter, secondsRemaining, period };
}
