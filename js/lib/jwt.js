/**
 * JWT decoder/inspector. Decodes header + payload (does not require a
 * secret), flags alg:none and weak/none signing, and reports expiry
 * status. Optionally verifies an HS256/384/512 signature if the caller
 * supplies a secret (Web Crypto HMAC) — verification is opt-in and
 * never required, since this is a client-side inspection tool.
 */

function base64UrlDecodeToBytes(segment) {
  let clean = segment.replace(/-/g, '+').replace(/_/g, '/');
  while (clean.length % 4 !== 0) clean += '=';
  const binStr = typeof atob === 'function' ? atob(clean) : Buffer.from(clean, 'base64').toString('binary');
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
  return bytes;
}

function base64UrlDecodeToString(segment) {
  const bytes = base64UrlDecodeToBytes(segment);
  return new TextDecoder().decode(bytes);
}

export const WEAK_ALGS = ['none', 'HS256']; // HS256 flagged only as "verify secret strength", not inherently broken
export const NONE_ALGS = ['none', 'None', 'NONE'];

/**
 * Decode a JWT into header/payload objects plus metadata. Does not
 * verify the signature.
 * @param {string} token
 */
export function decodeJwt(token) {
  const parts = token.trim().split('.');
  if (parts.length < 2 || parts.length > 3) {
    throw new Error('Not a valid JWT (expected header.payload.signature)');
  }
  const [headerSeg, payloadSeg, sigSeg] = parts;

  let header, payload;
  try {
    header = JSON.parse(base64UrlDecodeToString(headerSeg));
  } catch {
    throw new Error('Invalid JWT header (not valid base64url JSON)');
  }
  try {
    payload = JSON.parse(base64UrlDecodeToString(payloadSeg));
  } catch {
    throw new Error('Invalid JWT payload (not valid base64url JSON)');
  }

  const warnings = [];
  if (NONE_ALGS.includes(header.alg)) {
    warnings.push('CRITICAL: alg is "none" — this token requires NO signature and must never be trusted for authentication.');
  }
  if (!sigSeg && header.alg && !NONE_ALGS.includes(header.alg)) {
    warnings.push('Token has no signature segment despite declaring alg=' + header.alg + '.');
  }

  let expiryStatus = 'no exp claim';
  if (typeof payload.exp === 'number') {
    const nowSec = Math.floor(Date.now() / 1000);
    expiryStatus = payload.exp < nowSec ? 'expired' : 'valid (not yet expired)';
    if (payload.exp < nowSec) warnings.push('Token is expired (exp=' + payload.exp + ').');
  }

  let notBeforeStatus = null;
  if (typeof payload.nbf === 'number') {
    const nowSec = Math.floor(Date.now() / 1000);
    notBeforeStatus = payload.nbf > nowSec ? 'not yet valid' : 'active';
  }

  return {
    header,
    payload,
    signaturePresent: Boolean(sigSeg) && sigSeg.length > 0,
    signatureRaw: sigSeg || '',
    expiryStatus,
    notBeforeStatus,
    warnings
  };
}

/**
 * Verify an HS256/HS384/HS512-signed JWT against a supplied secret
 * using Web Crypto HMAC. Returns boolean. Throws for other algs.
 */
export async function verifyHmacJwt(token, secret) {
  const parts = token.trim().split('.');
  if (parts.length !== 3) throw new Error('Not a valid signed JWT');
  const [headerSeg, payloadSeg, sigSeg] = parts;
  const header = JSON.parse(base64UrlDecodeToString(headerSeg));

  const hashMap = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };
  const hashName = hashMap[header.alg];
  if (!hashName) throw new Error('verifyHmacJwt only supports HS256/384/512, got ' + header.alg);

  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: hashName },
    false,
    ['sign']
  );
  const expectedSigBuf = await globalThis.crypto.subtle.sign('HMAC', key, new TextEncoder().encode(headerSeg + '.' + payloadSeg));
  const expectedSigBytes = new Uint8Array(expectedSigBuf);
  const actualSigBytes = base64UrlDecodeToBytes(sigSeg);

  if (expectedSigBytes.length !== actualSigBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < expectedSigBytes.length; i++) diff |= expectedSigBytes[i] ^ actualSigBytes[i];
  return diff === 0;
}
