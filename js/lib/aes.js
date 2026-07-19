/**
 * AES-GCM encrypt/decrypt using the native Web Crypto API only — no
 * hand-rolled crypto. Key is derived from a user-supplied passphrase
 * via PBKDF2 (100,000 iterations, SHA-256), matching common practice
 * for passphrase-based symmetric encryption. A random salt and IV are
 * generated per encryption and packed alongside the ciphertext so
 * decryption only needs the passphrase.
 *
 * Output format (all packed into one base64 blob):
 *   [salt(16 bytes)][iv(12 bytes)][ciphertext+tag]
 */

const PBKDF2_ITERATIONS = 100000;
const SALT_LEN = 16;
const IV_LEN = 12;

function subtle() {
  return globalThis.crypto.subtle;
}

async function deriveKey(passphrase, salt) {
  const baseKey = await subtle().importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return subtle().deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function bytesToBase64(bytes) {
  let binStr = '';
  for (const b of bytes) binStr += String.fromCharCode(b);
  return typeof btoa === 'function' ? btoa(binStr) : Buffer.from(bytes).toString('base64');
}

function base64ToBytes(b64) {
  if (typeof atob === 'function') {
    const binStr = atob(b64);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
    return bytes;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

/**
 * Encrypt plaintext (string) with a passphrase. Returns a base64 blob
 * containing salt + iv + ciphertext.
 */
export async function aesEncrypt(plaintext, passphrase) {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(passphrase, salt);
  const ciphertextBuf = await subtle().encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  const packed = concatBytes(salt, iv, new Uint8Array(ciphertextBuf));
  return bytesToBase64(packed);
}

/**
 * Decrypt a base64 blob produced by aesEncrypt using the same
 * passphrase. Throws if the passphrase is wrong or data is corrupt
 * (GCM authentication tag will fail to verify).
 */
export async function aesDecrypt(blobBase64, passphrase) {
  const packed = base64ToBytes(blobBase64);
  if (packed.length < SALT_LEN + IV_LEN) throw new Error('Ciphertext blob too short / corrupt');
  const salt = packed.slice(0, SALT_LEN);
  const iv = packed.slice(SALT_LEN, SALT_LEN + IV_LEN);
  const ciphertext = packed.slice(SALT_LEN + IV_LEN);
  const key = await deriveKey(passphrase, salt);
  const plainBuf = await subtle().decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(plainBuf);
}

/**
 * File (byte-level) AES-GCM encryption — same PBKDF2 + AES-256-GCM
 * approach as aesEncrypt/aesDecrypt above, but operating on raw bytes
 * (an entire file) instead of a UTF-8 string, and returning the packed
 * [salt][iv][ciphertext+tag] blob as raw bytes rather than base64 (so a
 * downloaded ".enc" file isn't inflated ~33% for no reason). Used by the
 * File Encryption/Decryption tool.
 */
export async function aesEncryptBytes(plainBytes, passphrase) {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(passphrase, salt);
  const ciphertextBuf = await subtle().encrypt({ name: 'AES-GCM', iv }, key, plainBytes);
  return concatBytes(salt, iv, new Uint8Array(ciphertextBuf));
}

/**
 * Decrypt a byte blob produced by aesEncryptBytes using the same
 * passphrase. Throws if the passphrase is wrong or the data is corrupt.
 */
export async function aesDecryptBytes(packedBytes, passphrase) {
  const packed = packedBytes instanceof Uint8Array ? packedBytes : new Uint8Array(packedBytes);
  if (packed.length < SALT_LEN + IV_LEN) throw new Error('Encrypted file too short / corrupt');
  const salt = packed.slice(0, SALT_LEN);
  const iv = packed.slice(SALT_LEN, SALT_LEN + IV_LEN);
  const ciphertext = packed.slice(SALT_LEN + IV_LEN);
  const key = await deriveKey(passphrase, salt);
  const plainBuf = await subtle().decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new Uint8Array(plainBuf);
}
