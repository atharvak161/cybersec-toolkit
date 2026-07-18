/**
 * RSA keypair generation + encrypt/decrypt using the native Web Crypto
 * API only (RSA-OAEP, SHA-256). No hand-rolled crypto. Keys are
 * exported/imported as PEM (SPKI for public, PKCS8 for private) so
 * they can be copy-pasted in the UI.
 */

function subtle() {
  return globalThis.crypto.subtle;
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

function pemWrap(base64, label) {
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

function pemUnwrap(pem) {
  return pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');
}

/**
 * Generate an RSA-OAEP keypair. Returns { publicKeyPem, privateKeyPem }.
 * @param {number} modulusLength 2048 or 4096
 */
export async function generateRsaKeypair(modulusLength = 2048) {
  const keyPair = await subtle().generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );

  const spki = await subtle().exportKey('spki', keyPair.publicKey);
  const pkcs8 = await subtle().exportKey('pkcs8', keyPair.privateKey);

  return {
    publicKeyPem: pemWrap(bytesToBase64(new Uint8Array(spki)), 'PUBLIC KEY'),
    privateKeyPem: pemWrap(bytesToBase64(new Uint8Array(pkcs8)), 'PRIVATE KEY')
  };
}

async function importPublicKey(pem) {
  const der = base64ToBytes(pemUnwrap(pem));
  return subtle().importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

async function importPrivateKey(pem) {
  const der = base64ToBytes(pemUnwrap(pem));
  return subtle().importKey('pkcs8', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}

/** Encrypt plaintext (string, must fit RSA-OAEP max size for the key) with a PEM public key. Returns base64 ciphertext. */
export async function rsaEncrypt(plaintext, publicKeyPem) {
  const key = await importPublicKey(publicKeyPem);
  const ciphertextBuf = await subtle().encrypt({ name: 'RSA-OAEP' }, key, new TextEncoder().encode(plaintext));
  return bytesToBase64(new Uint8Array(ciphertextBuf));
}

/** Decrypt base64 ciphertext with a PEM private key. Returns plaintext string. */
export async function rsaDecrypt(ciphertextBase64, privateKeyPem) {
  const key = await importPrivateKey(privateKeyPem);
  const plainBuf = await subtle().decrypt({ name: 'RSA-OAEP' }, key, base64ToBytes(ciphertextBase64));
  return new TextDecoder().decode(plainBuf);
}
