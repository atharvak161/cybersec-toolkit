/**
 * Base64 / data-URI image previewer — pure parsing logic (no DOM). Given
 * either a full `data:<mime>;base64,<payload>` URI or a raw base64
 * blob, decodes it to bytes and identifies the real file type via the
 * existing magic-bytes signatures rather than trusting a declared MIME
 * type. The UI layer turns the returned bytes into a Blob/object URL to
 * actually render the <img>.
 */

import { base64Decode } from './encoding.js';
import { identifyFileType } from './magic-bytes.js';

const DATA_URI_RE = /^data:([^;,]+)?(;charset=[^;,]+)?(;base64)?,(.*)$/s;

/**
 * @param {string} input
 * @returns {{ bytes: Uint8Array, declaredMime: string|null, detected: {type:string, mime:string}|null, sizeBytes: number }}
 */
export function parseBase64Image(input) {
  const trimmed = (input || '').trim();
  if (!trimmed) throw new Error('Paste a base64 string or data URI first');

  let declaredMime = null;
  let payload = trimmed;

  const match = DATA_URI_RE.exec(trimmed);
  if (match) {
    const [, mime, , isBase64, data] = match;
    if (!isBase64) throw new Error('Only base64-encoded data URIs are supported (missing ";base64" marker)');
    declaredMime = mime || null;
    payload = data;
  }

  // Strip incidental whitespace/newlines some sources wrap base64 with.
  const cleanPayload = payload.replace(/\s+/g, '');
  let bytes;
  try {
    bytes = base64Decode(cleanPayload, true);
  } catch (err) {
    throw new Error('Could not decode as base64: ' + err.message);
  }
  if (bytes.length === 0) throw new Error('Decoded to zero bytes — check the input');

  const detected = identifyFileType(bytes.slice(0, 32));
  if (!detected || !/image/i.test(detected.mime)) {
    // Not a fatal error — still let the caller decide whether to attempt
    // rendering (e.g. using the declared mime), but flag it clearly.
    return { bytes, declaredMime, detected, sizeBytes: bytes.length, looksLikeImage: false };
  }
  return { bytes, declaredMime, detected, sizeBytes: bytes.length, looksLikeImage: true };
}
