/**
 * Recipe chaining engine — the CyberChef-lite "standout feature". Lets
 * the user pipe multiple operations together in sequence, each step's
 * output feeding the next step's input. Supports async steps (hashing,
 * AES/RSA use Web Crypto, which is promise-based).
 *
 * An "operation" is { id, name, category, run(input, params) } where
 * run may return a value or a Promise. `params` is a plain object of
 * the operation's configurable arguments (e.g. Caesar shift amount).
 *
 * Recipe export/import: a recipe (list of {opId, params}) can be
 * serialized to a compact JSON blob, then base64url-encoded so it can
 * be carried in a URL query parameter or shared as plain JSON.
 */

import * as enc from './encoding.js';
import * as encExtra from './encoding-extra.js';
import * as hashing from './hashing.js';
import { rot13, caesarShift } from './encoding.js';

export const OPERATIONS = [
  { id: 'to-hex', name: 'To Hex', category: 'Encoding', run: (input) => enc.hexEncode(input) },
  { id: 'from-hex', name: 'From Hex', category: 'Encoding', run: (input) => enc.hexDecode(input) },
  { id: 'to-base64', name: 'To Base64', category: 'Encoding', run: (input) => enc.base64Encode(input) },
  { id: 'from-base64', name: 'From Base64', category: 'Encoding', run: (input) => enc.base64Decode(input) },
  { id: 'to-base32', name: 'To Base32', category: 'Encoding', run: (input) => enc.base32Encode(input) },
  { id: 'from-base32', name: 'From Base32', category: 'Encoding', run: (input) => enc.base32Decode(input) },
  { id: 'to-base58', name: 'To Base58', category: 'Encoding', run: (input) => enc.base58Encode(input) },
  { id: 'from-base58', name: 'From Base58', category: 'Encoding', run: (input) => enc.base58Decode(input) },
  { id: 'to-base85', name: 'To Base85', category: 'Encoding', run: (input) => encExtra.base85Encode(input) },
  { id: 'from-base85', name: 'From Base85', category: 'Encoding', run: (input) => encExtra.base85Decode(input) },
  { id: 'to-base91', name: 'To Base91', category: 'Encoding', run: (input) => encExtra.base91Encode(input) },
  { id: 'from-base91', name: 'From Base91', category: 'Encoding', run: (input) => encExtra.base91Decode(input) },
  { id: 'url-encode', name: 'URL Encode', category: 'Encoding', run: (input) => enc.urlEncode(input) },
  { id: 'url-decode', name: 'URL Decode', category: 'Encoding', run: (input) => enc.urlDecode(input) },
  { id: 'to-binary', name: 'To Binary', category: 'Encoding', run: (input) => enc.binaryEncode(input) },
  { id: 'from-binary', name: 'From Binary', category: 'Encoding', run: (input) => enc.binaryDecode(input) },
  {
    id: 'rot13',
    name: 'ROT13',
    category: 'Encoding',
    run: (input) => rot13(input)
  },
  {
    id: 'caesar',
    name: 'Caesar Cipher',
    category: 'Encoding',
    params: { shift: 3 },
    run: (input, params = {}) => caesarShift(input, params.shift ?? 3)
  },
  { id: 'md5', name: 'MD5', category: 'Hashing', run: (input) => hashing.md5Hex(input) },
  { id: 'sha1', name: 'SHA-1', category: 'Hashing', run: (input) => hashing.sha1Hex(input) },
  { id: 'sha256', name: 'SHA-256', category: 'Hashing', run: (input) => hashing.sha256Hex(input) },
  { id: 'sha512', name: 'SHA-512', category: 'Hashing', run: (input) => hashing.sha512Hex(input) },
  { id: 'sha3-256', name: 'SHA3-256', category: 'Hashing', run: (input) => hashing.sha3_256Hex(input) },
  { id: 'crc32', name: 'CRC32', category: 'Hashing', run: (input) => hashing.crc32Hex(input) },
  { id: 'uppercase', name: 'To Uppercase', category: 'Misc', run: (input) => input.toUpperCase() },
  { id: 'lowercase', name: 'To Lowercase', category: 'Misc', run: (input) => input.toLowerCase() },
  { id: 'reverse', name: 'Reverse', category: 'Misc', run: (input) => input.split('').reverse().join('') },
  { id: 'trim', name: 'Trim Whitespace', category: 'Misc', run: (input) => input.trim() }
];

export function getOperation(id) {
  const op = OPERATIONS.find((o) => o.id === id);
  if (!op) throw new Error('Unknown recipe operation: ' + id);
  return op;
}

/**
 * Run a recipe: an array of { opId, params } steps, piping output to
 * input sequentially. Returns the final output plus a per-step trace
 * (each step's output and any error).
 * @param {{opId: string, params?: object}[]} steps
 * @param {string} initialInput
 */
export async function runRecipe(steps, initialInput) {
  let current = initialInput;
  const trace = [];
  for (const step of steps) {
    const op = getOperation(step.opId);
    try {
      current = await op.run(current, step.params || {});
      trace.push({ opId: step.opId, output: current, error: null });
    } catch (err) {
      trace.push({ opId: step.opId, output: current, error: err.message });
      throw Object.assign(new Error(`Step "${op.name}" failed: ${err.message}`), { trace });
    }
  }
  return { output: current, trace };
}

// ---------- Recipe export/import ----------

function toBase64Url(str) {
  const bytes = new TextEncoder().encode(str);
  return enc.base64Encode(bytes, true);
}

function fromBase64Url(str) {
  const bytes = enc.base64Decode(str, true);
  return new TextDecoder().decode(bytes);
}

/** Serialize a recipe (steps array) to a compact base64url string. */
export function exportRecipe(steps) {
  return toBase64Url(JSON.stringify(steps));
}

/** Parse a recipe previously produced by exportRecipe(). */
export function importRecipe(serialized) {
  const parsed = JSON.parse(fromBase64Url(serialized));
  if (!Array.isArray(parsed)) throw new Error('Invalid recipe: expected an array of steps');
  for (const step of parsed) {
    if (typeof step.opId !== 'string') throw new Error('Invalid recipe step: missing opId');
  }
  return parsed;
}

/** Build a full shareable URL (given a base page URL) embedding the recipe as a query param. */
export function buildShareableUrl(baseUrl, steps, input = '') {
  const url = new URL(baseUrl);
  url.searchParams.set('recipe', exportRecipe(steps));
  if (input) url.searchParams.set('input', toBase64Url(input));
  return url.toString();
}

/** Parse a shareable URL's query params back into { steps, input }. */
export function parseShareableUrl(urlStr) {
  const url = new URL(urlStr);
  const recipeParam = url.searchParams.get('recipe');
  const inputParam = url.searchParams.get('input');
  return {
    steps: recipeParam ? importRecipe(recipeParam) : [],
    input: inputParam ? fromBase64Url(inputParam) : ''
  };
}
