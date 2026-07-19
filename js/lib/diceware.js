/**
 * Diceware passphrase generator. Selects words uniformly at random (via
 * crypto.getRandomValues, same rejection-sampling approach as
 * password-gen.js) from the vendored EFF Large Wordlist — no physical
 * dice, no CDN fetch, no Math.random.
 */

import { randomIndex } from './password-gen.js';
import { EFF_LARGE_WORDLIST } from '../../data/eff-large-wordlist.js';

/**
 * @param {{ wordCount?: number, separator?: string, capitalize?: boolean, includeNumber?: boolean }} opts
 * @returns {{ passphrase: string, words: string[], entropyBits: number }}
 */
export function generatePassphrase(opts = {}) {
  const { wordCount = 6, separator = '-', capitalize = false, includeNumber = false } = opts;
  if (!Number.isInteger(wordCount) || wordCount < 1) throw new Error('Word count must be a positive integer');

  const words = [];
  for (let i = 0; i < wordCount; i++) {
    let word = EFF_LARGE_WORDLIST[randomIndex(EFF_LARGE_WORDLIST.length)];
    if (capitalize) word = word[0].toUpperCase() + word.slice(1);
    words.push(word);
  }

  if (includeNumber) {
    const digit = randomIndex(10);
    const position = randomIndex(words.length);
    words[position] = words[position] + digit;
  }

  const entropyBitsPerWord = Math.log2(EFF_LARGE_WORDLIST.length);
  const entropyBits = Math.round(wordCount * entropyBitsPerWord * 10) / 10 + (includeNumber ? Math.round(Math.log2(10) * 10) / 10 : 0);

  return { passphrase: words.join(separator), words, entropyBits };
}

export const WORDLIST_SIZE = EFF_LARGE_WORDLIST.length;
