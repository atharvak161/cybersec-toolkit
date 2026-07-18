/**
 * CRC-32 checksum — hand-implemented reference version 1.0.
 *
 * Source: CRC-32/ISO-HDLC (the classic "zip"/Ethernet CRC-32), polynomial
 * 0xEDB88320 (reversed representation of 0x04C11DB7), a widely documented
 * public algorithm. See e.g. ITU-T V.42 / IEEE 802.3 Appendix.
 *
 * Provenance note: this file is NOT pulled from an external package/CDN.
 * It is a direct implementation of the standard reflected CRC-32 table
 * algorithm, validated against known vectors (e.g. crc32("") === 0,
 * crc32("123456789") === 0xCBF43926, the standard "check value" for
 * this CRC in the CRC RevEng catalogue) in test/run-tests.js.
 *
 * ES module. Exposes crc32Hex(input: string | Uint8Array): string
 */

let TABLE = null;

function buildTable() {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
}

/**
 * Compute the CRC-32 checksum of a string or byte array.
 * @param {string|Uint8Array} input
 * @returns {string} lowercase 8-hex-digit checksum
 */
export function crc32Hex(input) {
  if (!TABLE) TABLE = buildTable();
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) {
    crc = TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
  }
  crc = (crc ^ 0xFFFFFFFF) >>> 0;
  return crc.toString(16).padStart(8, '0');
}
