/**
 * Search helper over the static well-known-ports reference data.
 * Matches against port number, protocol, name, and description —
 * simple substring match, no fuzzy scoring needed at this data size.
 */

import { WELL_KNOWN_PORTS } from '../../data/well-known-ports.js';

export function searchPorts(query) {
  const q = (query || '').trim().toLowerCase();
  if (!q) return WELL_KNOWN_PORTS;
  return WELL_KNOWN_PORTS.filter(
    (p) =>
      String(p.port).includes(q) ||
      p.proto.toLowerCase().includes(q) ||
      p.name.toLowerCase().includes(q) ||
      p.desc.toLowerCase().includes(q)
  );
}

export { WELL_KNOWN_PORTS };
