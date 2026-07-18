/**
 * Epoch / timestamp converter. Pure logic.
 */

export function epochSecondsToIso(seconds) {
  const n = Number(seconds);
  if (!Number.isFinite(n)) throw new Error('Invalid epoch seconds');
  return new Date(n * 1000).toISOString();
}

export function epochMillisToIso(millis) {
  const n = Number(millis);
  if (!Number.isFinite(n)) throw new Error('Invalid epoch millis');
  return new Date(n).toISOString();
}

export function isoToEpochSeconds(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) throw new Error('Invalid ISO date string');
  return Math.floor(t / 1000);
}

export function isoToEpochMillis(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) throw new Error('Invalid ISO date string');
  return t;
}

/** Best-effort auto-detect: treat as ms if it looks like 13 digits, seconds if ~10 digits. */
export function autoDetectEpoch(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) throw new Error('Invalid numeric timestamp');
  const digits = String(Math.trunc(Math.abs(n))).length;
  const unit = digits >= 12 ? 'milliseconds' : 'seconds';
  const iso = unit === 'milliseconds' ? epochMillisToIso(n) : epochSecondsToIso(n);
  return { unit, iso };
}
