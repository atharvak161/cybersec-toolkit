/**
 * CVSS v3.1 Base score — implements the official FIRST.org formula
 * exactly (metric weights, ISS, Impact/Exploitability sub-scores, the
 * scope-changed variants, and the spec's precision-safe "Roundup"
 * rounding, which is NOT plain Math.round to 1 decimal — see roundup()).
 * Reference: https://www.first.org/cvss/v3.1/specification-document
 */

const AV_WEIGHTS = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_WEIGHTS = { L: 0.77, H: 0.44 };
const PR_WEIGHTS_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PR_WEIGHTS_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };
const UI_WEIGHTS = { N: 0.85, R: 0.62 };
const CIA_WEIGHTS = { N: 0, L: 0.22, H: 0.56 };
const SCOPE_VALUES = ['U', 'C'];

const METRIC_ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
const METRIC_LABELS = {
  AV: 'Attack Vector', AC: 'Attack Complexity', PR: 'Privileges Required', UI: 'User Interaction',
  S: 'Scope', C: 'Confidentiality', I: 'Integrity', A: 'Availability'
};
const METRIC_VALUES = {
  AV: ['N', 'A', 'L', 'P'], AC: ['L', 'H'], PR: ['N', 'L', 'H'], UI: ['N', 'R'],
  S: ['U', 'C'], C: ['N', 'L', 'H'], I: ['N', 'L', 'H'], A: ['N', 'L', 'H']
};

/**
 * CVSS 3.1's "Roundup" function: rounds UP to the nearest 0.1, using
 * integer arithmetic (per the spec's reference pseudocode) to sidestep
 * IEEE-754 floating point edge cases that plain Math.ceil(x*10)/10 can
 * hit (e.g. 4.02 incorrectly bumping to 4.1 due to float imprecision).
 */
export function roundup(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function severityFor(score) {
  if (score <= 0) return 'None';
  if (score < 4.0) return 'Low';
  if (score < 7.0) return 'Medium';
  if (score < 9.0) return 'High';
  return 'Critical';
}

function validateMetrics(metrics) {
  for (const key of METRIC_ORDER) {
    const value = metrics[key];
    if (!value || !METRIC_VALUES[key].includes(value)) {
      throw new Error(`Invalid or missing metric ${key}: expected one of ${METRIC_VALUES[key].join('/')}, got "${value ?? ''}"`);
    }
  }
}

/**
 * Computes the CVSS 3.1 Base score for a full set of base metrics.
 * @param {{AV:string,AC:string,PR:string,UI:string,S:string,C:string,I:string,A:string}} metrics
 * @returns {{score:number, severity:string, vector:string}}
 */
export function cvss31Base(metrics) {
  validateMetrics(metrics);
  const { AV, AC, PR, UI, S, C, I, A } = metrics;
  const scopeChanged = S === 'C';

  const prWeights = scopeChanged ? PR_WEIGHTS_CHANGED : PR_WEIGHTS_UNCHANGED;
  const iss = 1 - (1 - CIA_WEIGHTS[C]) * (1 - CIA_WEIGHTS[I]) * (1 - CIA_WEIGHTS[A]);

  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;

  const exploitability = 8.22 * AV_WEIGHTS[AV] * AC_WEIGHTS[AC] * prWeights[PR] * UI_WEIGHTS[UI];

  let score;
  if (impact <= 0) {
    score = 0.0;
  } else {
    const raw = scopeChanged
      ? Math.min(1.08 * (impact + exploitability), 10)
      : Math.min(impact + exploitability, 10);
    score = roundup(raw);
  }

  const vector = `CVSS:3.1/${METRIC_ORDER.map((k) => `${k}:${metrics[k]}`).join('/')}`;
  return { score, severity: severityFor(score), vector };
}

/** Parses a "CVSS:3.1/AV:N/AC:L/…" vector string into a metrics object.
 * Throws on malformed segments or missing required metrics. */
export function parseCvssVector(str) {
  if (typeof str !== 'string' || !str.trim()) throw new Error('Vector string is required');
  const body = str.trim().replace(/^CVSS:3\.1\//i, '');
  const metrics = {};
  for (const segment of body.split('/').filter(Boolean)) {
    const [key, value] = segment.split(':');
    if (!key || !value) throw new Error(`Malformed vector segment: "${segment}"`);
    metrics[key] = value;
  }
  for (const key of METRIC_ORDER) {
    if (!metrics[key]) throw new Error(`Vector is missing required metric: ${METRIC_LABELS[key]} (${key})`);
  }
  return metrics;
}

export { METRIC_ORDER, METRIC_LABELS, METRIC_VALUES, SCOPE_VALUES };
