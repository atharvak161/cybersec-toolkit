/**
 * Dedicated high-volume coverage-guarantee stress test for the password
 * generator, matching (or exceeding) the scale QA used to catch the
 * bounce-cycle-2 "stomp" regression (500,000-trial Monte Carlo at length
 * 16, all 4 sets).
 *
 * Not part of the default `npm test` run — at these trial counts this adds
 * several seconds, which is disproportionate to run on every default test
 * invocation. `npm test` runs a fast 10,000-trial version of this same
 * check (see test/run-tests.js, "coverage guarantee holds across
 * length/charset combinations"). This script is the full-scale version;
 * run it explicitly whenever the coverage-guarantee logic in
 * js/lib/password-gen.js changes:
 *
 *   node test/password-gen-coverage-stress.mjs
 *
 * Exits non-zero on any coverage failure.
 */

import { generatePassword } from '../js/lib/password-gen.js';

const sets = {
  upper: /[A-Z]/, lower: /[a-z]/, digits: /[0-9]/,
  symbols: /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/
};

function runBatch(label, length, trials) {
  let failures = 0;
  for (let i = 0; i < trials; i++) {
    const pwd = generatePassword({ length });
    for (const [name, re] of Object.entries(sets)) {
      if (!re.test(pwd)) {
        failures++;
        if (failures <= 5) {
          console.error(`  FAIL [${label}] trial ${i}: "${pwd}" missing required set "${name}"`);
        }
        break;
      }
    }
  }
  console.log(`[${label}] length=${length} trials=${trials} failures=${failures}`);
  return failures;
}

console.log('Running password-gen coverage-guarantee stress test (all 4 sets selected)...');
let totalFailures = 0;
totalFailures += runBatch('length-16', 16, 500000);
totalFailures += runBatch('length-8-tighter', 8, 200000);
totalFailures += runBatch('length-4-tightest', 4, 200000);

console.log(`\nTotal trials: 900000, total failures: ${totalFailures}`);
if (totalFailures > 0) {
  console.error('COVERAGE GUARANTEE REGRESSION DETECTED.');
  process.exit(1);
} else {
  console.log('PASS: zero coverage failures.');
}
