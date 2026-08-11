/**
 * Enigma AUTO-BREAK — keyless cryptanalysis that recovers Enigma settings from
 * ciphertext ALONE (no known key), then returns the decrypted plaintext.
 *
 * This is the companion to the settings-based simulator in enigma.js. It does
 * NOT reimplement any Enigma wiring — it uses `enigmaProcess()` as its
 * decryption primitive and drives a fitness-guided search over the key space,
 * exactly as a modern ciphertext-only Enigma attack does (the software
 * descendant of Turing's Bombe / Gillogly's 1995 IoC + hill-climb method):
 *
 *   Phase 1 — rotor order + start positions.
 *     For every ordered choice of 3 rotors from the available set, for every
 *     reflector, and for all 26^3 window start positions, decrypt with an
 *     EMPTY plugboard and default rings and score with the Index of
 *     Coincidence. The plugboard is a pure transposition that barely moves IoC,
 *     so the correct rotor wheel-order and start positions rise to the top of
 *     the IoC ranking even while the plugboard is still unknown. Keep the top-N.
 *
 *   Phase 2 — ring settings (Ringstellung).
 *     For the surviving candidates, locally optimise the right then middle ring
 *     by quadgram-style English fitness. Rings only shift stepping/substitution
 *     timing, so a small local search recovers a non-default ring when the
 *     signal supports it; a strict-improvement gate means a correct default-ring
 *     solution is never degraded.
 *
 *   Phase 3 — plugboard (Steckerbrett) hill-climb.
 *     Starting from an empty board, greedily add the single plug pair that most
 *     improves English fitness (swapping out any conflicting existing plug),
 *     iterating until no pair improves or the 10-pair cap is reached — the
 *     standard plugboard hill-climb.
 *
 * The winner across candidates (by final English fitness) yields the recovered
 * rotor order, ring settings, start positions, plugboard, the decrypted
 * plaintext, and confidence signals (English fitness + IoC).
 *
 * ---- Scope / limits (documented on purpose, surfaced in the UI) ----
 *   • Rotors modelled: Wehrmacht Enigma I / M3, wheels I–V, reflectors B and C
 *     (whatever enigma.js exposes) — the classic 3-rotor machine. Naval M4 (4th
 *     rotor / thin reflectors) and rotors VI–VIII (double-notch) are not modelled.
 *   • Ciphertext-only recovery of a NON-default Ringstellung is genuinely hard
 *     and only best-effort here; recovery is most reliable when the message is
 *     long (≳ 120–150 letters) and the rings are at/near default. This mirrors
 *     the real difficulty — it is why the historical attack needed cribs and
 *     hardware, not a limitation we could simply engineer away.
 *   • Cost is dominated by Phase 1: |reflectors| × P(rotorSet,3) × 26^3 decrypts.
 *     For the full 5-rotor set and both reflectors that is ~2.1M short-prefix
 *     decrypts. See enigmaAutoBreakCost() and the `probeLen` / `rotorSet` /
 *     `reflectors` options for bounding it; run it in a Web Worker in-browser so
 *     the tab stays responsive.
 */

import { enigmaProcess, ENIGMA_ROTOR_NAMES, ENIGMA_REFLECTOR_NAMES } from './enigma.js';
import { indexOfCoincidence, scoreEnglish, lettersOnly } from './english-fitness.js';

const A_CODE = 65;
const idxToLetter = (i) => String.fromCharCode(A_CODE + (((i % 26) + 26) % 26));

/** All ordered selections of 3 distinct rotors from `rotorSet` (P(n,3)). */
export function rotorOrderings(rotorSet) {
  const out = [];
  for (const a of rotorSet) {
    for (const b of rotorSet) {
      if (b === a) continue;
      for (const c of rotorSet) {
        if (c === a || c === b) continue;
        out.push([a, b, c]);
      }
    }
  }
  return out;
}

/**
 * Rough cost of a run, so the UI (and tests) can warn/bound before launching a
 * search that would freeze a tab. Returns the number of Phase-1 decrypts and
 * the probe length actually used.
 */
export function enigmaAutoBreakCost(ciphertext, options = {}) {
  const {
    rotorSet = ENIGMA_ROTOR_NAMES,
    reflectors = ENIGMA_REFLECTOR_NAMES,
    probeLen = 200
  } = options;
  const cleanedLen = lettersOnly(ciphertext).length;
  const probe = probeLen > 0 ? Math.min(probeLen, cleanedLen) : cleanedLen;
  const orderings = rotorOrderings(rotorSet).length;
  const phase1Decrypts = reflectors.length * orderings * 26 * 26 * 26;
  return { phase1Decrypts, orderings, probeChars: probe, cleanedLen };
}

// Maintain a fixed-size max-by-`ic` shortlist without sorting a million rows.
function pushTopN(list, item, topN) {
  if (list.length < topN) {
    list.push(item);
    return;
  }
  let minIdx = 0;
  for (let i = 1; i < list.length; i++) {
    if (list[i].ic < list[minIdx].ic) minIdx = i;
  }
  if (item.ic > list[minIdx].ic) list[minIdx] = item;
}

/**
 * Plugboard (Steckerbrett) hill-climb. Returns { plugboard: ["AB",...], score }.
 * `fitnessFn` maps a decrypted string to a number (higher = more English).
 *
 * Two phases:
 *   A. Additive grow — repeatedly add the single best fitness-improving plug
 *      pair, until no pair improves or the maxPlugs cap is reached. This is the
 *      classic greedy Steckerbrett climb and, crucially, is conservative: it
 *      never adds a plug that does not improve fitness, so it does not over-fit
 *      spurious steckers the way an add/remove/reseat sweep does on shorter
 *      ciphertext.
 *   B. Fixed-count repair — for each recovered plug, try re-pairing one of its
 *      two letters with a currently-UNPLUGGED letter (keeping the total plug
 *      COUNT constant), accepting any strict improvement, sweeping until stable.
 *      This corrects a "near-miss" partner the greedy phase locked in early
 *      (e.g. C↔U where C↔D was correct) WITHOUT introducing new plugs — so it
 *      only ever helps. When the greedy solution is already optimal (the common
 *      case on adequately long text) this phase is a no-op.
 *
 * Note: at very short lengths (≲120 letters) the English fitness signal itself
 * cannot always separate the correct partner from a near neighbour, so a
 * near-miss plug can survive both phases — a fundamental signal limit of a
 * short ciphertext, documented at the top of this file, not a search bug.
 */
export function hillClimbPlugboard(letters, baseSettings, fitnessFn, maxPlugs = 10) {
  const score = (pp) => fitnessFn(enigmaProcess(letters, { ...baseSettings, plugboard: pp }));
  let plugs = [];
  let current = score(plugs);

  // ---- Phase A: additive grow. ----
  let improved = true;
  while (improved && plugs.length < maxPlugs) {
    improved = false;
    let bestScore = current;
    let bestPlugs = null;
    for (let i = 0; i < 26; i++) {
      const a = idxToLetter(i);
      for (let j = i + 1; j < 26; j++) {
        const b = idxToLetter(j);
        const trial = plugs.filter((p) => !p.includes(a) && !p.includes(b));
        trial.push(a + b);
        const s = score(trial);
        if (s > bestScore + 1e-9) {
          bestScore = s;
          bestPlugs = trial;
        }
      }
    }
    if (bestPlugs) {
      plugs = bestPlugs;
      current = bestScore;
      improved = true;
    }
  }

  // ---- Phase B: fixed-count repair (re-pair to an unplugged letter). ----
  let changed = true;
  while (changed) {
    changed = false;
    for (const pair of plugs.slice()) {
      const [x, y] = pair.split('');
      let bestScore = current;
      let bestPlugs = null;
      for (const keep of [x, y]) {
        for (let k = 0; k < 26; k++) {
          const z = idxToLetter(k);
          if (z === x || z === y) continue;
          if (plugs.some((p) => p.includes(z))) continue; // z must be unplugged
          const trial = plugs.filter((p) => p !== pair);
          trial.push(keep + z);
          const s = score(trial);
          if (s > bestScore + 1e-9) {
            bestScore = s;
            bestPlugs = trial;
          }
        }
      }
      if (bestPlugs) {
        plugs = bestPlugs;
        current = bestScore;
        changed = true;
      }
    }
  }

  return { plugboard: plugs, score: current };
}

/**
 * Local ring-setting optimisation over the right then middle wheel. Returns
 * { ringSettings: [L,M,R], score }. Strict-improvement gated so a correct
 * default-ring candidate is never made worse.
 */
export function optimizeRings(letters, baseSettings, fitnessFn) {
  let ringSettings = (baseSettings.ringSettings || ['A', 'A', 'A']).slice();
  let bestScore = fitnessFn(enigmaProcess(letters, { ...baseSettings, ringSettings }));

  for (const wheel of [2, 1]) { // right, then middle (left ring is inert for stepping)
    let localBest = ringSettings;
    let localScore = bestScore;
    for (let r = 0; r < 26; r++) {
      const trial = ringSettings.slice();
      trial[wheel] = idxToLetter(r);
      const s = fitnessFn(enigmaProcess(letters, { ...baseSettings, ringSettings: trial }));
      if (s > localScore + 1e-9) {
        localScore = s;
        localBest = trial;
      }
    }
    ringSettings = localBest;
    bestScore = localScore;
  }
  return { ringSettings, score: bestScore };
}

/**
 * Recover Enigma settings from ciphertext alone and return the decrypted
 * plaintext.
 *
 * @param {string} ciphertext
 * @param {object} [options]
 * @param {string[]} [options.rotorSet]   - wheels available to try (default I–V)
 * @param {string[]} [options.reflectors] - reflectors to try (default B, C)
 * @param {number}   [options.topN=8]     - Phase-1 shortlist size (by IoC)
 * @param {number}   [options.refineTop]  - how many shortlisted candidates get
 *                                          full ring+plugboard refinement
 *                                          (default min(topN,5))
 * @param {number}   [options.probeLen=200] - Phase-1 prefix length in letters
 *                                            (0 = use full text). Bounds cost.
 * @param {number}   [options.maxPlugs=10] - plugboard pair cap
 * @param {boolean}  [options.ringSearch=true]
 * @param {(p:{phase:number,done:number,total:number})=>void} [options.onProgress]
 * @returns {{
 *   rotors:string[], reflector:string, ringSettings:string[], positions:string[],
 *   plugboard:string[], plaintext:string, fitness:number, ic:number,
 *   confidence:number, confidenceLabel:string, candidates:Array
 * }}
 */
export function enigmaAutoBreak(ciphertext, options = {}) {
  const {
    rotorSet = ENIGMA_ROTOR_NAMES,
    reflectors = ENIGMA_REFLECTOR_NAMES,
    topN = 8,
    probeLen = 200,
    maxPlugs = 10,
    ringSearch = true,
    onProgress = null
  } = options;
  const refineTop = options.refineTop || Math.min(topN, 5);

  const cleaned = lettersOnly(ciphertext);
  if (cleaned.length < 8) {
    throw new Error(
      'Ciphertext too short to analyse — need at least ~8 letters, and realistically ' +
      '60+ (ideally 120+) for a reliable ciphertext-only Enigma break.'
    );
  }
  if (rotorSet.length < 3) {
    throw new Error('rotorSet must contain at least 3 rotor names to choose from.');
  }

  const probe = probeLen > 0 ? cleaned.slice(0, probeLen) : cleaned;
  const orderings = rotorOrderings(rotorSet);
  const total = reflectors.length * orderings.length * 26 * 26 * 26;

  // ---- Phase 1: rotor order + reflector + start positions, ranked by IoC. ----
  const shortlist = [];
  let done = 0;
  let sinceProgress = 0;
  for (const reflector of reflectors) {
    for (const rotors of orderings) {
      for (let p0 = 0; p0 < 26; p0++) {
        const l0 = idxToLetter(p0);
        for (let p1 = 0; p1 < 26; p1++) {
          const l1 = idxToLetter(p1);
          for (let p2 = 0; p2 < 26; p2++) {
            const positions = [l0, l1, idxToLetter(p2)];
            const dec = enigmaProcess(probe, { rotors, reflector, positions });
            const ic = indexOfCoincidence(dec);
            pushTopN(shortlist, { rotors, reflector, positions, ic }, topN);
            done++;
            if (onProgress && ++sinceProgress >= 20000) {
              sinceProgress = 0;
              onProgress({ phase: 1, done, total });
            }
          }
        }
      }
    }
  }
  if (onProgress) onProgress({ phase: 1, done, total });

  // Rank the shortlist by IoC (plugboard-insensitive) and refine the strongest.
  shortlist.sort((a, b) => b.ic - a.ic);
  const toRefine = shortlist.slice(0, refineTop);

  // ---- Phases 2 & 3 on the full text: rings, then plugboard hill-climb. ----
  const fitnessFn = (s) => scoreEnglish(s);
  const refined = [];
  let ri = 0;
  for (const cand of toRefine) {
    let ringSettings = ['A', 'A', 'A'];
    let base = { rotors: cand.rotors, reflector: cand.reflector, positions: cand.positions, ringSettings };

    if (ringSearch) {
      const rings = optimizeRings(cleaned, base, fitnessFn);
      ringSettings = rings.ringSettings;
      base = { ...base, ringSettings };
    }

    const plug = hillClimbPlugboard(cleaned, base, fitnessFn, maxPlugs);
    const settings = { ...base, plugboard: plug.plugboard };
    const plaintext = enigmaProcess(ciphertext, settings);
    refined.push({
      rotors: cand.rotors,
      reflector: cand.reflector,
      ringSettings,
      positions: cand.positions,
      plugboard: plug.plugboard,
      plaintext,
      fitness: plug.score,
      ic: indexOfCoincidence(lettersOnly(plaintext))
    });
    if (onProgress) onProgress({ phase: 3, done: ++ri, total: toRefine.length });
  }

  refined.sort((a, b) => b.fitness - a.fitness);
  const best = refined[0];

  const confidence = Math.max(0, Math.min(1, best.fitness));
  return {
    ...best,
    confidence,
    confidenceLabel: labelFor(confidence),
    candidates: refined
  };
}

function labelFor(fitness) {
  if (fitness >= 0.45) return 'High confidence';
  if (fitness >= 0.28) return 'Likely';
  if (fitness >= 0.15) return 'Weak signal';
  return 'No clear English';
}
