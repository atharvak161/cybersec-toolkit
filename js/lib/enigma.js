/**
 * Enigma machine SIMULATOR — historically accurate rotor wiring, reflectors,
 * ring settings, initial positions, and a plugboard. This is a SETTINGS-BASED
 * simulator: given a known configuration it encrypts/decrypts text exactly
 * like a real M3/Wehrmacht Enigma. It does NOT attempt to recover an unknown
 * configuration (that is the Bombe / modern cryptanalytic attack, a
 * fundamentally different and vastly more involved problem — out of scope
 * here, and noted as such in the UI).
 *
 * Because of how the signal path works (through the plugboard, through the
 * rotors right-to-left, through the reflector, back through the rotors
 * left-to-right, back through the plugboard), Enigma is its OWN INVERSE for
 * a given machine configuration: encrypting and decrypting are the exact
 * same operation. enigmaProcess() is therefore used for both directions.
 *
 * Only A-Z letters pass through the rotor/plugboard/reflector signal path
 * (this mirrors the real machine, which only had letter keys). Any other
 * character (spaces, digits, punctuation) is passed through UNCHANGED and
 * does NOT advance the rotors — documented here explicitly per the task
 * spec's instruction to make this choice and state it.
 */

// Historical rotor wirings (Wehrmacht Enigma I / M3 rotors I-V). Each string
// is the substitution alphabet: wiring[i] is the letter that rotor contact i
// (0=A) connects to on the wired side, in the rotor's OWN reference frame.
// notch is the letter at which, when it is the LETTER SHOWING in the window
// (i.e. this rotor is at that position when about to step), the NEXT rotor
// to its left steps too (matches the historical single/double-notch points
// for rotors I-V; VI-VIII had two notches and are not modeled — not needed
// for I-V, which is what every classic worked Enigma example uses).
const ROTORS = {
  I: { wiring: 'EKMFLGDQVZNTOWYHXUSPAIBRCJ', notch: 'Q' },
  II: { wiring: 'AJDKSIRUXBLHWTMCQGZNPYFVOE', notch: 'E' },
  III: { wiring: 'BDFHJLCPRTXVZNYEIWGAKMUSQO', notch: 'V' },
  IV: { wiring: 'ESOVPZJAYQUIRHXLNFTGKDCMWB', notch: 'J' },
  V: { wiring: 'VZBRGITYUPSDNHLXAWMJQOFECK', notch: 'Z' }
};

// Historical reflector wirings (B and C — the two in common historical use).
const REFLECTORS = {
  B: 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
  C: 'FVPJIAOYEDRZXWGCTKUQSBNMHL'
};

const A_CODE = 65;

function letterToIndex(ch) {
  return ch.charCodeAt(0) - A_CODE;
}
function indexToLetter(i) {
  return String.fromCharCode(A_CODE + ((i % 26) + 26) % 26);
}

/**
 * Builds a live rotor state: wiring/notch plus mutable position, from a
 * rotor NAME, its ring setting (Ringstellung, 'A'-'Z' or 1-26), and its
 * initial position (Grundstellung, 'A'-'Z').
 */
function buildRotor(name, ringSetting, position) {
  const def = ROTORS[name];
  if (!def) throw new Error(`Unknown rotor: ${name}. Valid rotors: ${Object.keys(ROTORS).join(', ')}`);
  const ring = normalizeLetterSetting(ringSetting, 'ring setting');
  const pos = normalizeLetterSetting(position, 'initial position');
  return {
    name,
    wiring: def.wiring,
    notch: letterToIndex(def.notch),
    ring: letterToIndex(ring),
    position: letterToIndex(pos)
  };
}

function normalizeLetterSetting(value, label) {
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 1 || value > 26) {
      throw new Error(`Invalid ${label}: ${value} (expected 1-26 or a single letter A-Z)`);
    }
    return String.fromCharCode(A_CODE + value - 1);
  }
  const s = String(value).trim().toUpperCase();
  if (!/^[A-Z]$/.test(s)) throw new Error(`Invalid ${label}: "${value}" (expected a single letter A-Z)`);
  return s;
}

/**
 * Parses a plugboard spec into a lookup map. Accepts an array of 2-letter
 * pair strings (["AB", "CD"]) or a single space-separated string
 * ("AB CD EF"). Each letter may appear in at most one pair (Steckerbrett
 * constraint on a real machine).
 */
function buildPlugboard(spec) {
  const map = {};
  if (!spec) return map;
  const pairs = Array.isArray(spec)
    ? spec
    : String(spec).trim().split(/\s+/).filter(Boolean);
  for (const pair of pairs) {
    const p = pair.toUpperCase();
    if (!/^[A-Z]{2}$/.test(p)) {
      throw new Error(`Invalid plugboard pair: "${pair}" (expected two letters, e.g. "AB")`);
    }
    const [a, b] = p.split('');
    if (map[a] || map[b]) {
      throw new Error(`Invalid plugboard: letter ${map[a] ? a : b} used in more than one pair`);
    }
    map[a] = b;
    map[b] = a;
  }
  return map;
}

function plugboardSwap(ch, plugMap) {
  return plugMap[ch] || ch;
}

// Steps the rotor set for ONE keypress, implementing the historical
// double-stepping anomaly: the middle rotor steps both when the RIGHT
// rotor's notch passes it AND, if the middle rotor's OWN notch is at the
// window, it steps again the same keypress (dragging the left rotor with
// it) — this is exactly how a real M3 behaves and is a well-known,
// deliberately-preserved historical quirk, not a bug.
function stepRotors(rotors) {
  const [left, middle, right] = rotors;
  const middleAtNotch = middle.position === middle.notch;
  const rightAtNotch = right.position === right.notch;

  if (middleAtNotch) {
    middle.position = (middle.position + 1) % 26;
    left.position = (left.position + 1) % 26;
  } else if (rightAtNotch) {
    middle.position = (middle.position + 1) % 26;
  }
  right.position = (right.position + 1) % 26;
}

// Passes a signal (0-25) through one rotor, left-to-right (entering from the
// right/keyboard side, i.e. the normal forward direction).
function rotorForward(rotor, signal) {
  const shifted = (signal + rotor.position - rotor.ring + 26) % 26;
  const wired = letterToIndex(rotor.wiring[shifted]);
  return (wired - rotor.position + rotor.ring + 26) % 26;
}

// Passes a signal (0-25) through one rotor in reverse (the return path,
// after the reflector).
function rotorBackward(rotor, signal) {
  const shifted = (signal + rotor.position - rotor.ring + 26) % 26;
  const wired = rotor.wiring.indexOf(indexToLetter(shifted));
  return (wired - rotor.position + rotor.ring + 26) % 26;
}

/**
 * Encrypts/decrypts `text` with a full Enigma configuration. Same function
 * for both directions (Enigma is its own inverse for a fixed configuration).
 * @param {string} text
 * @param {object} settings
 * @param {[string,string,string]} settings.rotors - rotor names, LEFT to RIGHT, e.g. ['I','II','III']
 * @param {'B'|'C'} settings.reflector
 * @param {[string|number,string|number,string|number]} [settings.ringSettings=['A','A','A']] - Ringstellung, LEFT to RIGHT
 * @param {[string|number,string|number,string|number]} [settings.positions=['A','A','A']] - Grundstellung, LEFT to RIGHT
 * @param {string|string[]} [settings.plugboard=''] - e.g. "AB CD EF" or ["AB","CD","EF"]
 * @returns {string}
 */
export function enigmaProcess(text, settings) {
  if (!settings || !Array.isArray(settings.rotors) || settings.rotors.length !== 3) {
    throw new Error('Enigma requires exactly 3 rotors, e.g. rotors: ["I","II","III"]');
  }
  const reflectorWiring = REFLECTORS[settings.reflector];
  if (!reflectorWiring) {
    throw new Error(`Unknown reflector: ${settings.reflector}. Valid reflectors: ${Object.keys(REFLECTORS).join(', ')}`);
  }
  const ringSettings = settings.ringSettings || ['A', 'A', 'A'];
  const positions = settings.positions || ['A', 'A', 'A'];

  // rotors array is stored LEFT to RIGHT to match how settings are specified
  // (matching historical operator convention of reading left-to-right).
  const rotors = settings.rotors.map((name, i) => buildRotor(name, ringSettings[i], positions[i]));
  const plugMap = buildPlugboard(settings.plugboard);

  let out = '';
  for (const ch of text) {
    const upper = ch.toUpperCase();
    if (!/[A-Z]/.test(upper)) {
      out += ch; // pass through unchanged, does not advance rotors
      continue;
    }

    stepRotors(rotors);

    let signal = letterToIndex(plugboardSwap(upper, plugMap));

    // Forward through rotors, RIGHT to LEFT (index 2 -> 1 -> 0).
    signal = rotorForward(rotors[2], signal);
    signal = rotorForward(rotors[1], signal);
    signal = rotorForward(rotors[0], signal);

    // Reflector.
    signal = letterToIndex(reflectorWiring[signal]);

    // Backward through rotors, LEFT to RIGHT (index 0 -> 1 -> 2).
    signal = rotorBackward(rotors[0], signal);
    signal = rotorBackward(rotors[1], signal);
    signal = rotorBackward(rotors[2], signal);

    const resultLetter = plugboardSwap(indexToLetter(signal), plugMap);
    out += ch === upper ? resultLetter : resultLetter.toLowerCase();
  }
  return out;
}

export const ENIGMA_ROTOR_NAMES = Object.keys(ROTORS);
export const ENIGMA_REFLECTOR_NAMES = Object.keys(REFLECTORS);
