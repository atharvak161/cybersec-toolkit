/**
 * Auto-Decode (Magic Wand) UI module. Matches the {id, name, render(container)}
 * tool-object shape used across the toolkit and builds its DOM with the shared
 * `el`/`clear` helpers (no innerHTML, per project XSS convention).
 *
 * All logic lives in js/lib/auto-decode.js — this file is presentation only.
 */

import { autoDecode, DECODER_NAMES, MAX_INPUT_LENGTH } from '../lib/auto-decode.js';
import { el, clear, toolHeader, copyButton, showError } from './helpers.js';
import { TOOL_COPY } from '../data/tool-copy.js';

// A candidate at or above this score is shown expanded by default; everything
// below is folded away behind the "show more (low confidence)" toggle so the
// user is never buried in near-random decode attempts.
const HIGH_CONFIDENCE = 0.5;

// Friendly labels for the terminal/plaintext step when rendering a path.
function renderPath(path) {
  return path.join(' → ') + ' → text';
}

function candidateCard(candidate) {
  const outputArea = el('textarea', {
    rows: String(Math.min(8, Math.max(2, candidate.output.split('\n').length + 1))),
    class: 'output',
    readonly: 'true'
  });
  outputArea.value = candidate.output;

  const reasons = el('ul', { class: 'reason-list' },
    candidate.reasons.map((r) => el('li', {}, r))
  );

  const body = el('div', { class: 'card', style: 'margin-top:10px' }, [
    el('div', { class: 'field-row', style: 'justify-content:space-between;align-items:baseline' }, [
      el('strong', { class: 'decode-path' }, renderPath(candidate.path)),
      el('span', { class: 'decode-score' }, `${Math.round(candidate.score * 100)}% confidence`)
    ]),
    el('label', { style: 'margin-top:8px' }, 'Decoded output'),
    outputArea,
    copyButton(() => candidate.output),
    el('div', { class: 'decode-reasons', style: 'margin-top:8px' }, [
      el('span', { class: 'tooltip-usecase-label' }, 'Why this ranking'),
      reasons
    ])
  ]);
  return body;
}

function hashNote(hashInfo) {
  const list = el('ul', { class: 'reason-list' },
    hashInfo.matches.map((m) => el('li', {}, `${m.algorithm} (${m.confidence} confidence)`))
  );
  return el('div', { class: 'card educational-badge-wrap', style: 'margin-top:14px' }, [
    el('div', { class: 'educational-badge' }, 'ℹ️ Hash identification — informational, not a decode'),
    el('p', { class: 'tool-desc', style: 'margin-top:8px' }, hashInfo.note),
    el('label', {}, 'Likely algorithm(s)'),
    list
  ]);
}

export const AUTO_DECODE_TOOLS = [
  {
    id: 'auto-decode',
    name: 'Auto-Decode (Magic Wand)',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['auto-decode']));

      const input = el('textarea', {
        rows: '6',
        placeholder: 'Paste a mystery string — base64, hex, Morse, ROT13, a stack of several…'
      });
      const runBtn = el('button', { class: 'btn' }, 'Decode');
      const errorNode = el('div', {});
      const resultsNode = el('div', { class: 'auto-decode-results' });

      const helpLine = el('p', { class: 'tool-desc', style: 'margin-top:6px' },
        `Tries ${DECODER_NAMES.length} encoders/decoders (${DECODER_NAMES.join(', ')}), recursively peels layered encodings, ` +
        `and also cracks classical ciphers — Caesar (all shifts), Atbash, rail-fence, single-byte XOR, and Vigenère — ranking every result by how much it reads like real English. ` +
        `Limit: ${MAX_INPUT_LENGTH.toLocaleString()} characters per input.`);

      function run() {
        clear(errorNode);
        clear(resultsNode);
        const value = input.value;
        if (!value.trim()) {
          resultsNode.appendChild(el('p', { class: 'tool-desc' }, 'Paste something above, then press Decode.'));
          return;
        }

        let result;
        try {
          result = autoDecode(value);
        } catch (err) {
          showError(errorNode, err);
          return;
        }

        if (result.stats.sizeCapped) {
          const actual = result.stats.inputLength.toLocaleString();
          const limit = result.stats.maxInputLength.toLocaleString();
          resultsNode.appendChild(el('div', { class: 'card educational-badge-wrap', style: 'margin-top:14px' }, [
            el('div', { class: 'educational-badge' }, 'Input too large to decode'),
            el('p', { class: 'tool-desc', style: 'margin-top:8px' },
              `That's ${actual} characters — over the ${limit}-character limit for Auto-Decode. ` +
              'Nothing was processed (this guard runs before any decoding, precisely to avoid a slow ' +
              'freeze on very large pastes). Paste a shorter mystery string — a JWT, token, config ' +
              'blob, or typical CTF ciphertext are all comfortably under this limit — or use one of ' +
              'the dedicated Base64/hex tools for large data.')
          ]));
          return;
        }

        // Hash note first — clearly separated from decode candidates.
        if (result.hashInfo) {
          resultsNode.appendChild(hashNote(result.hashInfo));
        }

        const high = result.candidates.filter((c) => c.score >= HIGH_CONFIDENCE);
        const low = result.candidates.filter((c) => c.score < HIGH_CONFIDENCE);

        if (result.candidates.length === 0) {
          resultsNode.appendChild(el('div', { class: 'card', style: 'margin-top:14px' }, [
            el('p', { class: 'tool-desc' },
              result.hashInfo
                ? 'No reversible decoding found — but see the hash identification above.'
                : "Nothing decoded cleanly — this doesn't look like any encoding the toolkit knows. It may be raw ciphertext, a hash, or already plain text.")
          ]));
          appendStats(result.stats);
          return;
        }

        if (high.length > 0) {
          resultsNode.appendChild(el('h3', { class: 'result-heading' },
            `Most likely (${high.length})`));
          high.forEach((c) => resultsNode.appendChild(candidateCard(c)));
        } else {
          resultsNode.appendChild(el('div', { class: 'card', style: 'margin-top:14px' }, [
            el('p', { class: 'tool-desc' },
              'No high-confidence match. The lower-confidence attempts below are technically valid decodes but may be noise.')
          ]));
        }

        if (low.length > 0) {
          const lowWrap = el('div', { class: 'low-confidence-wrap', style: 'display:none' });
          low.forEach((c) => lowWrap.appendChild(candidateCard(c)));

          const toggle = el('button', { class: 'btn secondary', style: 'margin-top:12px' },
            `Show ${low.length} more (low confidence)`);
          let shown = false;
          toggle.addEventListener('click', () => {
            shown = !shown;
            lowWrap.style.display = shown ? 'block' : 'none';
            toggle.textContent = shown
              ? 'Hide low-confidence results'
              : `Show ${low.length} more (low confidence)`;
          });
          resultsNode.appendChild(toggle);
          resultsNode.appendChild(lowWrap);
        }

        appendStats(result.stats);
      }

      function appendStats(stats) {
        resultsNode.appendChild(el('p', { class: 'tool-desc muted', style: 'margin-top:14px;font-size:12px' },
          `${stats.attempts} decode attempts across ${stats.maxDepthReached} layer(s) in ${stats.elapsedMs.toFixed(1)} ms` +
          (stats.capHit ? ' — search cap reached (results are the most promising branches).' : '.')));
      }

      runBtn.addEventListener('click', run);
      input.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run();
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Mystery string'),
        input,
        helpLine,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode
      ]));
      container.appendChild(resultsNode);
    }
  }
];
