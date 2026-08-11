/**
 * UI for the classical-cipher tools:
 *   - Cipher Cracker: paste ciphertext, get the best-ranked plaintext across
 *     Caesar / Atbash / rail-fence / single-byte XOR / Vigenère, each with a
 *     confidence score — the "magic decryption" experience for keyless and
 *     weak-key classical ciphers.
 *   - Enigma: a settings-based simulator (supply the rotors/reflector/rings/
 *     positions/plugboard, it encrypts AND decrypts, since Enigma is its own
 *     inverse).
 *
 * All rendering goes through the el() text-node helpers — no innerHTML, and
 * nothing user-controlled is ever interpolated as markup.
 */
import { crackAllCiphers } from '../lib/classical-ciphers.js';
import { enigmaProcess, ENIGMA_ROTOR_NAMES, ENIGMA_REFLECTOR_NAMES } from '../lib/enigma.js';
import { enigmaAutoBreak, enigmaAutoBreakCost } from '../lib/enigma-break.js';
import { el, toolHeader, clear, resultLine, showError, copyButton } from './helpers.js';
import { TOOL_COPY } from '../data/tool-copy.js';

// The fitness score is uncapped-ish but real English tops out around ~0.6;
// scale the visual bar against that so a strong plaintext fills it, while
// being honest that short ciphertexts carry less signal (and so score lower).
function confidencePercent(score) {
  return Math.max(0, Math.min(100, Math.round((score / 0.6) * 100)));
}
function confidenceLabel(score, topLead) {
  if (score >= 0.45) return 'High confidence';
  if (score >= 0.2) return topLead ? 'Likely' : 'Possible';
  if (score >= 0.1) return 'Weak signal';
  return 'No clear English';
}
function bandClass(score) {
  if (score >= 0.45) return 'cc-strong';
  if (score >= 0.2) return 'cc-fair';
  if (score >= 0.1) return 'cc-weak';
  return 'cc-none';
}

export const CIPHER_TOOLS = [
  {
    id: 'cipher-cracker',
    name: 'Classical Cipher Cracker',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['cipher-cracker']));

      const input = el('textarea', {
        rows: '4',
        placeholder: 'Paste ciphertext — e.g. XRPCTCRGNEI',
        style: 'width:100%; font-family:var(--mono, monospace)'
      });
      const runBtn = el('button', { class: 'btn' }, 'Crack it');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      function render() {
        clear(resultsBox);
        clear(errorNode);
        const text = input.value.trim();
        if (!text) { showError(errorNode, new Error('Paste some ciphertext first.')); return; }
        let results;
        try {
          results = crackAllCiphers(text, { maxResults: 8 });
        } catch (err) { showError(errorNode, err); return; }

        if (!results.length) {
          resultsBox.appendChild(el('p', {}, 'No candidate plaintext could be produced from that input.'));
          return;
        }

        const top = results[0];
        const lead = results.length < 2 || top.score >= results[1].score * 1.5;

        // Headline "best match" card.
        const best = el('div', { class: `card cc-best ${bandClass(top.score)}` }, [
          el('div', { class: 'cc-best-label' }, `Best match · ${confidenceLabel(top.score, lead)} · ${top.cipher} (${top.key})`),
          el('div', { class: 'cc-best-text tabular-nums' }, top.text),
          el('div', { class: 'cc-bar' }, [el('div', { class: 'cc-bar-fill', style: `width:${confidencePercent(top.score)}%` })]),
          el('div', { class: 'field-row', style: 'margin-top:8px' }, [copyButton(() => top.text)])
        ]);
        resultsBox.appendChild(best);

        // The rest, as a compact ranked table.
        if (results.length > 1) {
          resultsBox.appendChild(el('div', { class: 'cc-others-h' }, 'Other candidates'));
          const rows = results.slice(1).map((r) => el('tr', {}, [
            el('td', { class: 'cc-cipher' }, `${r.cipher} · ${r.key}`),
            el('td', { class: 'cc-cand tabular-nums' }, r.text),
            el('td', { class: `cc-score ${bandClass(r.score)}` }, `${confidencePercent(r.score)}%`)
          ]));
          resultsBox.appendChild(el('table', { class: 'data-table cc-table' }, [
            el('tr', {}, [el('th', {}, 'Cipher'), el('th', {}, 'Plaintext'), el('th', {}, 'Confidence')]),
            ...rows
          ]));
        }

        // Honest scope note — what this can and cannot do.
        resultsBox.appendChild(el('div', { class: 'cc-note' }, [
          el('strong', {}, 'What this can’t crack: '),
          'a one-time pad is mathematically unbreakable (with a truly random key as long as the message, every plaintext is equally likely — there is no answer to find), and modern crypto like AES or RSA can’t be brute-forced here. This tool covers keyless and weak-key classical ciphers only.'
        ]));
      }

      runBtn.addEventListener('click', render);

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Ciphertext'),
        input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },

  {
    id: 'enigma',
    name: 'Enigma Machine (Simulator)',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['enigma']));

      const rotorSelect = (def) => el('select', {},
        ENIGMA_ROTOR_NAMES.map((n) => el('option', n === def ? { value: n, selected: 'true' } : { value: n }, n)));
      const r1 = rotorSelect('I');
      const r2 = rotorSelect('II');
      const r3 = rotorSelect('III');
      const reflector = el('select', {},
        ENIGMA_REFLECTOR_NAMES.map((n) => el('option', n === 'B' ? { value: n, selected: 'true' } : { value: n }, n)));

      const rings = el('input', { type: 'text', value: 'AAA', maxlength: '3', style: 'width:70px; text-transform:uppercase' });
      const positions = el('input', { type: 'text', value: 'AAA', maxlength: '3', style: 'width:70px; text-transform:uppercase' });
      const plugboard = el('input', { type: 'text', placeholder: 'e.g. AB CD EF', style: 'width:100%; text-transform:uppercase' });

      const text = el('textarea', { rows: '3', placeholder: 'Type text — same settings encrypt and decrypt', style: 'width:100%; text-transform:uppercase; font-family:var(--mono, monospace)' });
      const runBtn = el('button', { class: 'btn' }, 'Run through Enigma →');
      const output = el('input', { type: 'text', readonly: 'true', class: 'output tabular-nums', style: 'font-size:16px' });
      const errorNode = el('div', {});

      function letters3(v, fallback) {
        const up = (v || '').toUpperCase().replace(/[^A-Z]/g, '');
        return (up.length === 3 ? up : fallback).split('');
      }

      runBtn.addEventListener('click', () => {
        clear(errorNode);
        try {
          output.value = enigmaProcess(text.value, {
            rotors: [r1.value, r2.value, r3.value],
            reflector: reflector.value,
            ringSettings: letters3(rings.value, 'AAA'),
            positions: letters3(positions.value, 'AAA'),
            plugboard: plugboard.value.trim()
          });
        } catch (err) { showError(errorNode, err); }
      });

      const field = (label, node) => el('div', { class: 'field-col' }, [el('label', {}, label), node]);

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [
          field('Left rotor', r1), field('Middle rotor', r2), field('Right rotor', r3), field('Reflector', reflector)
        ]),
        el('div', { class: 'field-row' }, [
          field('Ring settings', rings), field('Start positions', positions)
        ]),
        field('Plugboard (space-separated letter pairs)', plugboard),
        el('label', { style: 'margin-top:10px' }, 'Text'),
        text,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode,
        el('label', { style: 'margin-top:10px' }, 'Result'),
        output,
        el('div', { class: 'field-row', style: 'margin-top:6px' }, [copyButton(() => output.value)])
      ]));
    }
  },

  {
    id: 'enigma-autobreak',
    name: 'Enigma Auto-Break (Cryptanalysis)',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['enigma-autobreak']));

      // Search-depth presets trade coverage for time. All use the full I–V wheel
      // set; the knobs are which reflector(s) to try and how many letters to
      // score in the Phase-1 position search. Shown decrypt counts come straight
      // from enigmaAutoBreakCost so the estimate can never drift from the engine.
      const DEPTHS = {
        fast: { label: 'Fast — reflector B only', reflectors: ['B'], probeLen: 120 },
        standard: { label: 'Standard — reflectors B and C', reflectors: ENIGMA_REFLECTOR_NAMES, probeLen: 150 },
        thorough: { label: 'Thorough — B and C, longer scoring window', reflectors: ENIGMA_REFLECTOR_NAMES, probeLen: 250 }
      };

      const input = el('textarea', {
        rows: '4',
        placeholder: 'Paste Enigma ciphertext (letters only matter) — e.g. the output of the Enigma simulator above',
        style: 'width:100%; text-transform:uppercase; font-family:var(--mono, monospace)'
      });
      const depth = el('select', {}, Object.entries(DEPTHS).map(([k, d]) =>
        el('option', k === 'standard' ? { value: k, selected: 'true' } : { value: k }, d.label)));
      const estimate = el('div', { class: 'tool-desc', style: 'margin-top:6px' }, '');
      const runBtn = el('button', { class: 'btn' }, 'Recover settings & decrypt');
      const cancelBtn = el('button', { class: 'btn secondary', style: 'display:none' }, 'Cancel');
      const progressWrap = el('div', { style: 'display:none; margin-top:10px' }, [
        el('div', { class: 'cc-bar' }, [el('div', { class: 'cc-bar-fill', id: 'eb-prog' })]),
        el('div', { class: 'tool-desc', id: 'eb-prog-label', style: 'margin-top:4px' }, '')
      ]);
      const progFill = progressWrap.querySelector('#eb-prog');
      const progLabel = progressWrap.querySelector('#eb-prog-label');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      function currentOpts() {
        const d = DEPTHS[depth.value];
        return { rotorSet: ENIGMA_ROTOR_NAMES, reflectors: d.reflectors, probeLen: d.probeLen };
      }
      function refreshEstimate() {
        const text = input.value.trim();
        if (!text) { estimate.textContent = ''; return; }
        try {
          const cost = enigmaAutoBreakCost(text, currentOpts());
          estimate.textContent = `Search space: ${cost.phase1Decrypts.toLocaleString()} candidate decrypts `
            + `across ${cost.orderings} rotor orders × 26³ start positions (scoring the first `
            + `${cost.probeChars} letters). Runs off the main thread; larger ciphertext = more reliable.`;
        } catch { estimate.textContent = ''; }
      }
      input.addEventListener('input', refreshEstimate);
      depth.addEventListener('change', refreshEstimate);

      let worker = null;
      function setRunning(on) {
        runBtn.disabled = on;
        runBtn.textContent = on ? 'Searching…' : 'Recover settings & decrypt';
        cancelBtn.style.display = on ? '' : 'none';
        progressWrap.style.display = on ? '' : 'none';
        if (!on) { progFill.style.width = '0%'; progLabel.textContent = ''; }
      }
      function onProgress(p) {
        if (p.phase === 1) {
          const pct = p.total ? Math.min(99, Math.round((p.done / p.total) * 100)) : 0;
          progFill.style.width = `${pct}%`;
          progLabel.textContent = `Phase 1 — rotor order & start positions (${pct}%)`;
        } else {
          progFill.style.width = '99%';
          progLabel.textContent = 'Phase 2/3 — ring settings & plugboard hill-climb…';
        }
      }
      function showResult(res) {
        clear(resultsBox);
        const pct = confidencePercent(res.fitness);
        const plug = res.plugboard.length ? res.plugboard.join(' ') : '(none)';

        const best = el('div', { class: `card cc-best ${bandClass(res.fitness)}` }, [
          el('div', { class: 'cc-best-label' }, `Recovered · ${res.confidenceLabel} · IoC ${res.ic.toFixed(4)}`),
          el('div', { class: 'cc-best-text tabular-nums' }, res.plaintext),
          el('div', { class: 'cc-bar' }, [el('div', { class: 'cc-bar-fill', style: `width:${pct}%` })]),
          el('div', { class: 'field-row', style: 'margin-top:8px' }, [copyButton(() => res.plaintext)])
        ]);
        resultsBox.appendChild(best);

        resultsBox.appendChild(el('div', { class: 'cc-others-h' }, 'Recovered settings'));
        resultsBox.appendChild(el('table', { class: 'data-table' }, [
          el('tr', {}, [el('th', {}, 'Rotor order (L→R)'), el('td', {}, res.rotors.join(' '))]),
          el('tr', {}, [el('th', {}, 'Reflector'), el('td', {}, res.reflector)]),
          el('tr', {}, [el('th', {}, 'Ring settings'), el('td', {}, res.ringSettings.join(''))]),
          el('tr', {}, [el('th', {}, 'Start positions'), el('td', {}, res.positions.join(''))]),
          el('tr', {}, [el('th', {}, 'Plugboard'), el('td', {}, plug)])
        ]));

        resultsBox.appendChild(el('div', { class: 'cc-note' }, [
          el('strong', {}, 'How to read this: '),
          'these settings were recovered from the ciphertext alone — no key was supplied — by ranking millions of '
          + 'candidate decrypts on their Index of Coincidence, then hill-climbing the plugboard on English fitness. '
          + 'Feed the recovered settings back into the simulator above to verify. Recovery is most reliable on '
          + 'longer messages (≳120 letters) with rings at or near default; a ciphertext-only, non-default '
          + 'Ringstellung recovery is genuinely hard and only best-effort here — that difficulty is exactly why the '
          + 'wartime attack needed cribs and the Bombe. This models the 3-rotor Enigma I / M3 (wheels I–V, '
          + 'reflectors B/C); the naval M4 and double-notch wheels VI–VIII are out of scope.'
        ]));
      }

      function runSync(ciphertext, opts) {
        // Fallback when Web Workers are unavailable: blocks the tab, so warn.
        progLabel.textContent = 'Running without a Web Worker — the tab may be unresponsive for a while…';
        setTimeout(() => {
          try {
            const res = enigmaAutoBreak(ciphertext, opts);
            setRunning(false);
            showResult(res);
          } catch (err) { setRunning(false); showError(errorNode, err); }
        }, 30);
      }

      runBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(resultsBox);
        const ciphertext = input.value.trim();
        if (!ciphertext) { showError(errorNode, new Error('Paste some Enigma ciphertext first.')); return; }
        const opts = currentOpts();
        setRunning(true);

        if (typeof Worker === 'undefined') { runSync(ciphertext, opts); return; }
        try {
          worker = new Worker(new URL('../lib/enigma-break-worker.js', import.meta.url), { type: 'module' });
        } catch {
          worker = null; runSync(ciphertext, opts); return;
        }
        worker.onmessage = (e) => {
          const msg = e.data;
          if (msg.type === 'progress') { onProgress(msg); return; }
          if (msg.type === 'result') { setRunning(false); worker.terminate(); worker = null; showResult(msg.result); return; }
          if (msg.type === 'error') { setRunning(false); worker.terminate(); worker = null; showError(errorNode, new Error(msg.message)); }
        };
        worker.onerror = (e) => { setRunning(false); if (worker) { worker.terminate(); worker = null; } showError(errorNode, new Error(e.message || 'Worker failed')); };
        worker.postMessage({ ciphertext, options: opts });
      });

      cancelBtn.addEventListener('click', () => {
        if (worker) { worker.terminate(); worker = null; }
        setRunning(false);
        progLabel.textContent = '';
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Ciphertext'),
        input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [
          field('Search depth', depth),
          el('div', { class: 'field-col', style: 'justify-content:flex-end' }, [runBtn, cancelBtn])
        ]),
        estimate,
        progressWrap,
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  }
];

// Shared little "label above a control" column, used by the Enigma panels.
function field(label, node) {
  return el('div', { class: 'field-col' }, [el('label', {}, label), node]);
}
