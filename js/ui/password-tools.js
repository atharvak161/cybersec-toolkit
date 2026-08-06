import { analyzePassword } from '../lib/password.js';
import { checkHibp } from '../lib/hibp.js';
import { lookupHashInDemoWordlist, SUPPORTED_ALGORITHMS } from '../lib/wordlist-lookup.js';
import { generatePassword, estimateEntropyBits } from '../lib/password-gen.js';
import { generatePassphrase, WORDLIST_SIZE } from '../lib/diceware.js';
import { assessStrength } from '../lib/crack-time.js';
import { el, toolHeader, clear, resultLine, showError, externalApiBadge, educationalBadge, copyButton } from './helpers.js';
import { TOOL_COPY } from '../data/tool-copy.js';

/**
 * Builds the live "how strong is this / how long to crack it" panel for the
 * password generator, from a plain entropy value. All text goes through the
 * el() text-node path — no innerHTML, nothing user-controlled is interpolated
 * as markup (the only inputs are numbers and this module's own copy).
 */
function renderStrengthMeter(entropyBits) {
  const a = assessStrength(entropyBits);

  const panel = el('div', { class: `pw-meter pw-band-${a.band.id}` });

  // Verdict headline + plain-English message.
  panel.appendChild(el('div', { class: 'pw-verdict' }, [
    el('span', { class: 'pw-verdict-icon' }, a.band.icon),
    el('div', {}, [
      el('div', { class: 'pw-verdict-head' }, `${a.band.label} — ${a.band.headline}`),
      el('div', { class: 'pw-verdict-msg' }, a.band.message)
    ])
  ]));

  // Strength bar.
  panel.appendChild(el('div', { class: 'pw-bar', title: `${a.entropyBits} bits of entropy` }, [
    el('div', { class: 'pw-bar-fill', style: `width:${Math.round(a.barFill * 100)}%` })
  ]));

  panel.appendChild(el('div', { class: 'pw-meter-meta' },
    `${a.entropyBits} bits of entropy · generated with crypto.getRandomValues — nothing is sent anywhere`));

  // Per-attacker crack-time table — the "who could break this, and how long".
  const rows = a.tiers.map((t) => el('tr', { class: t.id === a.referenceTierId ? 'pw-ref-row' : '' }, [
    el('td', { class: 'pw-tier-icon' }, t.icon),
    el('td', { class: 'pw-tier-name' }, [
      el('div', {}, t.name),
      el('div', { class: 'pw-tier-detail' }, t.detail)
    ]),
    el('td', { class: 'pw-tier-time tabular-nums' }, t.human)
  ]));
  panel.appendChild(el('table', { class: 'pw-crack' }, [
    el('caption', {}, 'How long to crack it by pure brute force'),
    el('tbody', {}, rows)
  ]));

  return panel;
}

export const PASSWORD_TOOLS = [
  {
    id: 'password-strength',
    name: 'Password Strength / Entropy',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['password-strength']));

      const input = el('input', { type: 'password', placeholder: 'Type a password to analyze…' });
      const showToggle = el('button', { class: 'btn secondary' }, 'Show');
      const resultsBox = el('div', { class: 'card' });

      showToggle.addEventListener('click', () => {
        input.type = input.type === 'password' ? 'text' : 'password';
        showToggle.textContent = input.type === 'password' ? 'Show' : 'Hide';
      });

      input.addEventListener('input', () => {
        clear(resultsBox);
        if (!input.value) return;
        const result = analyzePassword(input.value);
        resultsBox.appendChild(resultLine('Entropy', result.entropyBits + ' bits'));
        resultsBox.appendChild(resultLine('Strength', `${result.label} (${result.score}/4)`));
        resultsBox.appendChild(resultLine('Estimated offline crack time', result.crackTimeHuman));
        if (result.warnings.length) {
          const list = el('ul', { class: 'warning-list' });
          for (const w of result.warnings) list.appendChild(el('li', {}, w));
          resultsBox.appendChild(list);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Password'),
        el('div', { class: 'field-row' }, [input, showToggle])
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'hibp',
    name: 'HIBP Breach Check',
    render(container) {
      clear(container);
      container.appendChild(externalApiBadge('Calls api.pwnedpasswords.com — only a 5-character SHA-1 prefix is sent, never your password or full hash (k-anonymity model).'));
      container.appendChild(toolHeader(TOOL_COPY.hibp));

      const input = el('input', { type: 'password', placeholder: 'Password to check…' });
      const checkBtn = el('button', { class: 'btn' }, 'Check (via HIBP)');
      const resultBox = el('div', {});
      const errorNode = el('div', {});

      checkBtn.addEventListener('click', async () => {
        clear(resultBox);
        clear(errorNode);
        checkBtn.disabled = true;
        checkBtn.textContent = 'Checking…';
        try {
          const { breached, count, prefix } = await checkHibp(input.value);
          resultBox.appendChild(resultLine('SHA-1 prefix sent', prefix));
          if (breached) {
            resultBox.appendChild(el('p', { style: 'color:var(--danger); font-weight:600' }, `⚠ Found in ${count.toLocaleString()} breaches — do not use this password.`));
          } else {
            resultBox.appendChild(el('p', { style: 'color:var(--accent); font-weight:600' }, '✓ Not found in known breaches.'));
          }
        } catch (err) {
          showError(errorNode, err);
        }
        checkBtn.disabled = false;
        checkBtn.textContent = 'Check (via HIBP)';
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Password'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [checkBtn]),
        errorNode, resultBox
      ]));
    }
  },
  {
    id: 'wordlist-demo',
    name: 'Common-Password Hash Lookup',
    render(container) {
      clear(container);
      container.appendChild(educationalBadge('Educational demo, capped at 300 common passwords — NOT a real cracking tool.'));
      container.appendChild(toolHeader(TOOL_COPY['wordlist-demo']));

      const hashInput = el('input', { type: 'text', placeholder: 'Target hash…' });
      const algoSelect = el('select', {}, SUPPORTED_ALGORITHMS.map((a) => el('option', { value: a }, a)));
      const runBtn = el('button', { class: 'btn' }, 'Search demo wordlist');
      const resultBox = el('div', {});

      runBtn.addEventListener('click', async () => {
        clear(resultBox);
        runBtn.disabled = true;
        try {
          const result = await lookupHashInDemoWordlist(hashInput.value, algoSelect.value);
          if (result.found) {
            resultBox.appendChild(el('p', { style: 'color:var(--danger); font-weight:600' }, `Match found after ${result.attempts} attempts: "${result.plaintext}"`));
          } else {
            resultBox.appendChild(el('p', { style: 'color:var(--accent)' }, `No match after checking all ${result.attempts} demo entries.`));
          }
        } catch (err) {
          showError(resultBox, err);
        }
        runBtn.disabled = false;
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'Algorithm'), algoSelect]),
        el('label', {}, 'Target hash'), hashInput,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        resultBox
      ]));
    }
  },
  {
    id: 'password-generator',
    name: 'Password Generator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['password-generator']));

      const lengthInput = el('input', { type: 'number', value: '16', min: '4', max: '128', style: 'width:80px' });
      const upperCheck = el('input', { type: 'checkbox', checked: 'true', style: 'width:auto' });
      const lowerCheck = el('input', { type: 'checkbox', checked: 'true', style: 'width:auto' });
      const digitsCheck = el('input', { type: 'checkbox', checked: 'true', style: 'width:auto' });
      const symbolsCheck = el('input', { type: 'checkbox', checked: 'true', style: 'width:auto' });
      const excludeAmbiguousCheck = el('input', { type: 'checkbox', style: 'width:auto' });
      const lengthRange = el('input', { type: 'range', min: '4', max: '128', value: '16', style: 'flex:1; min-width:140px' });
      const generateBtn = el('button', { class: 'btn' }, 'Generate password');
      const output = el('input', { type: 'text', readonly: 'true', class: 'output tabular-nums', style: 'font-size:16px' });
      const strengthPanel = el('div', { class: 'pw-strength' });
      const errorNode = el('div', {});

      function checkboxRow(checkbox, label) {
        return el('label', { style: 'display:flex; align-items:center; gap:6px; width:auto' }, [checkbox, label]);
      }

      function currentOpts() {
        return {
          length: parseInt(lengthInput.value, 10) || 16,
          upper: upperCheck.checked,
          lower: lowerCheck.checked,
          digits: digitsCheck.checked,
          symbols: symbolsCheck.checked,
          excludeAmbiguous: excludeAmbiguousCheck.checked
        };
      }

      // Live strength verdict: recomputes from the CURRENT settings on every
      // change (entropy is a property of the settings, not the specific
      // string), so the user watches the rating climb as they drag length up
      // and can make the right call before generating anything.
      function refreshStrength() {
        clear(strengthPanel);
        if (!upperCheck.checked && !lowerCheck.checked && !digitsCheck.checked && !symbolsCheck.checked) {
          strengthPanel.appendChild(el('div', { class: 'tool-desc' }, 'Select at least one character set.'));
          return;
        }
        strengthPanel.appendChild(renderStrengthMeter(estimateEntropyBits(currentOpts())));
      }

      // Keep the number box and the slider in lock-step, and re-rate live.
      lengthRange.addEventListener('input', () => { lengthInput.value = lengthRange.value; refreshStrength(); });
      lengthInput.addEventListener('input', () => {
        const v = Math.max(4, Math.min(128, parseInt(lengthInput.value, 10) || 16));
        lengthRange.value = String(v);
        refreshStrength();
      });
      for (const c of [upperCheck, lowerCheck, digitsCheck, symbolsCheck, excludeAmbiguousCheck]) {
        c.addEventListener('change', refreshStrength);
      }

      generateBtn.addEventListener('click', () => {
        clear(errorNode);
        try {
          output.value = generatePassword(currentOpts());
          refreshStrength();
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'Length'), lengthInput, lengthRange]),
        el('div', { class: 'field-row' }, [
          checkboxRow(upperCheck, 'Uppercase (A-Z)'),
          checkboxRow(lowerCheck, 'Lowercase (a-z)'),
          checkboxRow(digitsCheck, 'Digits (0-9)'),
          checkboxRow(symbolsCheck, 'Symbols (!@#…)')
        ]),
        el('div', { class: 'field-row' }, [checkboxRow(excludeAmbiguousCheck, 'Exclude ambiguous characters (0/O, 1/l/I, …)')]),
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [generateBtn]),
        errorNode,
        el('label', { style: 'margin-top:10px' }, 'Generated password'), output,
        el('div', { class: 'field-row', style: 'margin-top:6px' }, [copyButton(() => output.value)]),
        strengthPanel
      ]));

      refreshStrength();
    }
  },
  {
    id: 'diceware',
    name: 'Diceware Passphrase Generator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY.diceware));
      container.appendChild(el('p', { class: 'tool-copy-line' }, [
        el('strong', {}, 'Wordlist: '),
        `EFF Large Wordlist (${WORDLIST_SIZE.toLocaleString()} words), vendored locally — see data/eff-large-wordlist.js. Words are chosen with crypto.getRandomValues, not physical dice.`
      ]));

      const wordCountInput = el('input', { type: 'number', value: '6', min: '3', max: '15', style: 'width:80px' });
      const separatorInput = el('input', { type: 'text', value: '-', style: 'width:80px' });
      const capitalizeCheck = el('input', { type: 'checkbox', style: 'width:auto' });
      const includeNumberCheck = el('input', { type: 'checkbox', style: 'width:auto' });
      const generateBtn = el('button', { class: 'btn' }, 'Generate passphrase');
      const output = el('input', { type: 'text', readonly: 'true', class: 'output', style: 'font-size:16px' });
      const entropyLine = el('div', { class: 'tool-desc' }, '');
      const errorNode = el('div', {});

      function checkboxRow(checkbox, label) {
        return el('label', { style: 'display:flex; align-items:center; gap:6px; width:auto' }, [checkbox, label]);
      }

      generateBtn.addEventListener('click', () => {
        clear(errorNode);
        try {
          const { passphrase, entropyBits } = generatePassphrase({
            wordCount: parseInt(wordCountInput.value, 10) || 6,
            separator: separatorInput.value,
            capitalize: capitalizeCheck.checked,
            includeNumber: includeNumberCheck.checked
          });
          output.value = passphrase;
          entropyLine.textContent = `~${entropyBits} bits of entropy.`;
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [
          el('div', {}, [el('label', {}, 'Word count'), wordCountInput]),
          el('div', {}, [el('label', {}, 'Separator'), separatorInput])
        ]),
        el('div', { class: 'field-row' }, [
          checkboxRow(capitalizeCheck, 'Capitalize each word'),
          checkboxRow(includeNumberCheck, 'Include a digit')
        ]),
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [generateBtn]),
        errorNode,
        el('label', { style: 'margin-top:10px' }, 'Generated passphrase'), output,
        el('div', { class: 'field-row', style: 'margin-top:6px' }, [copyButton(() => output.value)]),
        entropyLine
      ]));
    }
  }
];
