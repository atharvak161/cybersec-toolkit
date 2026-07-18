import { analyzePassword } from '../lib/password.js';
import { checkHibp } from '../lib/hibp.js';
import { lookupHashInDemoWordlist, SUPPORTED_ALGORITHMS } from '../lib/wordlist-lookup.js';
import { el, toolHeader, clear, resultLine, showError, externalApiBadge, educationalBadge } from './helpers.js';

export const PASSWORD_TOOLS = [
  {
    id: 'password-strength',
    name: 'Password Strength / Entropy',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Estimates entropy from length + effective charset, flags common weaknesses (sequences, repeats), and gives a rough offline-crack-time estimate. Nothing leaves your browser.'));

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
      container.appendChild(toolHeader('Checks whether a password has appeared in known data breaches, using the Have I Been Pwned k-anonymity range API.'));

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
      container.appendChild(toolHeader('Hashes each entry in a small built-in demo wordlist and compares against a target hash, to illustrate why weak/common passwords are trivially guessable offline.'));

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
  }
];
