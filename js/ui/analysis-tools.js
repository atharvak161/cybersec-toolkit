/**
 * Analysis & Intel: IOC Extractor + Defang/Refang, CVSS 3.1 Base
 * Calculator, Secret/API-key Scanner, and a standalone Entropy
 * Calculator. All pure client-side text analysis — nothing here makes a
 * network call.
 */

import { extractIocs, defang, refang } from '../lib/ioc.js';
import { cvss31Base, METRIC_VALUES, METRIC_LABELS } from '../lib/cvss.js';
import { scanSecrets, shannonEntropy, describeEntropy } from '../lib/secret-scan.js';
import { el, toolHeader, clear, resultLine, showError, copyButton } from './helpers.js';
import { TOOL_COPY } from '../data/tool-copy.js';

const IOC_CATEGORY_LABELS = {
  ipv4: 'IPv4 addresses',
  ipv6: 'IPv6 addresses',
  domains: 'Domains',
  urls: 'URLs',
  emails: 'Email addresses',
  md5: 'MD5 hashes',
  sha1: 'SHA-1 hashes',
  sha256: 'SHA-256 hashes',
  cves: 'CVE IDs'
};

export const ANALYSIS_TOOLS = [
  {
    id: 'ioc-extractor',
    name: 'IOC Extractor + Defang/Refang',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['ioc-extractor']));

      const input = el('textarea', { rows: '8', placeholder: 'Paste a threat report, phishing email, or log excerpt…\ne.g. hxxp://evil[.]example[.]com, 1[.]2[.]3[.]4, user[at]example[.]com, CVE-2021-44228' });
      const extractBtn = el('button', { class: 'btn' }, 'Extract IOCs');
      const defangBtn = el('button', { class: 'btn secondary' }, 'Defang text');
      const refangBtn = el('button', { class: 'btn secondary' }, 'Refang text');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      extractBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(resultsBox);
        try {
          const iocs = extractIocs(input.value);
          const total = Object.values(iocs).reduce((sum, arr) => sum + arr.length, 0);
          resultsBox.appendChild(el('p', { class: 'tool-desc' }, `${total} indicator${total === 1 ? '' : 's'} found across ${Object.values(iocs).filter((a) => a.length).length} categories.`));

          for (const [key, label] of Object.entries(IOC_CATEGORY_LABELS)) {
            const values = iocs[key];
            if (!values.length) continue;
            const card = el('div', { class: 'card' });
            card.appendChild(el('div', { class: 'field-row', style: 'justify-content:space-between; align-items:baseline' }, [
              el('h3', {}, `${label} (${values.length})`),
              copyButton(() => values.join('\n'))
            ]));
            const list = el('div', { class: 'ioc-list' });
            for (const v of values) list.appendChild(el('div', { class: 'ioc-item' }, v));
            card.appendChild(list);
            resultsBox.appendChild(card);
          }

          if (total === 0) resultsBox.appendChild(el('p', { class: 'tool-desc' }, 'No indicators found.'));
        } catch (err) {
          showError(errorNode, err);
        }
      });

      defangBtn.addEventListener('click', () => { input.value = defang(input.value); });
      refangBtn.addEventListener('click', () => { input.value = refang(input.value); });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Text to analyze'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [extractBtn, defangBtn, refangBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'cvss-calculator',
    name: 'CVSS 3.1 Base Score Calculator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['cvss-calculator']));

      const selects = {};
      const metricRow = el('div', { class: 'card' });
      const grid = el('div', { class: 'cvss-grid' });
      for (const key of Object.keys(METRIC_VALUES)) {
        const select = el('select', {}, METRIC_VALUES[key].map((v) => el('option', { value: v }, v)));
        selects[key] = select;
        select.addEventListener('change', recompute);
        grid.appendChild(el('div', { class: 'cvss-field' }, [
          el('label', {}, `${METRIC_LABELS[key]} (${key})`), select
        ]));
      }
      metricRow.appendChild(grid);

      const resultBox = el('div', { class: 'card' });
      const errorNode = el('div', {});

      function recompute() {
        clear(errorNode);
        clear(resultBox);
        try {
          const metrics = {};
          for (const key of Object.keys(selects)) metrics[key] = selects[key].value;
          const { score, severity, vector } = cvss31Base(metrics);
          const severityColor = {
            None: 'var(--text-dim)', Low: 'var(--accent)', Medium: 'var(--warning)', High: 'var(--danger)', Critical: 'var(--danger)'
          }[severity] || 'var(--text)';

          resultBox.appendChild(el('p', { style: `color:${severityColor}; font-weight:700; font-size:20px` }, `${score.toFixed(1)} — ${severity}`));
          resultBox.appendChild(resultLine('Vector', vector));
          resultBox.appendChild(el('div', { class: 'field-row', style: 'margin-top:10px' }, [copyButton(() => vector)]));
        } catch (err) {
          showError(errorNode, err);
        }
      }

      container.appendChild(metricRow);
      container.appendChild(resultBox);
      container.appendChild(errorNode);
      recompute();
    }
  },
  {
    id: 'secret-scanner',
    name: 'Secret / API-Key Scanner',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['secret-scanner']));
      container.appendChild(el('p', { class: 'tool-copy-line' }, [
        el('strong', {}, 'Runs entirely locally: '),
        'the pasted text never leaves this page — scanning happens in your browser and nothing is uploaded anywhere.'
      ]));

      const input = el('textarea', { rows: '10', placeholder: 'Paste a config file, .env, log, or source snippet…' });
      const runBtn = el('button', { class: 'btn' }, 'Scan for secrets');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      runBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(resultsBox);
        try {
          const findings = scanSecrets(input.value);
          const color = findings.length ? 'var(--danger)' : 'var(--accent)';
          resultsBox.appendChild(el('p', { style: `color:${color}; font-weight:600` },
            findings.length ? `${findings.length} potential secret${findings.length === 1 ? '' : 's'} found.` : 'No potential secrets found.'
          ));
          if (findings.length) {
            const table = el('table', { class: 'data-table' }, [
              el('tr', {}, [el('th', {}, 'Line'), el('th', {}, 'Type'), el('th', {}, 'Match (masked)')]),
              ...findings.map((f) => el('tr', {}, [
                el('td', { class: 'tabular-nums' }, String(f.line)), el('td', {}, f.type), el('td', { class: 'ioc-item' }, f.match)
              ]))
            ]);
            resultsBox.appendChild(table);
          }
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Text to scan'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'entropy-calculator',
    name: 'Shannon Entropy Calculator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['entropy-calculator']));

      const input = el('textarea', { rows: '4', placeholder: 'Paste a string to measure…' });
      const resultsBox = el('div', {});

      function recompute() {
        clear(resultsBox);
        const text = input.value;
        if (!text) return;
        const bitsPerChar = shannonEntropy(text);
        const totalBits = bitsPerChar * text.length;
        const card = el('div', { class: 'card' });
        card.appendChild(resultLine('Bits per character', bitsPerChar.toFixed(3)));
        card.appendChild(resultLine('Total entropy', `${totalBits.toFixed(2)} bits (${text.length} chars)`));
        card.appendChild(el('p', { class: 'tool-copy-line', style: 'margin-top:10px' }, [
          el('strong', {}, `~${bitsPerChar.toFixed(2)} bits/char — `),
          describeEntropy(bitsPerChar)
        ]));
        resultsBox.appendChild(card);
      }

      input.addEventListener('input', recompute);

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Input string'), input
      ]));
      container.appendChild(resultsBox);
    }
  }
];
