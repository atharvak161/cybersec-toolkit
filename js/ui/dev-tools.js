/**
 * Developer Utilities: Regex Tester, Text Diff, Epoch Converter, QR
 * Code, JSON/XML/YAML Formatter, Homoglyph Detector, Phishing URL
 * Checker. (X.509 moved to Cryptography in v3; Phishing Checker moved
 * in from Network in v3 — see design spec §1 "Notable regroupings".)
 */

import { autoDetectEpoch, isoToEpochSeconds, isoToEpochMillis } from '../lib/epoch.js';
import { diffLines, diffSummary } from '../lib/diff.js';
import { qrEncode } from '../lib/qr-encode.js';
import { qrDecode } from '../lib/qr-decode.js';
import { testRegex, COMMON_PATTERNS } from '../lib/regex-patterns.js';
import { analyzeUrl } from '../lib/phishing.js';
import { formatJson, formatXml, formatYaml } from '../lib/format-data.js';
import { detectHomoglyphs } from '../lib/homoglyph.js';
import { el, toolHeader, clear, resultLine, showError, copyButton } from './helpers.js';
import { TOOL_COPY } from '../data/tool-copy.js';

export const DEV_TOOLS = [
  {
    id: 'regex-tester',
    name: 'Regex Tester',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['regex-tester']));

      const presetSelect = el('select', {}, [
        el('option', { value: '' }, '— pick a common pattern —'),
        ...COMMON_PATTERNS.map((p) => el('option', { value: p.name }, p.name))
      ]);
      const patternInput = el('input', { type: 'text', placeholder: 'Regex pattern (without slashes)' });
      const flagsInput = el('input', { type: 'text', placeholder: 'Flags e.g. gi', value: 'g' });
      const textInput = el('textarea', { rows: '5', placeholder: 'Text to search…' });
      const runBtn = el('button', { class: 'btn' }, 'Test');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      presetSelect.addEventListener('change', () => {
        const preset = COMMON_PATTERNS.find((p) => p.name === presetSelect.value);
        if (preset) {
          patternInput.value = preset.pattern;
          flagsInput.value = preset.flags + 'g';
        }
      });

      runBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(resultsBox);
        try {
          const matches = testRegex(patternInput.value, flagsInput.value, textInput.value);
          resultsBox.appendChild(el('p', { class: 'tool-desc' }, `${matches.length} match${matches.length === 1 ? '' : 'es'}`));
          const table = el('table', { class: 'data-table' }, [
            el('tr', {}, [el('th', {}, '#'), el('th', {}, 'Match'), el('th', {}, 'Index'), el('th', {}, 'Groups')]),
            ...matches.map((m, i) => el('tr', {}, [
              el('td', {}, String(i + 1)), el('td', {}, m.match), el('td', {}, String(m.index)),
              el('td', {}, m.groups.filter((g) => g !== undefined).join(', ') || '—')
            ]))
          ]);
          resultsBox.appendChild(table);
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'Preset'), presetSelect]),
        el('div', { class: 'field-row' }, [
          el('div', { style: 'flex:1' }, [el('label', {}, 'Pattern'), patternInput]),
          el('div', { style: 'width:120px' }, [el('label', {}, 'Flags'), flagsInput])
        ]),
        el('label', { style: 'margin-top:10px' }, 'Text'), textInput,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'text-diff',
    name: 'Text Diff',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['text-diff']));

      const textA = el('textarea', { rows: '8', placeholder: 'Original text…' });
      const textB = el('textarea', { rows: '8', placeholder: 'Changed text…' });
      const runBtn = el('button', { class: 'btn' }, 'Diff');
      const summaryLine = el('div', {});
      const resultsBox = el('div', { class: 'card' });

      runBtn.addEventListener('click', () => {
        clear(resultsBox);
        clear(summaryLine);
        const result = diffLines(textA.value, textB.value);
        const summary = diffSummary(result);
        summaryLine.appendChild(el('p', { class: 'tool-desc' }, `${summary.equal} unchanged, ${summary.add} added, ${summary.remove} removed`));
        for (const entry of result) {
          const prefix = entry.type === 'add' ? '+ ' : entry.type === 'remove' ? '- ' : '  ';
          resultsBox.appendChild(el('div', { class: `diff-line diff-${entry.type}` }, prefix + entry.line));
        }
      });

      container.appendChild(el('div', { class: 'grid-2' }, [
        el('div', {}, [el('label', {}, 'Text A'), textA]),
        el('div', {}, [el('label', {}, 'Text B'), textB])
      ]));
      container.appendChild(el('div', { class: 'field-row', style: 'margin:12px 0' }, [runBtn]));
      container.appendChild(summaryLine);
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'epoch',
    name: 'Epoch / Timestamp Converter',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY.epoch));

      const epochInput = el('input', { type: 'text', placeholder: 'e.g. 1700000000 or 1700000000000' });
      const toIsoBtn = el('button', { class: 'btn' }, 'Epoch → ISO');
      const isoOut = el('input', { type: 'text', readonly: 'true', class: 'tabular-nums' });

      const isoInput = el('input', { type: 'text', placeholder: 'e.g. 2023-11-14T22:13:20.000Z' });
      const toEpochBtn = el('button', { class: 'btn secondary' }, 'ISO → Epoch');
      const epochOut = el('div', {});
      const errorNode = el('div', {});

      toIsoBtn.addEventListener('click', () => {
        clear(errorNode);
        try {
          const { unit, iso } = autoDetectEpoch(epochInput.value);
          isoOut.value = `${iso} (detected: ${unit})`;
        } catch (err) { showError(errorNode, err); }
      });
      toEpochBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(epochOut);
        try {
          epochOut.appendChild(resultLine('Seconds', isoToEpochSeconds(isoInput.value)));
          epochOut.appendChild(resultLine('Milliseconds', isoToEpochMillis(isoInput.value)));
        } catch (err) { showError(errorNode, err); }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Epoch timestamp'), epochInput,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [toIsoBtn]),
        el('label', { style: 'margin-top:10px' }, 'ISO date/time'), isoOut
      ]));
      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'ISO 8601 date'), isoInput,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [toEpochBtn]),
        epochOut
      ]));
      container.appendChild(errorNode);
    }
  },
  {
    id: 'qr-code',
    name: 'QR Code Generate / Decode',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['qr-code']));

      const textInput = el('textarea', { rows: '3', placeholder: 'Text or URL to encode…' });
      const levelSelect = el('select', {}, ['M', 'L'].map((l) => el('option', { value: l }, 'Level ' + l)));
      const genBtn = el('button', { class: 'btn' }, 'Generate QR');
      const qrPreview = el('div', {});
      const genError = el('div', {});
      let lastMatrix = null;

      genBtn.addEventListener('click', () => {
        clear(genError);
        clear(qrPreview);
        try {
          const { matrix, version, level, size } = qrEncode(textInput.value, levelSelect.value);
          lastMatrix = matrix;
          qrPreview.appendChild(el('p', { class: 'tool-desc' }, `Version ${version}, level ${level}, ${size}×${size} modules`));
          const grid = el('div', { class: 'qr-preview' });
          for (const row of matrix) {
            const rowEl = el('div', { class: 'qr-row' });
            for (const cell of row) rowEl.appendChild(el('div', { class: 'qr-cell ' + (cell ? 'dark' : 'light') }));
            grid.appendChild(rowEl);
          }
          qrPreview.appendChild(grid);
        } catch (err) {
          showError(genError, err);
        }
      });

      const decodeBtn = el('button', { class: 'btn secondary' }, 'Decode the QR code above');
      const decodeOut = el('div', {});
      decodeBtn.addEventListener('click', () => {
        clear(decodeOut);
        if (!lastMatrix) return showError(decodeOut, new Error('Generate a QR code first'));
        try {
          const result = qrDecode(lastMatrix);
          decodeOut.appendChild(resultLine('Decoded text', result.text));
        } catch (err) {
          showError(decodeOut, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Text to encode'), textInput,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [levelSelect, genBtn]),
        genError
      ]));
      container.appendChild(qrPreview);
      container.appendChild(el('div', { class: 'field-row', style: 'margin:12px 0' }, [decodeBtn]));
      container.appendChild(decodeOut);
    }
  },
  {
    id: 'json-formatter',
    name: 'JSON/XML/YAML Formatter',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['json-formatter']));
      container.appendChild(el('p', { class: 'tool-copy-line' }, [
        el('strong', {}, 'Format supported: '),
        'JSON (full), XML (well-formedness — no DTD/external-entity support), YAML (block mappings/sequences and scalars — no flow collections, block scalars, anchors, or multi-document streams). See js/lib/format-data.js for the exact subset.'
      ]));

      const formatSelect = el('select', {}, ['JSON', 'XML', 'YAML'].map((f) => el('option', { value: f }, f)));
      const input = el('textarea', { rows: '10', placeholder: 'Paste JSON, XML, or YAML…' });
      const runBtn = el('button', { class: 'btn' }, 'Format & validate');
      const output = el('textarea', { rows: '10', class: 'output', readonly: 'true' });
      const errorNode = el('div', {});
      const statusNode = el('div', {});

      runBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(statusNode);
        output.value = '';
        try {
          let formatted;
          if (formatSelect.value === 'JSON') formatted = formatJson(input.value);
          else if (formatSelect.value === 'XML') formatted = formatXml(input.value);
          else formatted = formatYaml(input.value);
          output.value = formatted;
          statusNode.appendChild(el('p', { style: 'color:var(--accent); font-size:12px' }, `Valid ${formatSelect.value}.`));
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'Format'), formatSelect]),
        el('label', { style: 'margin-top:10px' }, 'Input'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode, statusNode,
        el('label', { style: 'margin-top:10px' }, 'Formatted output'), output,
        copyButton(() => output.value)
      ]));
    }
  },
  {
    id: 'homoglyph',
    name: 'Homoglyph / Lookalike Detector',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY.homoglyph));

      const input = el('textarea', { rows: '4', placeholder: 'Paste a domain, username, or any text to scan…' });
      const runBtn = el('button', { class: 'btn' }, 'Scan for lookalikes');
      const resultsBox = el('div', {});

      runBtn.addEventListener('click', () => {
        clear(resultsBox);
        const { flagged, hasMixedScript, scriptsSeen } = detectHomoglyphs(input.value);
        if (flagged.length === 0) {
          resultsBox.appendChild(el('p', { style: 'color:var(--accent)' }, '✓ No known lookalike characters found.'));
          return;
        }
        const card = el('div', { class: 'card' });
        card.appendChild(el('p', { style: `color:${hasMixedScript ? 'var(--danger)' : 'var(--warning)'}; font-weight:600` },
          `${flagged.length} suspicious character${flagged.length === 1 ? '' : 's'} found${hasMixedScript ? ' — mixed scripts detected (' + scriptsSeen.join(', ') + ')' : ''}.`
        ));
        const table = el('table', { class: 'data-table' }, [
          el('tr', {}, [el('th', {}, 'Position'), el('th', {}, 'Character'), el('th', {}, 'Codepoint'), el('th', {}, 'Script'), el('th', {}, 'Looks like'), el('th', {}, 'Unicode name')]),
          ...flagged.map((f) => el('tr', {}, [
            el('td', {}, String(f.index)), el('td', {}, f.char), el('td', { class: 'tabular-nums' }, f.codepoint),
            el('td', {}, f.script), el('td', {}, `"${f.looksLike}"`), el('td', {}, f.name)
          ]))
        ]);
        card.appendChild(table);
        resultsBox.appendChild(card);
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Text to scan'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn])
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'phishing-checker',
    name: 'Phishing URL Heuristic Checker',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['phishing-checker']));

      const input = el('input', { type: 'text', placeholder: 'https://example.com/path' });
      const runBtn = el('button', { class: 'btn' }, 'Analyze');
      const resultsBox = el('div', {});

      runBtn.addEventListener('click', () => {
        clear(resultsBox);
        const result = analyzeUrl(input.value);
        const card = el('div', { class: 'card' });
        const riskColor = { minimal: 'var(--accent)', low: 'var(--info)', medium: 'var(--warning)', high: 'var(--danger)' }[result.risk] || 'var(--text)';
        card.appendChild(el('p', { style: `color:${riskColor}; font-weight:700; font-size:16px` }, `Risk: ${result.risk.toUpperCase()} (score ${result.score}/100)`));
        const list = el('ul', {});
        for (const r of result.reasons) list.appendChild(el('li', {}, r));
        card.appendChild(list);
        resultsBox.appendChild(card);
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'URL'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn])
      ]));
      container.appendChild(resultsBox);
    }
  }
];
