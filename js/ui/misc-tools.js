import { autoDetectEpoch, isoToEpochSeconds, isoToEpochMillis } from '../lib/epoch.js';
import { diffLines, diffSummary } from '../lib/diff.js';
import { qrEncode } from '../lib/qr-encode.js';
import { qrDecode } from '../lib/qr-decode.js';
import { parseCertificatePem } from '../lib/x509.js';
import { el, toolHeader, clear, resultLine, showError, copyButton } from './helpers.js';

export const MISC_TOOLS = [
  {
    id: 'epoch',
    name: 'Epoch / Timestamp Converter',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Convert between Unix epoch time and ISO 8601, in either direction. Auto-detects seconds vs. milliseconds.'));

      const epochInput = el('input', { type: 'text', placeholder: 'e.g. 1700000000 or 1700000000000' });
      const toIsoBtn = el('button', { class: 'btn' }, 'Epoch → ISO');
      const isoOut = el('input', { type: 'text', readonly: 'true' });

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
    id: 'text-diff',
    name: 'Text Diff',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Line-based diff between two texts.'));

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
    id: 'qr-code',
    name: 'QR Code Generate / Decode',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(
        'Hand-written QR encoder/decoder (versions 1-4, byte mode, EC levels L/M — see README for why this is scoped down rather than using a vendored library). ' +
        'Decode works on this tool’s own generated codes and on clean, axis-aligned scans; it is not a full perspective-correcting photo scanner.'
      ));

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
    id: 'x509',
    name: 'X.509 Certificate Decoder',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Paste a PEM-encoded certificate to view its parsed fields. Read-only inspection — no signature or chain validation.'));

      const input = el('textarea', { rows: '10', placeholder: '-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----' });
      const runBtn = el('button', { class: 'btn' }, 'Parse certificate');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      runBtn.addEventListener('click', () => {
        clear(resultsBox);
        clear(errorNode);
        try {
          const cert = parseCertificatePem(input.value);
          const card = el('div', { class: 'card' });
          card.appendChild(resultLine('Subject', cert.subjectString));
          card.appendChild(resultLine('Issuer', cert.issuerString));
          card.appendChild(resultLine('Serial number', cert.serialNumber));
          card.appendChild(resultLine('Signature algorithm', cert.signatureAlgorithm));
          card.appendChild(resultLine('Valid from', cert.notBefore));
          card.appendChild(resultLine('Valid until', cert.notAfter));
          card.appendChild(resultLine('Expired?', cert.isExpired ? 'YES' : 'No'));
          if (cert.subjectAltNames.length) {
            card.appendChild(resultLine('SANs', cert.subjectAltNames.map((s) => `${s.type}:${s.value}`).join(', ')));
          }
          resultsBox.appendChild(card);
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Certificate (PEM)'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  }
];
