import * as enc from '../lib/encoding.js';
import * as encExtra from '../lib/encoding-extra.js';
import { morseEncode, morseDecode } from '../lib/morse.js';
import { el, ioPanel, showError, copyButton, toolHeader, clear } from './helpers.js';
import { TOOL_COPY } from '../data/tool-copy.js';

function codecTool(id, name, description, encodeFn, decodeFn) {
  return {
    id,
    name,
    render(container) {
      clear(container);
      container.appendChild(toolHeader(description));

      const encodePanel = ioPanel({ inputLabel: 'Plain text', outputLabel: 'Encoded', runLabel: 'Encode →' });
      const decodePanel = ioPanel({ inputLabel: 'Encoded text', outputLabel: 'Decoded', runLabel: '← Decode' });

      encodePanel.runBtn.addEventListener('click', () => {
        clear(encodePanel.errorNode);
        try {
          encodePanel.output.value = encodeFn(encodePanel.input.value);
        } catch (err) {
          showError(encodePanel.errorNode, err);
        }
      });
      decodePanel.runBtn.addEventListener('click', () => {
        clear(decodePanel.errorNode);
        try {
          decodePanel.output.value = decodeFn(decodePanel.input.value);
        } catch (err) {
          showError(decodePanel.errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'grid-2' }, [
        el('div', { class: 'card' }, [encodePanel.wrapper, copyButton(() => encodePanel.output.value)]),
        el('div', { class: 'card' }, [decodePanel.wrapper, copyButton(() => decodePanel.output.value)])
      ]));
    }
  };
}

export const ENCODING_TOOLS = [
  codecTool('hex', 'Hex', 'Convert text to/from hexadecimal.', enc.hexEncode, enc.hexDecode),
  codecTool('base64', 'Base64', 'Standard Base64 (RFC 4648).', (s) => enc.base64Encode(s), (s) => enc.base64Decode(s)),
  codecTool('base32', 'Base32', 'Standard Base32 (RFC 4648).', (s) => enc.base32Encode(s), (s) => enc.base32Decode(s)),
  codecTool('base58', 'Base58', 'Bitcoin-alphabet Base58 (no 0/O/I/l).', (s) => enc.base58Encode(s), (s) => enc.base58Decode(s)),
  codecTool('base85', 'Base85 (Ascii85)', 'Adobe-variant Ascii85 encoding.', (s) => encExtra.base85Encode(s), (s) => encExtra.base85Decode(s)),
  codecTool('base91', 'Base91', 'basE91 encoding — denser than Base64.', (s) => encExtra.base91Encode(s), (s) => encExtra.base91Decode(s)),
  codecTool('url', 'URL Encode/Decode', 'Percent-encoding for URLs.', enc.urlEncode, enc.urlDecode),
  codecTool('binary', 'Binary', 'Text as space-separated 8-bit binary groups.', enc.binaryEncode, enc.binaryDecode),
  codecTool('uuencode', 'UUEncode', 'Classic Unix-to-Unix encoding.', (s) => encExtra.uuEncode(s), (s) => encExtra.uuDecode(s)),
  codecTool('morse', 'Morse Code', TOOL_COPY.morse, (s) => morseEncode(s), (s) => morseDecode(s)),
  {
    id: 'rot13-caesar',
    name: 'ROT13 / Caesar Cipher',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('ROT13 is a Caesar cipher with a fixed shift of 13 (its own inverse). Use the shift field for any other Caesar shift.'));

      const shiftInput = el('input', { type: 'number', value: '13', style: 'width:80px' });
      const panel = ioPanel({ inputLabel: 'Text', outputLabel: 'Result', runLabel: 'Shift →' });

      panel.runBtn.addEventListener('click', () => {
        clear(panel.errorNode);
        try {
          const shift = parseInt(shiftInput.value, 10) || 0;
          panel.output.value = enc.caesarShift(panel.input.value, shift);
        } catch (err) {
          showError(panel.errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'Shift amount'), shiftInput]),
        panel.wrapper,
        copyButton(() => panel.output.value)
      ]));
    }
  },
  {
    id: 'punycode',
    name: 'Punycode / IDN',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Convert an internationalized domain name to its ASCII ("xn--") form and back.'));
      const panel = ioPanel({ inputLabel: 'Domain (Unicode or ASCII)', outputLabel: 'Result', runLabel: 'toASCII', multiline: false });
      const toUnicodeBtn = el('button', { class: 'btn secondary' }, 'toUnicode');
      panel.wrapper.querySelector('.field-row').appendChild(toUnicodeBtn);

      import('../lib/vendor/punycode.js').then(({ toASCII, toUnicode }) => {
        panel.runBtn.addEventListener('click', () => {
          clear(panel.errorNode);
          try { panel.output.value = toASCII(panel.input.value); } catch (err) { showError(panel.errorNode, err); }
        });
        toUnicodeBtn.addEventListener('click', () => {
          clear(panel.errorNode);
          try { panel.output.value = toUnicode(panel.input.value); } catch (err) { showError(panel.errorNode, err); }
        });
      });

      container.appendChild(el('div', { class: 'card' }, [panel.wrapper, copyButton(() => panel.output.value)]));
    }
  }
];
