import * as hashing from '../lib/hashing.js';
import { crackHashes, detectHashType } from '../lib/hash-cracker.js';
import { el, toolHeader, clear, resultLine, showError, copyButton } from './helpers.js';

export const HASHING_TOOLS = [
  {
    id: 'hash-cracker',
    name: 'Hash Cracker',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Recovers the plaintext behind MD5, SHA-1, SHA-256, and SHA-512 hashes with a real dictionary + rules attack, entirely in your browser. Paste one hash or many (one per line). It catches common and weak passwords — it can’t replicate a service like CrackStation’s multi-hundred-GB server table, and salted or bcrypt/argon2 hashes are out of reach by design.'));

      const input = el('textarea', { rows: '4', placeholder: 'Paste one or more hashes, one per line\ne.g. 5f4dcc3b5aa765d61d8327deb882cf99', style: 'width:100%; font-family:var(--mono, monospace)', spellcheck: 'false' });
      const runBtn = el('button', { class: 'btn' }, 'Crack');
      const status = el('div', { class: 'tool-desc', style: 'margin-top:6px' });
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      runBtn.addEventListener('click', async () => {
        clear(errorNode); clear(resultsBox); clear(status);
        const hashes = input.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
        if (!hashes.length) { showError(errorNode, new Error('Paste at least one hash.')); return; }
        const det = detectHashType(hashes[0]);
        status.textContent = det ? `Detected ${det.name}. Cracking against the wordlist + rules…` : 'Cracking…';
        runBtn.disabled = true;
        try {
          const out = await crackHashes(hashes, {
            onProgress: (done) => { status.textContent = `Trying candidates… ${done.toLocaleString()} hashed`; }
          });
          const cracked = out.results.filter((r) => r.plaintext !== null).length;
          status.textContent = `${out.type} · ${cracked} of ${out.results.length} cracked · ${out.tried.toLocaleString()} candidates tried`;
          const rows = out.results.map((r) => el('tr', { class: r.plaintext !== null ? 'hc-hit' : 'hc-miss' }, [
            el('td', { class: 'hc-hash tabular-nums' }, r.hash),
            el('td', { class: 'hc-plain' }, r.plaintext !== null ? r.plaintext : 'not found in wordlist + rules')
          ]));
          resultsBox.appendChild(el('table', { class: 'data-table hc-table' }, [
            el('tr', {}, [el('th', {}, 'Hash'), el('th', {}, 'Plaintext')]),
            ...rows
          ]));
          resultsBox.appendChild(el('div', { class: 'hc-note' }, 'Not cracked doesn’t mean uncrackable — it means the plaintext isn’t in this bundled wordlist or its common variations. A longer or random password, or a salted/bcrypt/argon2 hash, won’t appear here by design.'));
        } catch (err) {
          showError(errorNode, err);
        } finally {
          runBtn.disabled = false;
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Hash(es)'),
        input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        status,
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'hash-generator',
    name: 'Hash Generator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Compute MD5, SHA-1, SHA-256, SHA-512, SHA-3-256 and CRC32 of any text, all at once. SHA-1/256/512 use the browser-native Web Crypto API; MD5/SHA-3/CRC32 use this project’s hand-written reference implementations (see README).'));

      const input = el('textarea', { rows: '4', placeholder: 'Type or paste text to hash…' });
      const resultsBox = el('div', { class: 'card' });
      const runBtn = el('button', { class: 'btn' }, 'Compute hashes');
      const errorNode = el('div', {});

      runBtn.addEventListener('click', async () => {
        clear(errorNode);
        clear(resultsBox);
        try {
          const text = input.value;
          const [md5, sha1, sha256, sha512] = await Promise.all([
            Promise.resolve(hashing.md5Hex(text)),
            hashing.sha1Hex(text),
            hashing.sha256Hex(text),
            hashing.sha512Hex(text)
          ]);
          const sha3 = hashing.sha3_256Hex(text);
          const crc32 = hashing.crc32Hex(text);
          const rows = [['MD5', md5], ['SHA-1', sha1], ['SHA-256', sha256], ['SHA-3-256', sha3], ['CRC32', crc32], ['SHA-512', sha512]];
          for (const [label, value] of rows) {
            const line = resultLine(label, value);
            const btn = copyButton(() => value);
            btn.style.marginLeft = '8px';
            line.appendChild(btn);
            resultsBox.appendChild(line);
          }
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Input text'),
        input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'hmac',
    name: 'HMAC Generator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Generate an HMAC using the native Web Crypto API (never a hand-rolled implementation).'));

      const key = el('input', { type: 'text', placeholder: 'Secret key' });
      const algo = el('select', {}, ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'].map((a) => el('option', { value: a }, a)));
      const message = el('textarea', { rows: '4', placeholder: 'Message' });
      const output = el('textarea', { rows: '3', class: 'output', readonly: 'true' });
      const runBtn = el('button', { class: 'btn' }, 'Generate HMAC');
      const errorNode = el('div', {});

      runBtn.addEventListener('click', async () => {
        clear(errorNode);
        try {
          output.value = await hashing.hmacHex(algo.value, key.value, message.value);
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'Algorithm'), algo]),
        el('label', {}, 'Secret key'), key,
        el('label', { style: 'margin-top:10px' }, 'Message'), message,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode,
        el('label', { style: 'margin-top:10px' }, 'HMAC'), output,
        copyButton(() => output.value)
      ]));
    }
  },
  {
    id: 'hash-identifier',
    name: 'Hash Type Identifier',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Guess the likely algorithm(s) behind a pasted hash, based on its length and charset. Heuristic only — many algorithms share output lengths.'));

      const input = el('input', { type: 'text', placeholder: 'Paste a hash…' });
      const resultsBox = el('div', { class: 'card' });
      const runBtn = el('button', { class: 'btn' }, 'Identify');

      runBtn.addEventListener('click', () => {
        clear(resultsBox);
        const guesses = hashing.identifyHash(input.value);
        for (const g of guesses) resultsBox.appendChild(resultLine(g.algorithm, g.confidence));
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Hash'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn])
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'file-hash-checker',
    name: 'File Hash Checker',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Drop a file to compute its hashes locally (nothing uploaded) — useful for verifying file integrity against a published checksum.'));

      const dropZone = el('div', {
        class: 'card',
        style: 'border:2px dashed var(--border); text-align:center; padding:32px; cursor:pointer;'
      }, 'Click or drag a file here');
      const fileInput = el('input', { type: 'file', style: 'display:none' });
      const resultsBox = el('div', { class: 'card' });

      dropZone.addEventListener('click', () => fileInput.click());
      dropZone.addEventListener('dragover', (e) => e.preventDefault());
      dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
      });
      fileInput.addEventListener('change', () => {
        if (fileInput.files[0]) handleFile(fileInput.files[0]);
      });

      async function handleFile(file) {
        clear(resultsBox);
        resultsBox.appendChild(el('p', { class: 'tool-desc' }, `Hashing "${file.name}" (${file.size.toLocaleString()} bytes)…`));
        const buffer = await file.arrayBuffer();
        const [sha256, sha1] = await Promise.all([hashing.sha256Hex(buffer), hashing.sha1Hex(buffer)]);
        const md5 = hashing.md5Hex(new Uint8Array(buffer));
        const crc32 = hashing.crc32Hex(new Uint8Array(buffer));
        clear(resultsBox);
        for (const [label, value] of [['MD5', md5], ['SHA-1', sha1], ['SHA-256', sha256], ['CRC32', crc32]]) {
          resultsBox.appendChild(resultLine(label, value));
        }
      }

      container.appendChild(dropZone);
      container.appendChild(fileInput);
      container.appendChild(resultsBox);
    }
  }
];
