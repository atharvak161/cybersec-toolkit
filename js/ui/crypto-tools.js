import { decodeJwt, verifyHmacJwt } from '../lib/jwt.js';
import { aesEncrypt, aesDecrypt, aesEncryptBytes, aesDecryptBytes } from '../lib/aes.js';
import { generateRsaKeypair, rsaEncrypt, rsaDecrypt } from '../lib/rsa.js';
import { parseCertificatePem } from '../lib/x509.js';
import { generateTotp } from '../lib/totp.js';
import { el, toolHeader, clear, showError, copyButton, resultLine } from './helpers.js';
import { TOOL_COPY } from '../data/tool-copy.js';

function dropZone(label, onFile) {
  const zone = el('div', {
    class: 'card',
    style: 'border:2px dashed var(--border); text-align:center; padding:32px; cursor:pointer;'
  }, label);
  const fileInput = el('input', { type: 'file', style: 'display:none' });
  zone.addEventListener('click', () => fileInput.click());
  zone.addEventListener('dragover', (e) => e.preventDefault());
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    if (e.dataTransfer.files[0]) onFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) onFile(fileInput.files[0]);
  });
  return { zone, fileInput };
}

export const CRYPTO_TOOLS = [
  {
    id: 'jwt-decoder',
    name: 'JWT Decoder / Inspector',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['jwt-decoder']));

      const input = el('textarea', { rows: '4', placeholder: 'Paste a JWT (header.payload.signature)…' });
      const decodeBtn = el('button', { class: 'btn' }, 'Decode');
      const errorNode = el('div', {});
      const resultsBox = el('div', {});

      const secretInput = el('input', { type: 'text', placeholder: 'Secret (optional, for HS256/384/512 verification)' });
      const verifyBtn = el('button', { class: 'btn secondary' }, 'Verify signature');
      const verifyResult = el('div', {});

      decodeBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(resultsBox);
        try {
          const decoded = decodeJwt(input.value);
          const card = el('div', { class: 'card' });
          card.appendChild(el('h3', {}, 'Header'));
          card.appendChild(el('pre', {}, JSON.stringify(decoded.header, null, 2)));
          card.appendChild(el('h3', {}, 'Payload'));
          card.appendChild(el('pre', {}, JSON.stringify(decoded.payload, null, 2)));
          card.appendChild(resultLine('Expiry status', decoded.expiryStatus));
          card.appendChild(resultLine('Signature present', decoded.signaturePresent));
          if (decoded.warnings.length) {
            const list = el('ul', { class: 'warning-list' });
            for (const w of decoded.warnings) list.appendChild(el('li', {}, w));
            card.appendChild(list);
          }
          resultsBox.appendChild(card);
        } catch (err) {
          showError(errorNode, err);
        }
      });

      verifyBtn.addEventListener('click', async () => {
        clear(verifyResult);
        try {
          const ok = await verifyHmacJwt(input.value, secretInput.value);
          verifyResult.appendChild(el('p', { style: ok ? 'color:var(--accent)' : 'color:var(--danger)' }, ok ? '✓ Signature valid for this secret' : '✗ Signature does NOT match this secret'));
        } catch (err) {
          showError(verifyResult, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'JWT'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [decodeBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Verify HMAC signature (optional)'), secretInput,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [verifyBtn]),
        verifyResult
      ]));
    }
  },
  {
    id: 'aes',
    name: 'AES-GCM Encrypt/Decrypt',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY.aes));

      const passphrase = el('input', { type: 'password', placeholder: 'Passphrase' });

      const plaintext = el('textarea', { rows: '3', placeholder: 'Plaintext' });
      const encryptBtn = el('button', { class: 'btn' }, 'Encrypt →');
      const ciphertextOut = el('textarea', { rows: '3', class: 'output', readonly: 'true' });

      const ciphertextIn = el('textarea', { rows: '3', placeholder: 'Ciphertext (base64 blob)' });
      const decryptBtn = el('button', { class: 'btn secondary' }, '← Decrypt');
      const plaintextOut = el('textarea', { rows: '3', class: 'output', readonly: 'true' });

      const errorNode = el('div', {});

      encryptBtn.addEventListener('click', async () => {
        clear(errorNode);
        try {
          ciphertextOut.value = await aesEncrypt(plaintext.value, passphrase.value);
        } catch (err) { showError(errorNode, err); }
      });
      decryptBtn.addEventListener('click', async () => {
        clear(errorNode);
        try {
          plaintextOut.value = await aesDecrypt(ciphertextIn.value, passphrase.value);
        } catch (err) { showError(errorNode, err); }
      });

      container.appendChild(el('div', { class: 'card' }, [el('label', {}, 'Passphrase'), passphrase]));
      container.appendChild(el('div', { class: 'grid-2' }, [
        el('div', { class: 'card' }, [
          el('label', {}, 'Plaintext'), plaintext,
          el('div', { class: 'field-row', style: 'margin-top:10px' }, [encryptBtn]),
          el('label', { style: 'margin-top:10px' }, 'Ciphertext (base64)'), ciphertextOut,
          copyButton(() => ciphertextOut.value)
        ]),
        el('div', { class: 'card' }, [
          el('label', {}, 'Ciphertext (base64)'), ciphertextIn,
          el('div', { class: 'field-row', style: 'margin-top:10px' }, [decryptBtn]),
          el('label', { style: 'margin-top:10px' }, 'Plaintext'), plaintextOut
        ])
      ]));
      container.appendChild(errorNode);
    }
  },
  {
    id: 'rsa',
    name: 'RSA Keypair + Encrypt/Decrypt',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY.rsa));

      const modulusSelect = el('select', {}, ['2048', '4096'].map((v) => el('option', { value: v }, v + ' bits')));
      const generateBtn = el('button', { class: 'btn' }, 'Generate keypair');
      const pubKeyBox = el('textarea', { rows: '6', class: 'output', readonly: 'true', placeholder: 'Public key (PEM)' });
      const privKeyBox = el('textarea', { rows: '6', class: 'output', readonly: 'true', placeholder: 'Private key (PEM)' });
      const genError = el('div', {});

      generateBtn.addEventListener('click', async () => {
        clear(genError);
        generateBtn.disabled = true;
        generateBtn.textContent = 'Generating… (may take a few seconds)';
        try {
          const { publicKeyPem, privateKeyPem } = await generateRsaKeypair(Number(modulusSelect.value));
          pubKeyBox.value = publicKeyPem;
          privKeyBox.value = privateKeyPem;
        } catch (err) { showError(genError, err); }
        generateBtn.disabled = false;
        generateBtn.textContent = 'Generate keypair';
      });

      const plaintext = el('textarea', { rows: '2', placeholder: 'Message to encrypt' });
      const encryptBtn = el('button', { class: 'btn' }, 'Encrypt with public key →');
      const ciphertextOut = el('textarea', { rows: '3', class: 'output', readonly: 'true' });
      const ciphertextIn = el('textarea', { rows: '3', placeholder: 'Ciphertext (base64)' });
      const decryptBtn = el('button', { class: 'btn secondary' }, '← Decrypt with private key');
      const plaintextOut = el('textarea', { rows: '2', class: 'output', readonly: 'true' });
      const opError = el('div', {});

      encryptBtn.addEventListener('click', async () => {
        clear(opError);
        try { ciphertextOut.value = await rsaEncrypt(plaintext.value, pubKeyBox.value); } catch (err) { showError(opError, err); }
      });
      decryptBtn.addEventListener('click', async () => {
        clear(opError);
        try { plaintextOut.value = await rsaDecrypt(ciphertextIn.value, privKeyBox.value); } catch (err) { showError(opError, err); }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'Modulus length'), modulusSelect, generateBtn]),
        genError,
        el('div', { class: 'grid-2', style: 'margin-top:10px' }, [
          el('div', {}, [el('label', {}, 'Public key'), pubKeyBox, copyButton(() => pubKeyBox.value)]),
          el('div', {}, [el('label', {}, 'Private key'), privKeyBox, copyButton(() => privKeyBox.value)])
        ])
      ]));

      container.appendChild(el('div', { class: 'grid-2' }, [
        el('div', { class: 'card' }, [
          el('label', {}, 'Plaintext'), plaintext,
          el('div', { class: 'field-row', style: 'margin-top:10px' }, [encryptBtn]),
          el('label', { style: 'margin-top:10px' }, 'Ciphertext (base64)'), ciphertextOut
        ]),
        el('div', { class: 'card' }, [
          el('label', {}, 'Ciphertext (base64)'), ciphertextIn,
          el('div', { class: 'field-row', style: 'margin-top:10px' }, [decryptBtn]),
          el('label', { style: 'margin-top:10px' }, 'Decrypted plaintext'), plaintextOut
        ])
      ]));
      container.appendChild(opError);
    }
  },
  {
    id: 'file-aes',
    name: 'File Encryption/Decryption',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['file-aes']));

      const passphrase = el('input', { type: 'password', placeholder: 'Passphrase' });
      const statusNode = el('div', {});
      const errorNode = el('div', {});
      const downloadArea = el('div', { style: 'margin-top:10px' });
      let loadedFile = null;

      const { zone, fileInput } = dropZone('Click or drag any file here (to encrypt, or a .enc file to decrypt)', (file) => {
        loadedFile = file;
        clear(statusNode);
        clear(downloadArea);
        statusNode.appendChild(el('p', { class: 'tool-desc' }, `Loaded "${file.name}" (${file.size.toLocaleString()} bytes).`));
      });

      const encryptBtn = el('button', { class: 'btn' }, 'Encrypt file →');
      const decryptBtn = el('button', { class: 'btn secondary' }, '← Decrypt file');

      encryptBtn.addEventListener('click', async () => {
        clear(errorNode);
        clear(downloadArea);
        if (!loadedFile) return showError(errorNode, new Error('Load a file first'));
        if (!passphrase.value) return showError(errorNode, new Error('Enter a passphrase'));
        try {
          const bytes = new Uint8Array(await loadedFile.arrayBuffer());
          const packed = await aesEncryptBytes(bytes, passphrase.value);
          const blob = new Blob([packed], { type: 'application/octet-stream' });
          const url = URL.createObjectURL(blob);
          downloadArea.appendChild(el('a', { href: url, download: loadedFile.name + '.enc', class: 'btn' }, `Download ${loadedFile.name}.enc`));
        } catch (err) {
          showError(errorNode, err);
        }
      });

      decryptBtn.addEventListener('click', async () => {
        clear(errorNode);
        clear(downloadArea);
        if (!loadedFile) return showError(errorNode, new Error('Load an encrypted file first'));
        if (!passphrase.value) return showError(errorNode, new Error('Enter the passphrase'));
        try {
          const packed = new Uint8Array(await loadedFile.arrayBuffer());
          const plainBytes = await aesDecryptBytes(packed, passphrase.value);
          const blob = new Blob([plainBytes], { type: 'application/octet-stream' });
          const url = URL.createObjectURL(blob);
          const outName = loadedFile.name.endsWith('.enc') ? loadedFile.name.slice(0, -4) : 'decrypted-' + loadedFile.name;
          downloadArea.appendChild(el('a', { href: url, download: outName, class: 'btn' }, `Download ${outName}`));
        } catch (err) {
          showError(errorNode, new Error('Decryption failed — wrong passphrase, or file is not a valid encrypted blob from this tool.'));
        }
      });

      container.appendChild(el('div', { class: 'card' }, [el('label', {}, 'Passphrase'), passphrase]));
      container.appendChild(zone);
      container.appendChild(fileInput);
      container.appendChild(statusNode);
      container.appendChild(el('div', { class: 'field-row', style: 'margin-top:10px' }, [encryptBtn, decryptBtn]));
      container.appendChild(errorNode);
      container.appendChild(downloadArea);
    }
  },
  {
    id: 'totp',
    name: 'TOTP / 2FA Code Generator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY.totp));

      const secretInput = el('input', { type: 'text', placeholder: 'Base32 secret, e.g. JBSWY3DPEHPK3PXP' });
      const algoSelect = el('select', {}, ['SHA-1', 'SHA-256', 'SHA-512'].map((a) => el('option', { value: a }, a)));
      const digitsSelect = el('select', {}, ['6', '8'].map((d) => el('option', { value: d }, d + ' digits')));
      const periodInput = el('input', { type: 'number', value: '30', style: 'width:80px' });
      const startBtn = el('button', { class: 'btn' }, 'Generate live code');
      const codeDisplay = el('div', { style: 'font-family:var(--mono); font-size:34px; letter-spacing:0.08em; margin:12px 0; color:var(--accent)', class: 'tabular-nums' }, '——— ———');
      const countdownDisplay = el('div', { class: 'tool-desc' }, '');
      const errorNode = el('div', {});
      let intervalHandle = null;

      async function tick() {
        clear(errorNode);
        try {
          const { code, secondsRemaining, period } = await generateTotp(secretInput.value, {
            algorithm: algoSelect.value,
            digits: Number(digitsSelect.value),
            period: Number(periodInput.value) || 30
          });
          codeDisplay.textContent = code.slice(0, code.length / 2) + ' ' + code.slice(code.length / 2);
          countdownDisplay.textContent = `Refreshes in ${secondsRemaining}s (period: ${period}s)`;
        } catch (err) {
          showError(errorNode, err);
          clearInterval(intervalHandle);
          intervalHandle = null;
        }
      }

      startBtn.addEventListener('click', () => {
        if (intervalHandle) clearInterval(intervalHandle);
        tick();
        intervalHandle = setInterval(tick, 1000);
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Base32 secret'), secretInput,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [
          el('div', {}, [el('label', {}, 'Algorithm'), algoSelect]),
          el('div', {}, [el('label', {}, 'Digits'), digitsSelect]),
          el('div', {}, [el('label', {}, 'Period (s)'), periodInput])
        ]),
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [startBtn]),
        errorNode,
        codeDisplay,
        countdownDisplay
      ]));
    }
  },
  {
    id: 'x509',
    name: 'X.509 Certificate Decoder',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY.x509));

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
