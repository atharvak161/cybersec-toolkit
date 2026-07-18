import { decodeJwt, verifyHmacJwt } from '../lib/jwt.js';
import { aesEncrypt, aesDecrypt } from '../lib/aes.js';
import { generateRsaKeypair, rsaEncrypt, rsaDecrypt } from '../lib/rsa.js';
import { el, toolHeader, clear, showError, copyButton, resultLine } from './helpers.js';

export const CRYPTO_TOOLS = [
  {
    id: 'jwt-decoder',
    name: 'JWT Decoder / Inspector',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Decode a JWT’s header and payload locally. Flags alg:none and reports expiry status. Optional: verify an HS256/384/512 signature if you supply the secret (never required, never sent anywhere).'));

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
      container.appendChild(toolHeader('AES-256-GCM via the native Web Crypto API. Key is derived from your passphrase with PBKDF2 (100,000 iterations). A random salt+IV is generated per encryption and packed with the ciphertext.'));

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
      container.appendChild(toolHeader('RSA-OAEP (SHA-256) via the native Web Crypto API. Generate a keypair, then encrypt with the public key and decrypt with the private key. Message size is limited by RSA-OAEP (short messages only — for larger data, use AES and encrypt the AES key with RSA).'));

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
  }
];
