import { readExif, stripExif } from '../lib/exif.js';
import { identifyFileType } from '../lib/magic-bytes.js';
import { lsbEncode, lsbDecode, lsbCapacityBytes } from '../lib/steganography.js';
import { el, toolHeader, clear, resultLine, showError, educationalBadge } from './helpers.js';

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

export const FILES_TOOLS = [
  {
    id: 'exif',
    name: 'EXIF Viewer / Stripper',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Read EXIF metadata from a JPEG (camera make/model, timestamps, GPS if present), or strip all metadata and download a cleaned copy. Everything happens locally.'));

      const resultsBox = el('div', {});
      const downloadArea = el('div', {});

      const { zone, fileInput } = dropZone('Click or drag a JPEG here', async (file) => {
        clear(resultsBox);
        clear(downloadArea);
        try {
          const buffer = await file.arrayBuffer();
          const tags = readExif(buffer);
          if (Object.keys(tags).length === 0) {
            resultsBox.appendChild(el('p', {}, 'No EXIF metadata found in this file.'));
          } else {
            const card = el('div', { class: 'card' });
            for (const [key, value] of Object.entries(tags)) card.appendChild(resultLine(key, Array.isArray(value) ? value.join(', ') : value));
            resultsBox.appendChild(card);
          }

          const stripped = stripExif(buffer);
          const blob = new Blob([stripped], { type: 'image/jpeg' });
          const url = URL.createObjectURL(blob);
          const link = el('a', { href: url, download: 'stripped-' + file.name, class: 'btn' }, 'Download metadata-stripped copy');
          downloadArea.appendChild(link);
        } catch (err) {
          showError(resultsBox, err);
        }
      });

      container.appendChild(zone);
      container.appendChild(fileInput);
      container.appendChild(resultsBox);
      container.appendChild(downloadArea);
    }
  },
  {
    id: 'magic-bytes',
    name: 'File Type Identifier (Magic Bytes)',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Identifies a file’s true type from its leading bytes, regardless of its extension.'));

      const resultsBox = el('div', {});
      const { zone, fileInput } = dropZone('Click or drag any file here', async (file) => {
        clear(resultsBox);
        const buffer = await file.slice(0, 32).arrayBuffer();
        const result = identifyFileType(buffer);
        const card = el('div', { class: 'card' });
        card.appendChild(resultLine('File name', file.name));
        card.appendChild(resultLine('Declared type', file.type || '(none)'));
        card.appendChild(resultLine('Detected type', result ? result.type : 'Unknown (no matching signature)'));
        if (result) card.appendChild(resultLine('MIME (detected)', result.mime));
        resultsBox.appendChild(card);
      });

      container.appendChild(zone);
      container.appendChild(fileInput);
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'steganography',
    name: 'Steganography (LSB) — Educational',
    render(container) {
      clear(container);
      container.appendChild(educationalBadge('Educational — least-significant-bit steganography on PNG images.'));
      container.appendChild(toolHeader('Hide a text message in an image’s pixel data (LSB of R/G/B channels), or extract a previously hidden message. Use PNG (lossless) — JPEG compression will destroy the hidden bits.'));

      let canvas = document.createElement('canvas');
      let ctx = canvas.getContext('2d');
      let loadedImageData = null;

      const preview = el('div', {});
      const capacityLine = el('div', {});

      const { zone, fileInput } = dropZone('Click or drag a PNG image here', (file) => {
        const img = new Image();
        img.onload = () => {
          canvas.width = img.width;
          canvas.height = img.height;
          ctx.drawImage(img, 0, 0);
          loadedImageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          clear(preview);
          preview.appendChild(canvas);
          clear(capacityLine);
          capacityLine.appendChild(resultLine('Capacity', lsbCapacityBytes(canvas.width * canvas.height) + ' bytes'));
        };
        img.src = URL.createObjectURL(file);
      });

      const message = el('textarea', { rows: '3', placeholder: 'Message to hide…' });
      const encodeBtn = el('button', { class: 'btn' }, 'Embed message →');
      const decodeBtn = el('button', { class: 'btn secondary' }, 'Extract hidden message');
      const outputArea = el('div', {});
      const errorNode = el('div', {});

      encodeBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(outputArea);
        if (!loadedImageData) return showError(errorNode, new Error('Load an image first'));
        try {
          const encodedData = lsbEncode(loadedImageData.data, message.value);
          const outCanvas = document.createElement('canvas');
          outCanvas.width = canvas.width;
          outCanvas.height = canvas.height;
          const outCtx = outCanvas.getContext('2d');
          const outImageData = new ImageData(encodedData, canvas.width, canvas.height);
          outCtx.putImageData(outImageData, 0, 0);
          outCanvas.toBlob((blob) => {
            const url = URL.createObjectURL(blob);
            outputArea.appendChild(el('a', { href: url, download: 'stego-output.png', class: 'btn' }, 'Download image with hidden message'));
          });
        } catch (err) {
          showError(errorNode, err);
        }
      });

      decodeBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(outputArea);
        if (!loadedImageData) return showError(errorNode, new Error('Load an image first'));
        try {
          const hidden = lsbDecode(loadedImageData.data);
          outputArea.appendChild(resultLine('Extracted message', hidden || '(empty)'));
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(zone);
      container.appendChild(fileInput);
      container.appendChild(preview);
      container.appendChild(capacityLine);
      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Message to hide'), message,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [encodeBtn, decodeBtn]),
        errorNode, outputArea
      ]));
    }
  }
];
