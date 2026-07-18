/**
 * File type / magic-byte identifier: inspects the leading bytes of a
 * file to identify its true type regardless of extension.
 */

const SIGNATURES = [
  { type: 'PNG image', mime: 'image/png', bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { type: 'JPEG image', mime: 'image/jpeg', bytes: [0xff, 0xd8, 0xff] },
  { type: 'GIF image (87a)', mime: 'image/gif', bytes: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61] },
  { type: 'GIF image (89a)', mime: 'image/gif', bytes: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61] },
  { type: 'PDF document', mime: 'application/pdf', bytes: [0x25, 0x50, 0x44, 0x46] },
  { type: 'ZIP archive (or docx/xlsx/pptx/jar/apk)', mime: 'application/zip', bytes: [0x50, 0x4b, 0x03, 0x04] },
  { type: 'ZIP archive (empty)', mime: 'application/zip', bytes: [0x50, 0x4b, 0x05, 0x06] },
  { type: 'GZIP archive', mime: 'application/gzip', bytes: [0x1f, 0x8b] },
  { type: 'BMP image', mime: 'image/bmp', bytes: [0x42, 0x4d] },
  { type: 'WEBP image', mime: 'image/webp', bytes: [0x52, 0x49, 0x46, 0x46], offset: 0, extraCheck: (b) => b.length >= 12 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50 },
  { type: 'ELF executable', mime: 'application/x-elf', bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { type: 'Windows PE executable (EXE/DLL)', mime: 'application/x-msdownload', bytes: [0x4d, 0x5a] },
  { type: 'RAR archive (v1.5+)', mime: 'application/vnd.rar', bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00] },
  { type: 'RAR archive (v5+)', mime: 'application/vnd.rar', bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00] },
  { type: '7-Zip archive', mime: 'application/x-7z-compressed', bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { type: 'MP3 audio (ID3)', mime: 'audio/mpeg', bytes: [0x49, 0x44, 0x33] },
  { type: 'FLAC audio', mime: 'audio/flac', bytes: [0x66, 0x4c, 0x61, 0x43] },
  { type: 'WAV audio', mime: 'audio/wav', bytes: [0x52, 0x49, 0x46, 0x46], extraCheck: (b) => b.length >= 12 && b[8] === 0x57 && b[9] === 0x41 && b[10] === 0x56 && b[11] === 0x45 },
  { type: 'MP4/MOV video', mime: 'video/mp4', bytes: [0x66, 0x74, 0x79, 0x70], offset: 4 },
  { type: 'SQLite database', mime: 'application/x-sqlite3', bytes: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00] },
  { type: 'Class file (Java bytecode)', mime: 'application/java-vm', bytes: [0xca, 0xfe, 0xba, 0xbe] }
];

/**
 * Identify a file's true type from its magic bytes.
 * @param {Uint8Array|ArrayBuffer} data first ~32 bytes are sufficient
 * @returns {{ type: string, mime: string } | null}
 */
export function identifyFileType(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  for (const sig of SIGNATURES) {
    const offset = sig.offset || 0;
    if (bytes.length < offset + sig.bytes.length) continue;
    let matches = true;
    for (let i = 0; i < sig.bytes.length; i++) {
      if (bytes[offset + i] !== sig.bytes[i]) {
        matches = false;
        break;
      }
    }
    if (matches && (!sig.extraCheck || sig.extraCheck(bytes))) {
      return { type: sig.type, mime: sig.mime };
    }
  }
  return null;
}
