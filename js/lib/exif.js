/**
 * Minimal EXIF metadata reader/stripper for JPEG images. Parses the
 * APP1 "Exif" segment's TIFF structure for a useful common-tag subset,
 * and provides a stripper that removes all APP1/APPn metadata segments
 * while keeping the image data intact. Hand-written (not a security
 * primitive — plain binary format parsing), covers the common tag set
 * rather than the full EXIF/TIFF spec.
 */

const TAG_NAMES = {
  0x010f: 'Make',
  0x0110: 'Model',
  0x0112: 'Orientation',
  0x011a: 'XResolution',
  0x011b: 'YResolution',
  0x0131: 'Software',
  0x0132: 'DateTime',
  0x8769: 'ExifIFDPointer',
  0x8825: 'GPSInfoIFDPointer',
  0x829a: 'ExposureTime',
  0x829d: 'FNumber',
  0x8827: 'ISOSpeedRatings',
  0x9003: 'DateTimeOriginal',
  0x9004: 'DateTimeDigitized',
  0x920a: 'FocalLength',
  0xa002: 'PixelXDimension',
  0xa003: 'PixelYDimension'
};

const GPS_TAG_NAMES = {
  0x0001: 'GPSLatitudeRef',
  0x0002: 'GPSLatitude',
  0x0003: 'GPSLongitudeRef',
  0x0004: 'GPSLongitude',
  0x0006: 'GPSAltitude'
};

function findExifSegment(view) {
  if (view.getUint16(0, false) !== 0xffd8) throw new Error('Not a JPEG file (missing SOI marker)');
  let offset = 2;
  while (offset < view.byteLength - 4) {
    const marker = view.getUint16(offset, false);
    if ((marker & 0xff00) !== 0xff00) break;
    const size = view.getUint16(offset + 2, false);
    if (marker === 0xffe1) {
      const tag = String.fromCharCode(
        view.getUint8(offset + 4),
        view.getUint8(offset + 5),
        view.getUint8(offset + 6),
        view.getUint8(offset + 7)
      );
      if (tag === 'Exif') {
        return { tiffStart: offset + 10, segmentStart: offset, segmentSize: size };
      }
    }
    if (marker === 0xffda) break; // Start of Scan — no more metadata segments before image data
    offset += 2 + size;
  }
  return null;
}

function readIfd(view, tiffStart, ifdOffset, little, tagNames) {
  const entries = {};
  const count = view.getUint16(ifdOffset, little);
  for (let i = 0; i < count; i++) {
    const entryOffset = ifdOffset + 2 + i * 12;
    const tag = view.getUint16(entryOffset, little);
    const type = view.getUint16(entryOffset + 2, little);
    const numValues = view.getUint32(entryOffset + 4, little);
    const valueOffsetField = entryOffset + 8;

    const typeSizes = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };
    const size = (typeSizes[type] || 1) * numValues;
    const dataOffset = size <= 4 ? valueOffsetField : tiffStart + view.getUint32(valueOffsetField, little);

    let value;
    if (type === 2) {
      // ASCII string
      const bytes = [];
      for (let j = 0; j < numValues - 1; j++) bytes.push(view.getUint8(dataOffset + j));
      value = String.fromCharCode(...bytes);
    } else if (type === 3) {
      value = numValues === 1 ? view.getUint16(dataOffset, little) : Array.from({ length: numValues }, (_, j) => view.getUint16(dataOffset + j * 2, little));
    } else if (type === 4) {
      value = numValues === 1 ? view.getUint32(dataOffset, little) : Array.from({ length: numValues }, (_, j) => view.getUint32(dataOffset + j * 4, little));
    } else if (type === 5 || type === 10) {
      const readRational = (off) => {
        const num = type === 5 ? view.getUint32(off, little) : view.getInt32(off, little);
        const den = type === 5 ? view.getUint32(off + 4, little) : view.getInt32(off + 4, little);
        return den === 0 ? 0 : num / den;
      };
      value = numValues === 1 ? readRational(dataOffset) : Array.from({ length: numValues }, (_, j) => readRational(dataOffset + j * 8));
    } else {
      value = view.getUint32(valueOffsetField, little);
    }

    const name = tagNames[tag] || `Tag0x${tag.toString(16)}`;
    entries[name] = value;
  }
  const nextIfdOffset = view.getUint32(ifdOffset + 2 + count * 12, little);
  return { entries, nextIfdOffset };
}

/**
 * Read EXIF tags from a JPEG ArrayBuffer. Returns {} if no EXIF present.
 */
export function readExif(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const seg = findExifSegment(view);
  if (!seg) return {};

  const tiffStart = seg.tiffStart;
  const byteOrder = view.getUint16(tiffStart, false);
  const little = byteOrder === 0x4949; // 'II'
  if (byteOrder !== 0x4949 && byteOrder !== 0x4d4d) throw new Error('Invalid TIFF byte order marker');

  const firstIfdOffset = view.getUint32(tiffStart + 4, little);
  const { entries: ifd0 } = readIfd(view, tiffStart, tiffStart + firstIfdOffset, little, TAG_NAMES);

  let exifIfd = {};
  if (ifd0.ExifIFDPointer) {
    exifIfd = readIfd(view, tiffStart, tiffStart + ifd0.ExifIFDPointer, little, TAG_NAMES).entries;
  }
  let gpsIfd = {};
  if (ifd0.GPSInfoIFDPointer) {
    gpsIfd = readIfd(view, tiffStart, tiffStart + ifd0.GPSInfoIFDPointer, little, GPS_TAG_NAMES).entries;
  }

  return { ...ifd0, ...exifIfd, ...gpsIfd };
}

/**
 * Strip all APP1..APPn metadata segments from a JPEG, returning a new
 * ArrayBuffer with the same image data but no EXIF/XMP/ICC metadata.
 */
export function stripExif(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  if (view.getUint16(0, false) !== 0xffd8) throw new Error('Not a JPEG file (missing SOI marker)');

  const keepChunks = [new Uint8Array(arrayBuffer, 0, 2)]; // SOI
  let offset = 2;
  while (offset < view.byteLength - 4) {
    const marker = view.getUint16(offset, false);
    if ((marker & 0xff00) !== 0xff00) break;
    if (marker === 0xffda) {
      // Start of scan — keep everything from here to the end verbatim
      keepChunks.push(new Uint8Array(arrayBuffer, offset));
      break;
    }
    const size = view.getUint16(offset + 2, false);
    const isAppSegment = marker >= 0xffe0 && marker <= 0xffef;
    if (!isAppSegment) {
      keepChunks.push(new Uint8Array(arrayBuffer, offset, 2 + size));
    }
    offset += 2 + size;
  }

  const totalLen = keepChunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(totalLen);
  let pos = 0;
  for (const chunk of keepChunks) {
    out.set(chunk, pos);
    pos += chunk.length;
  }
  return out.buffer;
}
