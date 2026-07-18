/**
 * X.509 certificate / PEM decoder. Implements a small generic ASN.1 DER
 * TLV parser (hand-written — this is a binary format parser, not
 * cryptography) and walks the known X.509 structure to extract the
 * fields most useful for quick inspection: subject, issuer, validity
 * period, serial number, signature algorithm, and Subject Alternative
 * Names. This is not a full ASN.1/X.509 implementation (no signature
 * verification, no chain validation) — it is a read-only field viewer.
 */

const OID_NAMES = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '2.5.29.17': 'subjectAltName',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384'
};

function pemToDer(pem) {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');
  const binStr = typeof atob === 'function' ? atob(base64) : Buffer.from(base64, 'base64').toString('binary');
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
  return bytes;
}

/** Parse one DER TLV at `offset`. Returns { tag, length, contentStart, contentEnd, nextOffset }. */
function parseTlv(bytes, offset) {
  const tag = bytes[offset];
  let lenByte = bytes[offset + 1];
  let length;
  let lenBytesUsed = 1;
  if (lenByte & 0x80) {
    const numLenBytes = lenByte & 0x7f;
    length = 0;
    for (let i = 0; i < numLenBytes; i++) length = (length << 8) | bytes[offset + 2 + i];
    lenBytesUsed = 1 + numLenBytes;
  } else {
    length = lenByte;
  }
  const contentStart = offset + 1 + lenBytesUsed;
  const contentEnd = contentStart + length;
  return { tag, length, contentStart, contentEnd, nextOffset: contentEnd };
}

function isConstructed(tag) {
  return (tag & 0x20) !== 0;
}

function parseOid(bytes, start, end) {
  const parts = [];
  let first = true;
  let value = 0;
  for (let i = start; i < end; i++) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      if (first) {
        parts.push(Math.floor(value / 40));
        parts.push(value % 40);
        first = false;
      } else {
        parts.push(value);
      }
      value = 0;
    }
  }
  return parts.join('.');
}

function parseInteger(bytes, start, end) {
  let hex = '';
  for (let i = start; i < end; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

function derTimeToDate(bytes, start, end, isUtcTime) {
  const str = String.fromCharCode(...bytes.slice(start, end));
  // UTCTime: YYMMDDHHMMSSZ, GeneralizedTime: YYYYMMDDHHMMSSZ
  let year, rest;
  if (isUtcTime) {
    const yy = parseInt(str.slice(0, 2), 10);
    year = yy < 50 ? 2000 + yy : 1900 + yy;
    rest = str.slice(2);
  } else {
    year = parseInt(str.slice(0, 4), 10);
    rest = str.slice(4);
  }
  const month = parseInt(rest.slice(0, 2), 10);
  const day = parseInt(rest.slice(2, 4), 10);
  const hour = parseInt(rest.slice(4, 6), 10);
  const min = parseInt(rest.slice(6, 8), 10);
  const sec = parseInt(rest.slice(8, 10), 10) || 0;
  return new Date(Date.UTC(year, month - 1, day, hour, min, sec));
}

function parseName(bytes, start, end) {
  // SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeAndValue)
  const parts = [];
  let offset = start;
  while (offset < end) {
    const rdnSet = parseTlv(bytes, offset); // SET
    let innerOffset = rdnSet.contentStart;
    while (innerOffset < rdnSet.contentEnd) {
      const atav = parseTlv(bytes, innerOffset); // SEQUENCE
      const oidTlv = parseTlv(bytes, atav.contentStart);
      const oid = parseOid(bytes, oidTlv.contentStart, oidTlv.contentEnd);
      const valTlv = parseTlv(bytes, oidTlv.nextOffset);
      const value = new TextDecoder().decode(bytes.slice(valTlv.contentStart, valTlv.contentEnd));
      parts.push({ oid, name: OID_NAMES[oid] || oid, value });
      innerOffset = atav.nextOffset;
    }
    offset = rdnSet.nextOffset;
  }
  return parts;
}

function nameToString(parts) {
  return parts.map((p) => `${p.name}=${p.value}`).join(', ');
}

function parseSubjectAltNames(bytes, start, end) {
  const sans = [];
  let offset = start;
  while (offset < end) {
    const item = parseTlv(bytes, offset);
    const ctxTag = item.tag & 0x1f;
    const typeMap = { 1: 'email', 2: 'DNS', 6: 'URI', 7: 'IP' };
    const type = typeMap[ctxTag] || `type${ctxTag}`;
    let value;
    if (ctxTag === 7) {
      value = Array.from(bytes.slice(item.contentStart, item.contentEnd)).join('.');
    } else {
      value = new TextDecoder().decode(bytes.slice(item.contentStart, item.contentEnd));
    }
    sans.push({ type, value });
    offset = item.nextOffset;
  }
  return sans;
}

/**
 * Parse a PEM-encoded X.509 certificate and return a plain object with
 * the commonly-inspected fields.
 */
export function parseCertificatePem(pem) {
  const bytes = pemToDer(pem);

  const certSeq = parseTlv(bytes, 0); // Certificate ::= SEQUENCE
  const tbsSeq = parseTlv(bytes, certSeq.contentStart); // tbsCertificate ::= SEQUENCE
  let offset = tbsSeq.contentStart;

  // [0] version (optional, context tag 0xa0) — EXPLICIT
  let versionTlv = parseTlv(bytes, offset);
  let version = 1;
  if (versionTlv.tag === 0xa0) {
    const inner = parseTlv(bytes, versionTlv.contentStart);
    version = parseInt(parseInteger(bytes, inner.contentStart, inner.contentEnd), 16) + 1;
    offset = versionTlv.nextOffset;
  }

  const serialTlv = parseTlv(bytes, offset);
  const serialNumber = parseInteger(bytes, serialTlv.contentStart, serialTlv.contentEnd);
  offset = serialTlv.nextOffset;

  const sigAlgTlv = parseTlv(bytes, offset); // SEQUENCE
  const sigAlgOidTlv = parseTlv(bytes, sigAlgTlv.contentStart);
  const sigAlgOid = parseOid(bytes, sigAlgOidTlv.contentStart, sigAlgOidTlv.contentEnd);
  offset = sigAlgTlv.nextOffset;

  const issuerTlv = parseTlv(bytes, offset);
  const issuer = parseName(bytes, issuerTlv.contentStart, issuerTlv.contentEnd);
  offset = issuerTlv.nextOffset;

  const validityTlv = parseTlv(bytes, offset); // SEQUENCE of two times
  const notBeforeTlv = parseTlv(bytes, validityTlv.contentStart);
  const notBefore = derTimeToDate(bytes, notBeforeTlv.contentStart, notBeforeTlv.contentEnd, notBeforeTlv.tag === 0x17);
  const notAfterTlv = parseTlv(bytes, notBeforeTlv.nextOffset);
  const notAfter = derTimeToDate(bytes, notAfterTlv.contentStart, notAfterTlv.contentEnd, notAfterTlv.tag === 0x17);
  offset = validityTlv.nextOffset;

  const subjectTlv = parseTlv(bytes, offset);
  const subject = parseName(bytes, subjectTlv.contentStart, subjectTlv.contentEnd);
  offset = subjectTlv.nextOffset;

  // Remaining: subjectPublicKeyInfo, then optional [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions
  const spkiTlv = parseTlv(bytes, offset);
  offset = spkiTlv.nextOffset;

  let subjectAltNames = [];
  while (offset < tbsSeq.contentEnd) {
    const ctxTlv = parseTlv(bytes, offset);
    if (ctxTlv.tag === 0xa3) {
      // extensions ::= [3] EXPLICIT SEQUENCE OF Extension
      const extSeq = parseTlv(bytes, ctxTlv.contentStart);
      let extOffset = extSeq.contentStart;
      while (extOffset < extSeq.contentEnd) {
        const ext = parseTlv(bytes, extOffset); // SEQUENCE
        const extOidTlv = parseTlv(bytes, ext.contentStart);
        const extOid = parseOid(bytes, extOidTlv.contentStart, extOidTlv.contentEnd);
        let nextField = parseTlv(bytes, extOidTlv.nextOffset);
        let valueTlv = nextField;
        if (nextField.tag === 0x01) {
          // critical BOOLEAN, skip to actual OCTET STRING
          valueTlv = parseTlv(bytes, nextField.nextOffset);
        }
        if (extOid === '2.5.29.17') {
          const sanSeqTlv = parseTlv(bytes, valueTlv.contentStart); // OCTET STRING wraps a SEQUENCE
          subjectAltNames = parseSubjectAltNames(bytes, sanSeqTlv.contentStart, sanSeqTlv.contentEnd);
        }
        extOffset = ext.nextOffset;
      }
    }
    offset = ctxTlv.nextOffset;
  }

  const now = new Date();
  return {
    version,
    serialNumber,
    signatureAlgorithm: OID_NAMES[sigAlgOid] || sigAlgOid,
    issuer,
    issuerString: nameToString(issuer),
    subject,
    subjectString: nameToString(subject),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    isExpired: now > notAfter,
    isNotYetValid: now < notBefore,
    subjectAltNames
  };
}
