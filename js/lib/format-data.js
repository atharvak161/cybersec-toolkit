/**
 * JSON / XML / YAML formatter + validator.
 *
 * - JSON: uses the built-in JSON.parse/JSON.stringify (part of the JS
 *   language, not a third-party dependency) — full spec support.
 * - XML: a small hand-written well-formedness parser + pretty-printer.
 *   Supported: elements, attributes, nested elements, text content,
 *   comments, CDATA sections, self-closing tags, the <?xml ... ?>
 *   declaration and <!DOCTYPE ...> (both passed through/ignored).
 *   NOT supported: external entities, DTD validation, namespaces beyond
 *   treating "prefix:tag" as an opaque tag name, processing instructions
 *   other than the leading XML declaration. This is a formatter/validator
 *   for well-formedness, not a full XML 1.0 conformance parser.
 * - YAML: a small hand-written parser covering the common subset used in
 *   config files: block mappings and sequences (indentation-based),
 *   scalars (strings/numbers/booleans/null), single/double-quoted
 *   strings, and comments. NOT supported: flow collections ({..}/[..]),
 *   multi-line block scalars (| and >), anchors/aliases (&/*), explicit
 *   tags (!!str etc.), multi-document streams (---/...). Documents using
 *   those features will throw a descriptive "unsupported YAML feature"
 *   error rather than silently mis-parsing.
 */

// ============================================================
// JSON
// ============================================================

export function formatJson(text, indent = 2) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error('Invalid JSON: ' + err.message);
  }
  return JSON.stringify(parsed, null, indent);
}

// ============================================================
// XML
// ============================================================

function parseXml(text) {
  let src = text.replace(/<\?xml[^>]*\?>/, '').replace(/<!DOCTYPE[^>]*>/i, '').trim();
  let pos = 0;

  function error(msg) {
    throw new Error(`Invalid XML at position ${pos}: ${msg}`);
  }

  function skipWhitespace() {
    while (pos < src.length && /\s/.test(src[pos])) pos++;
  }

  function parseNode() {
    skipWhitespace();
    if (src.startsWith('<!--', pos)) {
      const end = src.indexOf('-->', pos);
      if (end === -1) error('unterminated comment');
      const node = { type: 'comment', text: src.slice(pos + 4, end) };
      pos = end + 3;
      return node;
    }
    if (src.startsWith('<![CDATA[', pos)) {
      const end = src.indexOf(']]>', pos);
      if (end === -1) error('unterminated CDATA section');
      const node = { type: 'cdata', text: src.slice(pos + 9, end) };
      pos = end + 3;
      return node;
    }
    if (src[pos] === '<') {
      return parseElement();
    }
    // Text node
    const start = pos;
    while (pos < src.length && src[pos] !== '<') pos++;
    return { type: 'text', text: src.slice(start, pos) };
  }

  function parseElement() {
    if (src[pos] !== '<') error('expected "<"');
    pos++;
    const nameMatch = /^[^\s/>]+/.exec(src.slice(pos));
    if (!nameMatch) error('expected element name');
    const name = nameMatch[0];
    pos += name.length;

    const attrs = {};
    while (true) {
      skipWhitespace();
      if (src.startsWith('/>', pos)) {
        pos += 2;
        return { type: 'element', name, attrs, children: [] };
      }
      if (src[pos] === '>') {
        pos++;
        break;
      }
      const attrMatch = /^([^\s=/>]+)\s*=\s*("([^"]*)"|'([^']*)')/.exec(src.slice(pos));
      if (!attrMatch) error(`malformed attribute near "${src.slice(pos, pos + 20)}"`);
      attrs[attrMatch[1]] = attrMatch[3] !== undefined ? attrMatch[3] : attrMatch[4];
      pos += attrMatch[0].length;
    }

    const children = [];
    while (true) {
      skipWhitespace();
      if (pos >= src.length) error(`unexpected end of input, unclosed tag <${name}>`);
      if (src.startsWith('</', pos)) {
        const closeMatch = /^<\/([^\s>]+)\s*>/.exec(src.slice(pos));
        if (!closeMatch) error('malformed closing tag');
        if (closeMatch[1] !== name) error(`mismatched closing tag: expected </${name}> got </${closeMatch[1]}>`);
        pos += closeMatch[0].length;
        break;
      }
      const child = parseNode();
      if (child.type !== 'text' || child.text.trim() !== '') children.push(child);
    }
    return { type: 'element', name, attrs, children };
  }

  skipWhitespace();
  if (pos >= src.length) throw new Error('Invalid XML: empty document');
  const root = parseNode();
  skipWhitespace();
  if (pos < src.length) throw new Error(`Invalid XML: unexpected trailing content at position ${pos} (multiple root elements?)`);
  if (root.type !== 'element') throw new Error('Invalid XML: document must have a root element');
  return root;
}

function serializeXml(node, depth = 0) {
  const indent = '  '.repeat(depth);
  if (node.type === 'text') return indent + node.text.trim();
  if (node.type === 'comment') return `${indent}<!--${node.text}-->`;
  if (node.type === 'cdata') return `${indent}<![CDATA[${node.text}]]>`;

  const attrStr = Object.entries(node.attrs)
    .map(([k, v]) => ` ${k}="${v}"`)
    .join('');

  if (node.children.length === 0) return `${indent}<${node.name}${attrStr} />`;

  // Single text-only child renders inline for readability.
  if (node.children.length === 1 && node.children[0].type === 'text') {
    return `${indent}<${node.name}${attrStr}>${node.children[0].text.trim()}</${node.name}>`;
  }

  const inner = node.children.map((c) => serializeXml(c, depth + 1)).join('\n');
  return `${indent}<${node.name}${attrStr}>\n${inner}\n${indent}</${node.name}>`;
}

export function formatXml(text) {
  const root = parseXml(text);
  return serializeXml(root, 0);
}

export { parseXml, serializeXml };

// ============================================================
// YAML (documented subset — see file header)
// ============================================================

const UNSUPPORTED_YAML_PATTERNS = [
  { re: /^\s*---/m, msg: 'multi-document streams (---) are not supported' },
  { re: /&\w+/, msg: 'anchors (&name) are not supported' },
  { re: /\*\w+/, msg: 'aliases (*name) are not supported' },
  { re: /^\s*[^#\n]*:\s*[|>]/m, msg: 'block scalars (| and >) are not supported' },
  { re: /!!\w+/, msg: 'explicit tags (!!type) are not supported' }
];

function stripComment(line) {
  // Strip a trailing # comment, but not one inside a quoted string.
  let inSingle = false, inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function coerceScalar(raw) {
  const s = raw.trim();
  if (s === '' || s === '~' || s === 'null' || s === 'Null' || s === 'NULL') return null;
  if (s === 'true' || s === 'True' || s === 'TRUE') return true;
  if (s === 'false' || s === 'False' || s === 'FALSE') return false;
  if (/^"([^"\\]|\\.)*"$/.test(s)) return JSON.parse(s);
  if (/^'.*'$/.test(s)) return s.slice(1, -1).replace(/''/g, "'");
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^-?\d*\.\d+$/.test(s)) return parseFloat(s);
  if (/^\[.*\]$/.test(s) || /^\{.*\}$/.test(s)) {
    throw new Error('Flow-style collections ({...} / [...]) are not supported by this formatter\'s YAML subset');
  }
  return s;
}

function indentOf(line) {
  const m = /^(\s*)/.exec(line);
  return m[1].length;
}

/** Parses the documented YAML subset into a plain JS value. */
export function parseYaml(text) {
  for (const { re, msg } of UNSUPPORTED_YAML_PATTERNS) {
    if (re.test(text)) throw new Error('Unsupported YAML feature: ' + msg);
  }

  const rawLines = text.split(/\r?\n/);
  const lines = [];
  for (const line of rawLines) {
    const stripped = stripComment(line).replace(/\s+$/, '');
    if (stripped.trim() === '') continue;
    lines.push({ indent: indentOf(stripped), text: stripped.trim() });
  }
  if (lines.length === 0) return null;

  let cursor = 0;

  function parseBlock(minIndent) {
    if (cursor >= lines.length || lines[cursor].indent < minIndent) return undefined;
    const blockIndent = lines[cursor].indent;

    if (lines[cursor].text.startsWith('- ') || lines[cursor].text === '-') {
      return parseSequence(blockIndent);
    }
    return parseMapping(blockIndent);
  }

  function parseSequence(blockIndent) {
    const arr = [];
    while (cursor < lines.length && lines[cursor].indent === blockIndent && (lines[cursor].text.startsWith('- ') || lines[cursor].text === '-')) {
      const line = lines[cursor];
      const rest = line.text === '-' ? '' : line.text.slice(2);
      if (rest === '') {
        cursor++;
        const nested = parseBlock(blockIndent + 1);
        arr.push(nested === undefined ? null : nested);
      } else if (/^[^:]+:(\s|$)/.test(rest)) {
        // Inline "- key: value" starts a mapping at this item's column.
        const virtualIndent = line.indent + (line.text.length - rest.length);
        lines[cursor] = { indent: virtualIndent, text: rest };
        arr.push(parseMapping(virtualIndent));
      } else {
        cursor++;
        arr.push(coerceScalar(rest));
      }
    }
    return arr;
  }

  function parseMapping(blockIndent) {
    const obj = {};
    while (cursor < lines.length && lines[cursor].indent === blockIndent) {
      const line = lines[cursor];
      if (line.text.startsWith('- ')) break; // handled by caller as a sequence
      const idx = findKeyColon(line.text);
      if (idx === -1) throw new Error(`Invalid YAML: expected "key: value" at "${line.text}"`);
      const key = unquoteKey(line.text.slice(0, idx).trim());
      const rest = line.text.slice(idx + 1).trim();
      cursor++;
      if (rest === '') {
        const nested = parseBlock(blockIndent + 1);
        obj[key] = nested === undefined ? null : nested;
      } else {
        obj[key] = coerceScalar(rest);
      }
    }
    return obj;
  }

  function findKeyColon(text) {
    let inSingle = false, inDouble = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch === "'" && !inDouble) inSingle = !inSingle;
      else if (ch === '"' && !inSingle) inDouble = !inDouble;
      else if (ch === ':' && !inSingle && !inDouble && (i === text.length - 1 || text[i + 1] === ' ')) return i;
    }
    return -1;
  }

  function unquoteKey(key) {
    if (/^".*"$/.test(key)) return JSON.parse(key);
    if (/^'.*'$/.test(key)) return key.slice(1, -1);
    return key;
  }

  const result = parseBlock(0);
  if (cursor < lines.length) throw new Error(`Invalid YAML: unexpected content at "${lines[cursor].text}"`);
  return result;
}

function yamlScalarString(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  if (typeof value === 'string') {
    if (value === '' || /^[\s]|[\s]$|[:#\[\]{}&*!|>'"%@`]/.test(value) || /^(true|false|null|~|-?\d+(\.\d+)?)$/i.test(value)) {
      return JSON.stringify(value);
    }
    return value;
  }
  return String(value);
}

function serializeYaml(value, indent = 0) {
  const pad = '  '.repeat(indent);
  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}[]`;
    return value
      .map((item) => {
        if (item !== null && typeof item === 'object') {
          const nested = serializeYaml(item, indent + 1).split('\n');
          nested[0] = nested[0].replace(/^\s+/, '');
          return `${pad}- ${nested.join('\n')}`;
        }
        return `${pad}- ${yamlScalarString(item)}`;
      })
      .join('\n');
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) return `${pad}{}`;
    return keys
      .map((key) => {
        const v = value[key];
        if (v !== null && typeof v === 'object' && Object.keys(v).length !== 0 && !(Array.isArray(v) && v.length === 0)) {
          return `${pad}${key}:\n${serializeYaml(v, indent + 1)}`;
        }
        return `${pad}${key}: ${yamlScalarString(v)}`;
      })
      .join('\n');
  }
  return `${pad}${yamlScalarString(value)}`;
}

export function formatYaml(text) {
  const parsed = parseYaml(text);
  return serializeYaml(parsed, 0);
}

export { serializeYaml };
