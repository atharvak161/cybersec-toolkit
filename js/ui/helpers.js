/**
 * Small shared DOM helpers used by every tool panel. No framework —
 * just thin wrappers over document.createElement to keep the tool
 * files readable.
 */

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'class') node.className = value;
    else if (key === 'html') node.innerHTML = value;
    else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2), value);
    else if (value !== undefined && value !== null) node.setAttribute(key, value);
  }
  for (const child of Array.isArray(children) ? children : [children]) {
    if (child === null || child === undefined) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function externalApiBadge(text = 'This tool calls an external API') {
  return el('div', { class: 'external-api-badge' }, `🌐 ${text}`);
}

export function educationalBadge(text = 'Educational demo — not a real cracking tool') {
  return el('div', { class: 'educational-badge' }, `🎓 ${text}`);
}

export function toolHeader(description) {
  return el('p', { class: 'tool-desc' }, description);
}

export function errorBox(message) {
  return el('div', { class: 'error-box' }, message);
}

export function resultLine(key, val) {
  return el('div', { class: 'result-line' }, [
    el('span', { class: 'key' }, key),
    el('span', { class: 'val' }, String(val))
  ]);
}

/** Standard input/output textarea panel with a Run button. Returns refs. */
export function ioPanel({ inputLabel = 'Input', outputLabel = 'Output', runLabel = 'Run', inputPlaceholder = '', multiline = true }) {
  const input = multiline
    ? el('textarea', { rows: '5', placeholder: inputPlaceholder })
    : el('input', { type: 'text', placeholder: inputPlaceholder });
  const output = el('textarea', { rows: '5', class: 'output', readonly: 'true' });
  const runBtn = el('button', { class: 'btn' }, runLabel);
  const errorNode = el('div', {});

  const wrapper = el('div', {}, [
    el('label', {}, inputLabel),
    input,
    el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
    errorNode,
    el('label', { style: 'margin-top:10px' }, outputLabel),
    output
  ]);

  return { wrapper, input, output, runBtn, errorNode };
}

export function showError(errorNode, err) {
  clear(errorNode);
  errorNode.appendChild(errorBox('Error: ' + (err && err.message ? err.message : String(err))));
}

export function copyButton(getText) {
  const btn = el('button', { class: 'btn secondary' }, 'Copy');
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(getText());
      btn.textContent = 'Copied!';
      setTimeout(() => (btn.textContent = 'Copy'), 1200);
    } catch {
      btn.textContent = 'Copy failed';
    }
  });
  return btn;
}
