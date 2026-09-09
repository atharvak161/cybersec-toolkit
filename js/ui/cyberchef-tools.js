/**
 * CyberChef operations, driven from this toolkit's own interface.
 *
 * The engine is CyberChef's unmodified core (Crown Copyright, Apache-2.0)
 * bundled at js/vendor/cyberchef-core.js — see CYBERCHEF-NOTICE.txt. Only the
 * interface is ours: search-first rather than a category tree, single-column
 * flow rather than three fixed panes, and per-step output so you can see
 * exactly where a chain breaks.
 *
 * The bundle is 23MB, so it is loaded lazily on first use and never on page
 * load. Everything still runs client-side; nothing is sent anywhere.
 */
import { el, toolHeader, clear, showError, copyButton } from './helpers.js';

const CORE_SRC = 'js/vendor/cyberchef-core.js';
let corePromise = null;

/** Load the core once, on demand. Resolves to the CyberChefCore API. */
function loadCore() {
  if (window.CyberChefCore) return Promise.resolve(window.CyberChefCore);
  if (corePromise) return corePromise;
  corePromise = new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = CORE_SRC;
    s.async = true;
    s.onload = () => window.CyberChefCore
      ? resolve(window.CyberChefCore)
      : reject(new Error('CyberChef core loaded but did not register'));
    s.onerror = () => reject(new Error(`Could not load ${CORE_SRC}`));
    document.head.appendChild(s);
  });
  return corePromise;
}

/** Render an input control for one CyberChef arg spec. */
function argField(spec, value, onChange) {
  const label = el('label', { class: 'cc-arg-label' }, spec.name);
  let field;
  if (spec.type === 'boolean') {
    field = el('input', { type: 'checkbox', class: 'cc-arg' });
    field.checked = !!value;
    field.addEventListener('change', () => onChange(field.checked));
  } else if (spec.type === 'option' || spec.type === 'argSelector') {
    field = el('select', { class: 'cc-arg' });
    const opts = Array.isArray(spec.value) ? spec.value : [];
    for (const o of opts) {
      const v = typeof o === 'object' ? (o.value ?? o.name) : o;
      const n = typeof o === 'object' ? (o.name ?? o.value) : o;
      const opt = el('option', { value: String(v) }, String(n));
      if (String(v) === String(value)) opt.selected = true;
      field.appendChild(opt);
    }
    field.addEventListener('change', () => onChange(field.value));
  } else if (spec.type === 'editableOption') {
    field = el('input', { type: 'text', class: 'cc-arg', value: String(value ?? '') });
    const listId = `cc-dl-${Math.random().toString(36).slice(2, 9)}`;
    field.setAttribute('list', listId);
    const dl = el('datalist', { id: listId });
    for (const o of (Array.isArray(spec.value) ? spec.value : [])) {
      dl.appendChild(el('option', { value: String(typeof o === 'object' ? o.value : o) },
        String(typeof o === 'object' ? o.name : o)));
    }
    field.addEventListener('input', () => onChange(field.value));
    return el('span', { class: 'cc-arg-wrap' }, [label, field, dl]);
  } else if (spec.type === 'number') {
    field = el('input', { type: 'number', class: 'cc-arg', value: String(value ?? 0) });
    field.addEventListener('input', () => onChange(Number(field.value)));
  } else if (spec.type === 'toggleString') {
    const v = value && typeof value === 'object' ? value : { option: (spec.toggleValues || [])[0], string: '' };
    const sel = el('select', { class: 'cc-arg cc-arg-toggle' });
    for (const o of (spec.toggleValues || [])) {
      const opt = el('option', { value: o }, o);
      if (o === v.option) opt.selected = true;
      sel.appendChild(opt);
    }
    const txt = el('input', { type: 'text', class: 'cc-arg', value: String(v.string ?? '') });
    const emit = () => onChange({ option: sel.value, string: txt.value });
    sel.addEventListener('change', emit);
    txt.addEventListener('input', emit);
    return el('span', { class: 'cc-arg-wrap' }, [label, sel, txt]);
  } else {
    field = el('input', { type: 'text', class: 'cc-arg', value: String(value ?? '') });
    field.addEventListener('input', () => onChange(field.value));
  }
  return el('span', { class: 'cc-arg-wrap' }, [label, field]);
}

export const CYBERCHEF_TOOL = {
  id: 'cyberchef',
  name: 'CyberChef Operations (505)',
  render(container) {
    clear(container);
    container.appendChild(toolHeader(
      'Every CyberChef operation, running locally in your browser. Search for what you need, ' +
      'stack operations into a recipe, and see each step’s output as it runs. ' +
      'The engine is CyberChef’s own (Crown Copyright, Apache-2.0); the interface is this toolkit’s.'
    ));

    let OPS = [];
    let steps = [];            // { uid, op, args }
    let uid = 0;
    let core = null;

    const status = el('div', { class: 'cc-status' }, 'Loading CyberChef core (23 MB, once per session)…');
    const search = el('input', { type: 'search', class: 'op-search', placeholder: 'Search operations…', 'aria-label': 'Search CyberChef operations' });
    const count = el('div', { class: 'op-count' }, '');
    const picker = el('div', { class: 'op-picker' });
    const input = el('textarea', { rows: '5', placeholder: 'Input…' });
    const stepsBox = el('div', { class: 'recipe-steps' });
    const output = el('textarea', { rows: '8', class: 'output', readonly: 'true' });
    const trace = el('div', { class: 'recipe-trace' });
    const errBox = el('div', {});

    async function execute() {
      clear(errBox); clear(trace);
      if (!core) return;
      if (!steps.length) { output.value = input.value; return; }
      // Run cumulative prefixes so each step's own output is visible — this is
      // what makes a broken chain findable instead of just "no output".
      try {
        for (let i = 0; i < steps.length; i++) {
          const prefix = steps.slice(0, i + 1).map((s) => ({ op: s.op, args: s.args }));
          let text;
          try { text = await core.bake(input.value, prefix); }
          catch (e) { text = null;
            trace.appendChild(el('div', { class: 'cc-trace-fail' },
              `Step ${i + 1} (${steps[i].op}) failed: ${e.message}`));
            output.value = '';
            return;
          }
          trace.appendChild(el('div', {}, [
            el('span', { class: 'step-num' }, `Step ${i + 1} · ${steps[i].op}: `),
            document.createTextNode(text.length > 200 ? text.slice(0, 200) + '…' : text)
          ]));
          if (i === steps.length - 1) output.value = text;
        }
      } catch (err) { output.value = ''; showError(errBox, err); }
    }

    function renderSteps() {
      clear(stepsBox);
      if (!steps.length) {
        stepsBox.appendChild(el('p', { class: 'tool-desc' }, 'No operations yet — search above and click one to add it.'));
        return;
      }
      steps.forEach((step, i) => {
        const spec = OPS.find((o) => o.name === step.op);
        const row = el('div', { class: 'recipe-step cc-step' });
        row.appendChild(el('span', { class: 'step-name' }, `${i + 1}. ${step.op}`));
        (spec?.args || []).forEach((argSpec, ai) => {
          row.appendChild(argField(argSpec, step.args[ai], (v) => { step.args[ai] = v; execute(); }));
        });
        const up = el('button', { class: 'cc-move', title: 'Move up' }, '↑');
        up.addEventListener('click', () => { if (i > 0) { [steps[i - 1], steps[i]] = [steps[i], steps[i - 1]]; renderSteps(); execute(); } });
        const down = el('button', { class: 'cc-move', title: 'Move down' }, '↓');
        down.addEventListener('click', () => { if (i < steps.length - 1) { [steps[i + 1], steps[i]] = [steps[i], steps[i + 1]]; renderSteps(); execute(); } });
        const rm = el('button', { class: 'remove-step', title: 'Remove' }, '✕');
        rm.addEventListener('click', () => { steps = steps.filter((s) => s.uid !== step.uid); renderSteps(); execute(); });
        row.appendChild(el('span', { class: 'cc-step-actions' }, [up, down, rm]));
        stepsBox.appendChild(row);
      });
    }

    function addStep(name) {
      const spec = OPS.find((o) => o.name === name);
      steps.push({ uid: uid++, op: name, args: [...(spec?.defaults || [])] });
      renderSteps(); execute();
    }

    function renderPicker() {
      clear(picker);
      const q = search.value.trim().toLowerCase();
      const matches = q
        ? OPS.filter((o) => o.name.toLowerCase().includes(q) ||
                            o.category.toLowerCase().includes(q) ||
                            o.description.toLowerCase().includes(q))
        : OPS;
      count.textContent = q ? `${matches.length} of ${OPS.length} operations`
                            : `${OPS.length} operations — type to search`;
      const shown = matches.slice(0, 300);
      let lastCat = null;
      for (const op of shown) {
        if (op.category !== lastCat) {
          picker.appendChild(el('div', { class: 'op-picker-category' }, op.category));
          lastCat = op.category;
        }
        const btn = el('button', { class: 'op-picker-item', title: op.description.slice(0, 220) }, `+ ${op.name}`);
        btn.addEventListener('click', () => addStep(op.name));
        picker.appendChild(btn);
      }
      if (!shown.length) picker.appendChild(el('p', { class: 'tool-desc' }, `No operation matches “${search.value}”.`));
      else if (matches.length > shown.length) picker.appendChild(el('p', { class: 'tool-desc' }, `…and ${matches.length - shown.length} more. Keep typing to narrow.`));
    }

    search.addEventListener('input', renderPicker);
    input.addEventListener('input', execute);

    container.appendChild(el('div', { class: 'recipe-layout' }, [
      el('div', { class: 'card' }, [el('h3', { style: 'margin-top:0' }, 'Operations'), status, search, count, picker]),
      el('div', {}, [
        el('div', { class: 'card' }, [el('label', {}, 'Input'), input,
          el('label', { style: 'margin-top:10px' }, 'Recipe'), stepsBox]),
        el('div', { class: 'card' }, [el('label', {}, 'Output'), output, copyButton(() => output.value), errBox,
          el('label', { style: 'margin-top:10px' }, 'Step-by-step output'), trace])
      ])
    ]));

    renderSteps();
    loadCore().then((api) => {
      core = api;
      OPS = api.operations().sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
      status.textContent = `CyberChef ${api.version} core loaded · runs entirely in your browser`;
      status.classList.add('cc-status-ready');
      search.placeholder = `Search ${OPS.length} operations…`;
      renderPicker(); execute();
    }).catch((e) => {
      status.textContent = `Could not load the CyberChef core: ${e.message}`;
      status.classList.add('cc-status-error');
    });
  }
};

export const CYBERCHEF_TOOLS = [CYBERCHEF_TOOL];
