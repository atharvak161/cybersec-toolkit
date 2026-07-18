import { OPERATIONS, runRecipe, exportRecipe, importRecipe, buildShareableUrl, parseShareableUrl } from '../lib/recipe.js';
import { el, toolHeader, clear, showError, copyButton } from './helpers.js';

const CATEGORY_ORDER = ['Encoding', 'Hashing', 'Misc'];

function groupByCategory() {
  const groups = {};
  for (const op of OPERATIONS) {
    if (!groups[op.category]) groups[op.category] = [];
    groups[op.category].push(op);
  }
  return groups;
}

export const RECIPE_TOOL = {
  id: 'recipe-chain',
  name: 'Recipe Chain (CyberChef-lite)',
  render(container) {
    clear(container);
    container.appendChild(toolHeader(
      'Chain multiple operations together — each step’s output feeds the next step’s input. Click an operation to add it, drag steps to reorder, and the output updates live.'
    ));

    let steps = []; // { uid, opId, params }
    let uidCounter = 0;

    const input = el('textarea', { rows: '4', placeholder: 'Type or paste input…' });
    const stepsContainer = el('div', { class: 'recipe-steps' });
    const outputBox = el('textarea', { rows: '5', class: 'output', readonly: 'true' });
    const traceBox = el('div', { class: 'recipe-trace' });
    const errorNode = el('div', {});
    const shareUrlBox = el('input', { type: 'text', readonly: 'true', placeholder: 'Shareable URL will appear here after you build a recipe' });

    async function execute() {
      clear(errorNode);
      clear(traceBox);
      if (steps.length === 0) {
        outputBox.value = input.value;
        return;
      }
      try {
        const { output, trace } = await runRecipe(
          steps.map((s) => ({ opId: s.opId, params: s.params })),
          input.value
        );
        outputBox.value = output;
        trace.forEach((t, i) => {
          traceBox.appendChild(el('div', {}, [
            el('span', { class: 'step-num' }, `Step ${i + 1}: `),
            document.createTextNode(String(t.output).slice(0, 200))
          ]));
        });
      } catch (err) {
        outputBox.value = '';
        showError(errorNode, err);
      }
      updateShareUrl();
    }

    function updateShareUrl() {
      if (steps.length === 0) {
        shareUrlBox.value = '';
        return;
      }
      const base = typeof window !== 'undefined' ? window.location.href.split('?')[0] : 'https://example.com/';
      shareUrlBox.value = buildShareableUrl(base, steps.map((s) => ({ opId: s.opId, params: s.params })), input.value);
    }

    function renderSteps() {
      clear(stepsContainer);
      if (steps.length === 0) {
        stepsContainer.appendChild(el('p', { class: 'tool-desc' }, 'No steps yet — click an operation on the left to add one.'));
      }
      steps.forEach((step, index) => {
        const op = OPERATIONS.find((o) => o.id === step.opId);
        const row = el('div', { class: 'recipe-step', draggable: 'true' });
        row.dataset.uid = String(step.uid);

        row.appendChild(el('span', { class: 'drag-handle' }, '⠿'));
        row.appendChild(el('span', { class: 'step-name' }, `${index + 1}. ${op.name}`));

        if (op.id === 'caesar') {
          const shiftInput = el('input', { type: 'number', value: String(step.params.shift ?? 3) });
          shiftInput.addEventListener('input', () => {
            step.params.shift = parseInt(shiftInput.value, 10) || 0;
            execute();
          });
          row.appendChild(el('span', { class: 'step-params' }, [shiftInput]));
        }

        const removeBtn = el('button', { class: 'remove-step' }, '✕');
        removeBtn.addEventListener('click', () => {
          steps = steps.filter((s) => s.uid !== step.uid);
          renderSteps();
          execute();
        });
        row.appendChild(removeBtn);

        row.addEventListener('dragstart', () => row.classList.add('dragging'));
        row.addEventListener('dragend', () => {
          row.classList.remove('dragging');
          reorderFromDom();
          execute();
        });

        stepsContainer.appendChild(row);
      });
    }

    stepsContainer.addEventListener('dragover', (e) => {
      e.preventDefault();
      const dragging = stepsContainer.querySelector('.dragging');
      if (!dragging) return;
      const afterElement = [...stepsContainer.querySelectorAll('.recipe-step:not(.dragging)')].find((el2) => {
        const box = el2.getBoundingClientRect();
        return e.clientY < box.top + box.height / 2;
      });
      if (afterElement) stepsContainer.insertBefore(dragging, afterElement);
      else stepsContainer.appendChild(dragging);
    });

    function reorderFromDom() {
      const order = [...stepsContainer.querySelectorAll('.recipe-step')].map((row) => Number(row.dataset.uid));
      steps = order.map((uid) => steps.find((s) => s.uid === uid));
      renderSteps();
    }

    function addStep(opId) {
      const op = OPERATIONS.find((o) => o.id === opId);
      steps.push({ uid: uidCounter++, opId, params: op.params ? { ...op.params } : {} });
      renderSteps();
      execute();
    }

    // ---------- Operation picker ----------
    const picker = el('div', { class: 'op-picker' });
    const groups = groupByCategory();
    const allCategories = [...CATEGORY_ORDER, ...Object.keys(groups).filter((c) => !CATEGORY_ORDER.includes(c))];
    for (const category of allCategories) {
      if (!groups[category]) continue;
      picker.appendChild(el('div', { class: 'op-picker-category' }, category));
      for (const op of groups[category]) {
        const btn = el('button', { class: 'op-picker-item' }, `+ ${op.name}`);
        btn.addEventListener('click', () => addStep(op.id));
        picker.appendChild(btn);
      }
    }

    input.addEventListener('input', () => execute());

    const importBtn = el('button', { class: 'btn secondary' }, 'Import recipe from URL/JSON');
    const importInput = el('input', { type: 'text', placeholder: 'Paste a shareable URL or exported recipe string…' });
    importBtn.addEventListener('click', () => {
      clear(errorNode);
      try {
        let parsedSteps;
        let parsedInput = null;
        if (importInput.value.includes('://')) {
          const parsed = parseShareableUrl(importInput.value);
          parsedSteps = parsed.steps;
          parsedInput = parsed.input;
        } else {
          parsedSteps = importRecipe(importInput.value);
        }
        steps = parsedSteps.map((s) => ({ uid: uidCounter++, opId: s.opId, params: s.params || {} }));
        if (parsedInput) input.value = parsedInput;
        renderSteps();
        execute();
      } catch (err) {
        showError(errorNode, err);
      }
    });

    renderSteps();

    container.appendChild(el('div', { class: 'recipe-layout' }, [
      el('div', { class: 'card' }, [el('h3', { style: 'margin-top:0' }, 'Operations'), picker]),
      el('div', {}, [
        el('div', { class: 'card' }, [
          el('label', {}, 'Input'), input,
          el('label', { style: 'margin-top:10px' }, 'Recipe steps (drag to reorder)'), stepsContainer
        ]),
        el('div', { class: 'card' }, [
          el('label', {}, 'Output'), outputBox,
          copyButton(() => outputBox.value),
          errorNode,
          el('label', { style: 'margin-top:10px' }, 'Step-by-step trace'), traceBox
        ]),
        el('div', { class: 'card' }, [
          el('label', {}, 'Shareable recipe URL'), shareUrlBox,
          copyButton(() => shareUrlBox.value),
          el('label', { style: 'margin-top:10px' }, 'Import a recipe'),
          el('div', { class: 'field-row' }, [importInput, importBtn])
        ])
      ])
    ]));

    execute();
  }
};
