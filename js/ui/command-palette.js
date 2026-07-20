/**
 * Full-screen command palette overlay (Cmd/Ctrl+K), per design spec §2, v4.
 *
 * This module does not own the search index or navigation — it calls
 * `searchFn(query)` (the caller's existing computeSearchResults, per the
 * spec's hard requirement not to fork the matching/ranking logic) and
 * `onSelect(toolId)` (the caller's existing selectTool). This file only
 * owns the overlay DOM, keyboard handling, and rendering.
 *
 * export function openCommandPalette({ searchFn, onSelect })
 */

import { el, clear } from './helpers.js';

const DEBOUNCE_MS = 120;

/**
 * computeSearchResults() in js/app.js returns
 * { tool: { id, name, ... }, category: { name, ... }, nameMatch, excerpt }
 * per row. Normalize defensively to { id, name, sectionName, excerpt,
 * nameMatch } so this file also tolerates a flatter shape if the caller
 * ever wraps/adapts the search function differently.
 */
function normalizeResult(r) {
  if (r && r.tool) {
    return {
      id: r.tool.id,
      name: r.tool.name,
      sectionName: r.category ? r.category.name : '',
      excerpt: r.excerpt || null,
      nameMatch: r.nameMatch !== false
    };
  }
  return {
    id: r.id,
    name: r.name,
    sectionName: r.sectionName || '',
    excerpt: r.excerpt || null,
    nameMatch: r.nameMatch !== false
  };
}

function highlightMatch(text, q) {
  if (!q) return [text];
  const idx = text.toLowerCase().indexOf(q.toLowerCase());
  if (idx === -1) return [text];
  return [text.slice(0, idx), el('mark', {}, text.slice(idx, idx + q.length)), text.slice(idx + q.length)];
}

export function openCommandPalette({ searchFn, onSelect }) {
  const previouslyFocused = document.activeElement;
  const previousBodyOverflow = document.body.style.overflow;

  let results = [];
  let highlightedIndex = -1;
  let query = '';
  let debounceTimer = null;
  let closed = false;

  const input = el('input', {
    class: 'cmdk-input',
    type: 'text',
    placeholder: 'Search tools…',
    autocomplete: 'off',
    spellcheck: 'false'
  });
  const resultsList = el('div', { class: 'cmdk-results' });
  const panel = el('div', { class: 'cmdk-panel' }, [input, resultsList]);
  const backdrop = el('div', { class: 'cmdk-backdrop' }, [panel]);

  function rowEls() {
    return Array.from(resultsList.querySelectorAll('.cmdk-result'));
  }

  function updateHighlightClasses() {
    const rows = rowEls();
    rows.forEach((row, i) => row.classList.toggle('highlighted', i === highlightedIndex));
    const activeRow = rows[highlightedIndex];
    if (activeRow) activeRow.scrollIntoView({ block: 'nearest' });
  }

  function moveHighlight(delta) {
    if (!results.length) return;
    highlightedIndex = (highlightedIndex + delta + results.length) % results.length;
    updateHighlightClasses();
  }

  function selectIndex(i) {
    const r = results[i];
    if (!r) return;
    onSelect(r.id);
    close(false);
  }

  function renderResults() {
    clear(resultsList);
    const trimmed = query.trim();

    if (!trimmed) {
      highlightedIndex = -1;
      return;
    }

    if (results.length === 0) {
      resultsList.appendChild(
        el('div', { class: 'cmdk-empty' }, [`No tools match "${trimmed}". `, el('span', {}, 'Esc to close')])
      );
      highlightedIndex = -1;
      return;
    }

    results.forEach((r, i) => {
      const row = el('button', { class: 'cmdk-result', type: 'button' }, [
        el('div', { class: 'nav-result-name' }, r.nameMatch ? highlightMatch(r.name, trimmed) : [r.name]),
        el('div', { class: 'nav-result-section' }, r.sectionName),
        r.excerpt ? el('div', { class: 'nav-result-excerpt' }, r.excerpt) : null
      ]);
      row.addEventListener('click', () => selectIndex(i));
      row.addEventListener('mouseenter', () => {
        highlightedIndex = i;
        updateHighlightClasses();
      });
      resultsList.appendChild(row);
    });

    highlightedIndex = 0;
    updateHighlightClasses();
  }

  function runSearch() {
    const raw = searchFn(query) || [];
    results = raw.map(normalizeResult);
    renderResults();
  }

  input.addEventListener('input', () => {
    query = input.value;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runSearch, DEBOUNCE_MS);
  });

  function focusableEls() {
    return [input, ...rowEls()];
  }

  function handleKeydown(e) {
    if (e.key === 'Escape') {
      e.preventDefault();
      close(true);
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      moveHighlight(1);
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      moveHighlight(-1);
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      selectIndex(highlightedIndex === -1 ? 0 : highlightedIndex);
      return;
    }
    if (e.key === 'Tab') {
      // Minimal focus trap: Tab/Shift+Tab cycle only between the input
      // and the visible result rows, never escaping to the dimmed page.
      const focusable = focusableEls();
      if (!focusable.length) return;
      const currentIndex = focusable.indexOf(document.activeElement);
      let nextIndex;
      if (e.shiftKey) {
        nextIndex = currentIndex <= 0 ? focusable.length - 1 : currentIndex - 1;
      } else {
        nextIndex = currentIndex === -1 || currentIndex === focusable.length - 1 ? 0 : currentIndex + 1;
      }
      e.preventDefault();
      focusable[nextIndex].focus();
    }
  }

  function handleBackdropMouseDown(e) {
    if (e.target !== backdrop) return;
    // Prevent the browser's default mousedown behavior, which blurs the
    // currently focused element (the palette input) to <body> since the
    // backdrop itself isn't focusable. Without this, close(true) below
    // restores focus correctly but the default action then immediately
    // steals it back to <body> right after, once this handler returns.
    e.preventDefault();
    close(true);
  }

  panel.addEventListener('keydown', handleKeydown);
  backdrop.addEventListener('mousedown', handleBackdropMouseDown);

  function close(restoreFocus) {
    if (closed) return;
    closed = true;
    clearTimeout(debounceTimer);
    panel.removeEventListener('keydown', handleKeydown);
    backdrop.removeEventListener('mousedown', handleBackdropMouseDown);
    backdrop.remove();
    document.body.style.overflow = previousBodyOverflow;
    if (restoreFocus && previouslyFocused && typeof previouslyFocused.focus === 'function') {
      previouslyFocused.focus();
    }
  }

  document.body.style.overflow = 'hidden';
  document.body.appendChild(backdrop);
  input.focus();
}
