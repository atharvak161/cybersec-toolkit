/**
 * Shared hover/focus preview tooltip (design spec §3, v4).
 *
 * A single tooltip DOM node is created lazily and reused/repositioned for
 * whichever target is currently active, rather than creating one element
 * per attached target — this will be attached to dozens of sidebar items
 * and card elements at once, so a per-target element would be wasteful.
 *
 * export function attachTooltip(targetEl, getContent) -> detach()
 */

import { el, clear } from './helpers.js';

const MOUSE_SHOW_DELAY_MS = 400;
const HIDE_GRACE_MS = 100;
const EDGE_MARGIN = 8;

let tooltipEl = null;
let currentTarget = null;
let showTimer = null;
let hideTimer = null;
let globalListenersInstalled = false;

function ensureTooltipEl() {
  if (!tooltipEl) {
    tooltipEl = el('div', { class: 'tooltip-popover' });
    document.body.appendChild(tooltipEl);
  }
  return tooltipEl;
}

function clearShowTimer() {
  if (showTimer) {
    clearTimeout(showTimer);
    showTimer = null;
  }
}

function clearHideTimer() {
  if (hideTimer) {
    clearTimeout(hideTimer);
    hideTimer = null;
  }
}

/**
 * Renders tooltip content. Supports three shapes per the design spec:
 *  - a plain string (single line)
 *  - a { what, when } object (either field may be omitted — e.g. the
 *    section-landing-card target which shows `when` only)
 *  - an array of tool names (section tool-list preview, capped at 8 with
 *    a "+N more" trailer)
 */
function renderContent(content) {
  const node = ensureTooltipEl();
  clear(node);

  if (typeof content === 'string') {
    node.appendChild(el('p', { class: 'tooltip-line' }, content));
    return;
  }

  if (Array.isArray(content)) {
    const shown = content.slice(0, 8);
    node.appendChild(el('p', { class: 'tooltip-line tooltip-usecase-label' }, 'TOOLS IN THIS SECTION'));
    node.appendChild(el('ul', { class: 'tooltip-tool-list' }, shown.map((name) => el('li', {}, name))));
    if (content.length > 8) {
      node.appendChild(el('p', { class: 'tooltip-more' }, `+${content.length - 8} more`));
    }
    return;
  }

  if (content && typeof content === 'object') {
    if (content.what) {
      node.appendChild(el('p', { class: 'tooltip-line' }, [el('strong', {}, 'What it does: '), content.what]));
    }
    if (content.when) {
      node.appendChild(el('p', { class: 'tooltip-line tooltip-usecase' }, [
        el('span', { class: 'tooltip-usecase-label' }, 'USE CASE'),
        ' ' + content.when
      ]));
    }
  }
}

/**
 * position: fixed, edge-detected per the design spec:
 *  - sidebar targets (.nav-item, .nav-result-item): open right, 8px gap,
 *    vertically centered; flip to left if it would overflow the right edge.
 *  - all other targets: open below, 8px gap, left-aligned; flip above if
 *    it would overflow the bottom edge.
 *  - horizontal overflow on a below/above tooltip clamps rather than flips.
 *  - never fully off-screen either axis.
 */
function positionTooltip(targetEl) {
  const node = tooltipEl;
  const rect = targetEl.getBoundingClientRect();
  const isSidebarTarget = typeof targetEl.matches === 'function' && targetEl.matches('.nav-item, .nav-result-item');

  // Reset offset before measuring so a previous position can't influence
  // the node's natural size (it doesn't, since this is position:fixed and
  // sized by content/max-width, but keeping this deterministic is cheap).
  node.style.left = '0px';
  node.style.top = '0px';
  const tRect = node.getBoundingClientRect();

  let left;
  let top;

  if (isSidebarTarget) {
    left = rect.right + EDGE_MARGIN;
    top = rect.top + rect.height / 2 - tRect.height / 2;
    if (left + tRect.width > window.innerWidth - EDGE_MARGIN) {
      left = rect.left - EDGE_MARGIN - tRect.width;
    }
    if (top < EDGE_MARGIN) top = EDGE_MARGIN;
    if (top + tRect.height > window.innerHeight - EDGE_MARGIN) top = window.innerHeight - EDGE_MARGIN - tRect.height;
  } else {
    left = rect.left;
    top = rect.bottom + EDGE_MARGIN;
    if (top + tRect.height > window.innerHeight - EDGE_MARGIN) {
      top = rect.top - EDGE_MARGIN - tRect.height;
    }
    if (top < EDGE_MARGIN) top = EDGE_MARGIN;
  }

  // Horizontal clamp applies to both groups as a final safety net so the
  // tooltip is never fully (or partly) off-screen.
  if (left < EDGE_MARGIN) left = EDGE_MARGIN;
  if (left + tRect.width > window.innerWidth - EDGE_MARGIN) left = window.innerWidth - EDGE_MARGIN - tRect.width;

  node.style.left = `${left}px`;
  node.style.top = `${top}px`;
}

function showFor(targetEl, getContent) {
  const content = getContent();
  if (content === null || content === undefined) return;
  currentTarget = targetEl;
  renderContent(content);
  const node = ensureTooltipEl();
  node.classList.add('visible');
  positionTooltip(targetEl);
}

function hideCurrent() {
  clearShowTimer();
  clearHideTimer();
  if (tooltipEl) tooltipEl.classList.remove('visible');
  currentTarget = null;
}

function installGlobalListenersOnce() {
  if (globalListenersInstalled) return;
  globalListenersInstalled = true;
  const node = ensureTooltipEl();

  // Escape hides the tooltip only — doesn't blur the target, doesn't
  // trigger any other close behavior.
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && currentTarget) {
      hideCurrent();
    }
  });

  // A floating tooltip anchored to a now-scrolled-away element is worse
  // than no tooltip — hide immediately on any scroll, including inside
  // nested overflow containers (capture:true catches those).
  document.addEventListener(
    'scroll',
    () => {
      if (currentTarget) hideCurrent();
    },
    true
  );

  // Moving the mouse from the target directly into the tooltip itself
  // must not hide it; leaving the tooltip hides it (with the same grace
  // window as leaving the target).
  node.addEventListener('mouseenter', () => {
    if (currentTarget) clearHideTimer();
  });
  node.addEventListener('mouseleave', () => {
    const target = currentTarget;
    if (!target) return;
    clearHideTimer();
    hideTimer = setTimeout(() => {
      hideTimer = null;
      if (currentTarget === target) hideCurrent();
    }, HIDE_GRACE_MS);
  });
}

export function attachTooltip(targetEl, getContent) {
  installGlobalListenersOnce();
  ensureTooltipEl();

  function onMouseEnter() {
    clearHideTimer();
    if (currentTarget === targetEl && tooltipEl.classList.contains('visible')) return;
    clearShowTimer();
    showTimer = setTimeout(() => {
      showTimer = null;
      showFor(targetEl, getContent);
    }, MOUSE_SHOW_DELAY_MS);
  }

  function onMouseLeave() {
    if (showTimer) {
      // Timer hadn't fired yet — a mouse simply passing over the target,
      // no tooltip ever showed, so there's nothing to hide/flicker.
      clearShowTimer();
      return;
    }
    if (currentTarget !== targetEl) return;
    clearHideTimer();
    hideTimer = setTimeout(() => {
      hideTimer = null;
      if (currentTarget === targetEl) hideCurrent();
    }, HIDE_GRACE_MS);
  }

  function onFocus(e) {
    let isKeyboard = true;
    try {
      isKeyboard = targetEl.matches(':focus-visible');
    } catch {
      // :focus-visible unsupported — fail open so keyboard users still
      // get the instant path rather than none at all.
      isKeyboard = true;
    }
    if (!isKeyboard) return;
    clearShowTimer();
    clearHideTimer();
    showFor(targetEl, getContent);
  }

  function onBlur() {
    if (currentTarget === targetEl) hideCurrent();
  }

  targetEl.addEventListener('mouseenter', onMouseEnter);
  targetEl.addEventListener('mouseleave', onMouseLeave);
  targetEl.addEventListener('focus', onFocus);
  targetEl.addEventListener('blur', onBlur);

  return function detach() {
    targetEl.removeEventListener('mouseenter', onMouseEnter);
    targetEl.removeEventListener('mouseleave', onMouseLeave);
    targetEl.removeEventListener('focus', onFocus);
    targetEl.removeEventListener('blur', onBlur);
    if (showTimer && currentTarget === null) clearShowTimer();
    if (currentTarget === targetEl) hideCurrent();
  };
}
