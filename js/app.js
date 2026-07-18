/**
 * Main application shell: builds the sidebar navigation grouped by
 * category, and routes to the selected tool's render(container) call.
 * No framework, no build step — plain DOM + ES modules.
 */

import { el, clear } from './ui/helpers.js';
import { ENCODING_TOOLS } from './ui/encoding-tools.js';
import { HASHING_TOOLS } from './ui/hashing-tools.js';
import { CRYPTO_TOOLS } from './ui/crypto-tools.js';
import { RECIPE_TOOL } from './ui/recipe-tools.js';
import { PASSWORD_TOOLS } from './ui/password-tools.js';
import { FILES_TOOLS } from './ui/files-tools.js';
import { NETWORK_TOOLS } from './ui/network-tools.js';
import { MISC_TOOLS } from './ui/misc-tools.js';

const CATEGORIES = [
  { name: 'Recipe Chain', tools: [RECIPE_TOOL] },
  { name: 'Encoding', tools: ENCODING_TOOLS },
  { name: 'Hashing', tools: HASHING_TOOLS },
  { name: 'Crypto', tools: CRYPTO_TOOLS },
  { name: 'Passwords & Breach Check', tools: PASSWORD_TOOLS },
  { name: 'Files & Metadata', tools: FILES_TOOLS },
  { name: 'Network / OSINT', tools: NETWORK_TOOLS },
  { name: 'Misc', tools: MISC_TOOLS }
];

const EXTERNAL_API_TOOL_IDS = new Set(['hibp', 'dns-lookup', 'whois-lookup', 'ip-geo']);

const nav = document.getElementById('nav');
const content = document.getElementById('content');
const toolTitle = document.getElementById('tool-title');
const sidebar = document.getElementById('sidebar');

function findTool(toolId) {
  for (const category of CATEGORIES) {
    const tool = category.tools.find((t) => t.id === toolId);
    if (tool) return tool;
  }
  return null;
}

/** Renders the given tool into the content area. Does NOT touch the URL hash. */
function renderTool(toolId) {
  const tool = findTool(toolId);
  if (!tool) return;

  document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.toolId === toolId));
  toolTitle.textContent = tool.name;
  clear(content);
  tool.render(content);
  sidebar.classList.remove('open');
}

/** Navigates to a tool: updates the hash (single source of truth), which
 * triggers the hashchange listener below to actually render it. Clicking
 * the same tool that's already active won't fire hashchange, so render
 * directly in that case. */
function selectTool(toolId) {
  if (window.location.hash.replace('#', '') === toolId) {
    renderTool(toolId);
  } else {
    window.location.hash = toolId;
  }
}

function buildNav() {
  clear(nav);
  for (const category of CATEGORIES) {
    nav.appendChild(el('div', { class: 'nav-category' }, category.name));
    for (const tool of category.tools) {
      const badge = EXTERNAL_API_TOOL_IDS.has(tool.id) ? el('span', { class: 'badge' }, '🌐') : null;
      const item = el('button', { class: 'nav-item', 'data-tool-id': tool.id }, [
        el('span', {}, tool.name),
        badge
      ]);
      item.addEventListener('click', () => selectTool(tool.id));
      nav.appendChild(item);
    }
  }
}

document.getElementById('menu-toggle').addEventListener('click', () => {
  sidebar.classList.toggle('open');
});

// Single source of truth for navigation: the hash. Sidebar clicks, browser
// back/forward, and direct hash edits all funnel through this listener.
window.addEventListener('hashchange', () => {
  const toolId = window.location.hash.replace('#', '');
  if (toolId && findTool(toolId)) renderTool(toolId);
});

function init() {
  buildNav();
  const initial = window.location.hash.replace('#', '') || RECIPE_TOOL.id;
  if (findTool(initial)) {
    if (!window.location.hash) window.location.hash = initial;
    renderTool(initial);
  } else {
    toolTitle.textContent = 'Welcome';
    content.appendChild(el('div', { class: 'card' }, [
      el('h2', {}, 'Welcome to cybersec-toolkit'),
      el('p', {}, 'A static, client-side-only cybersecurity toolkit. Nothing you type is sent anywhere except the few tools explicitly marked with a 🌐 badge (HIBP breach check, DNS lookup, WHOIS lookup, IP geolocation) — each of those shows exactly what it calls before you use it.'),
      el('p', {}, 'Pick a tool from the sidebar to get started. The Recipe Chain (CyberChef-lite) lets you pipe multiple operations together — it’s the best place to start.')
    ]));
  }
}

init();
