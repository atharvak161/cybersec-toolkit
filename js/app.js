/**
 * Main application shell: builds the sidebar navigation (pinned Recipe
 * Chain + collapsible category groups + quick-search), renders section
 * landing pages and individual tools into #content, and keeps the URL
 * hash as the single source of truth for navigation (hashchange drives
 * every render, so direct links and browser back/forward both work).
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
import { DEV_TOOLS } from './ui/dev-tools.js';
import { PENTEST_TOOLS } from './ui/pentest-tools.js';
import { TOOL_COPY } from './data/tool-copy.js';

// ---------- 1. Information architecture (design spec §1) ----------
// Recipe Chain is pinned above the category system entirely — it's a
// distinct mode (chains other tools), not a peer of a single codec.
const PINNED_CATEGORY = { name: 'Recipe Builder', slug: 'recipe-builder', tools: [RECIPE_TOOL] };

const CATEGORIES = [
  {
    name: 'Encoding & Ciphers',
    slug: 'encoding-ciphers',
    tools: ENCODING_TOOLS,
    intro: "Convert data between representations: hex, Base64 and its cousins, URL encoding, classic ciphers, Morse. Reach for this section whenever you're staring at text that's obviously transformed and you need to see what's underneath, or need to produce that transformation yourself."
  },
  {
    name: 'Hashing & Integrity',
    slug: 'hashing-integrity',
    tools: HASHING_TOOLS,
    intro: "Generate and identify cryptographic and legacy hashes, and verify that a file or message hasn't changed. Reach for this when you need to prove (or check) that two pieces of data are identical, or sign a message with HMAC."
  },
  {
    name: 'Cryptography',
    slug: 'cryptography',
    tools: CRYPTO_TOOLS,
    intro: 'Encrypt, decrypt, and inspect the real cryptographic primitives: AES, RSA, JWTs, X.509 certificates, and time-based one-time passwords. Reach for this when you need to actually protect data, verify a token, or understand what a certificate or 2FA secret is doing.'
  },
  {
    name: 'Passwords & Credential Safety',
    slug: 'passwords-credential-safety',
    tools: PASSWORD_TOOLS,
    intro: 'Generate strong passwords and passphrases, and check whether a password is weak or already compromised. Reach for this before you commit to a new password or master passphrase, not after.'
  },
  {
    name: 'Files & Metadata',
    slug: 'files-metadata',
    tools: FILES_TOOLS,
    intro: "Inspect what a file actually is and what it's carrying, beyond its filename or extension — EXIF data, magic bytes, hidden LSB payloads, embedded base64 images. Reach for this when a file needs to be verified or sanitized before you trust it or share it further."
  },
  {
    name: 'Network & Recon',
    slug: 'network-recon',
    tools: NETWORK_TOOLS,
    intro: 'Look up public information about domains, IPs, and subnets, and reference common ports and protocols. Reach for this for read-only, passive lookups — nothing here actively scans or probes a third-party system.'
  },
  {
    name: 'Developer Utilities',
    slug: 'developer-utilities',
    tools: DEV_TOOLS,
    intro: 'The everyday tools for parsing, testing, and sanity-checking data: regex, diffs, timestamps, QR codes, structured-data formatting, and spotting deceptive text or URLs. Reach for this for the small tasks that interrupt real work if you don’t have a fast tool on hand.'
  },
  {
    name: 'Pentest & CTF Reference',
    slug: 'pentest-ctf-reference',
    tools: PENTEST_TOOLS,
    intro: 'Reference material for authorized penetration testing and CTF work: shell payloads, injection cheat-sheets, and privilege-escalation enumeration steps. This assumes an authorized engagement or lab/CTF context throughout — same category of tool as revshells.com, PayloadsAllTheThings, or GTFOBins.'
  }
];

function allCategoriesForLookup() {
  return [PINNED_CATEGORY, ...CATEGORIES];
}

const TOTAL_TOOL_COUNT = allCategoriesForLookup().reduce((sum, c) => sum + c.tools.length, 0);

const EXTERNAL_API_TOOL_IDS = new Set(['hibp', 'dns-lookup', 'whois-lookup', 'ip-geo']);

const EXPANDED_STORAGE_KEY = 'cybersec-toolkit:nav-expanded';

// ---------- DOM refs ----------
const nav = document.getElementById('nav');
const navPinned = document.getElementById('nav-pinned');
const searchInput = document.getElementById('nav-search-input');
const content = document.getElementById('content');
const breadcrumbEl = document.getElementById('breadcrumb');
const sidebar = document.getElementById('sidebar');

let categoriesContainer;
let resultsContainer;
const navGroupEls = {};

let expandedState = loadExpandedState();
let currentResults = [];
let highlightedIndex = -1;
let firstRender = true;

// ---------- Lookup helpers ----------
function findToolWithCategory(toolId) {
  for (const category of allCategoriesForLookup()) {
    const tool = category.tools.find((t) => t.id === toolId);
    if (tool) return { tool, category };
  }
  return null;
}

// ---------- localStorage (collapsible group state) ----------
function loadExpandedState() {
  try {
    return JSON.parse(localStorage.getItem(EXPANDED_STORAGE_KEY)) || {};
  } catch {
    return {};
  }
}

function saveExpandedState() {
  try {
    localStorage.setItem(EXPANDED_STORAGE_KEY, JSON.stringify(expandedState));
  } catch {
    /* localStorage unavailable (private mode, etc.) — degrade silently */
  }
}

function setGroupExpanded(slug, expanded, { persist = true } = {}) {
  expandedState[slug] = expanded;
  if (persist) saveExpandedState();
  const group = navGroupEls[slug];
  if (!group) return;
  group.chevron.classList.toggle('expanded', expanded);
  group.chevron.setAttribute('aria-expanded', String(expanded));
  group.body.classList.toggle('expanded', expanded);
}

// ---------- Content-swap motion (design spec §4, motion moment #1) ----------
// 140ms opacity+translateY fade on every tool<->tool / tool<->landing swap.
// Suppressed on the very first paint (page load) — the spec explicitly
// rules out page-load animation sequences; only *swaps* animate.
function swapContent(populate) {
  clear(content);
  populate(content);
  if (firstRender) {
    firstRender = false;
    return;
  }
  content.classList.remove('content-enter');
  void content.offsetWidth; // force reflow so the animation restarts
  content.classList.add('content-enter');
}

// ---------- Breadcrumb (design spec §2C) ----------
function setBreadcrumb({ sectionName, sectionSlug, toolName } = {}) {
  clear(breadcrumbEl);
  if (sectionName && toolName) {
    const link = el('button', { class: 'breadcrumb-section link' }, sectionName);
    link.addEventListener('click', () => navigateToSection(sectionSlug));
    breadcrumbEl.appendChild(link);
    breadcrumbEl.appendChild(el('span', { class: 'breadcrumb-sep' }, '/'));
    breadcrumbEl.appendChild(el('span', { class: 'breadcrumb-tool' }, toolName));
  } else if (sectionName) {
    breadcrumbEl.appendChild(el('span', { class: 'breadcrumb-section' }, sectionName));
  } else {
    breadcrumbEl.appendChild(el('span', { class: 'breadcrumb-tool' }, toolName || 'Welcome'));
  }
}

// ---------- Rendering: home / tool / section landing ----------
function renderHome() {
  swapContent((container) => {
    container.appendChild(el('div', {}, [
      el('h1', { class: 'home-title' }, 'Welcome to cybersec-toolkit'),
      el('p', { class: 'tool-copy-line' }, 'A static, client-side-only cybersecurity toolkit — nothing you type is sent anywhere except the few tools explicitly marked with a 🌐 badge (HIBP breach check, DNS lookup, WHOIS lookup, IP geolocation), each of which shows exactly what it calls before you use it.'),
      el('p', { class: 'tool-copy-line' }, `Pick a tool from the sidebar, browse a section for an overview, or press "/" to search all ${TOTAL_TOOL_COUNT} tools. The Recipe Chain — pinned above the sidebar search box — lets you pipe multiple operations together; it's the best place to start.`)
    ]));
  });
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.remove('active'));
  setBreadcrumb({ toolName: 'Welcome' });
  document.title = 'cybersec-toolkit';
}

function renderTool(toolId) {
  const found = findToolWithCategory(toolId);
  if (!found) {
    renderHome();
    return;
  }
  const { tool, category } = found;
  const isPinned = category.slug === PINNED_CATEGORY.slug;

  swapContent((container) => {
    tool.render(container);
  });

  document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.toolId === toolId));
  setBreadcrumb({
    sectionName: isPinned ? null : category.name,
    sectionSlug: isPinned ? null : category.slug,
    toolName: tool.name
  });
  if (!isPinned) setGroupExpanded(category.slug, true);
  sidebar.classList.remove('open');
  document.title = `${tool.name} — cybersec-toolkit`;
}

function renderSectionLanding(category) {
  swapContent((container) => {
    const eyebrow = el('p', { class: 'section-eyebrow' }, `SECTION · ${category.tools.length} TOOLS`);
    const title = el('h1', { class: 'section-title' }, category.name);
    const intro = el('p', { class: 'section-intro' }, category.intro);
    const grid = el('div', { class: 'card-grid' }, category.tools.map((tool) => {
      const copy = TOOL_COPY[tool.id];
      const card = el('button', { class: 'landing-card' }, [
        el('h3', { class: 'landing-card-title' }, tool.name),
        el('p', { class: 'landing-card-desc' }, copy ? copy.what : '')
      ]);
      card.addEventListener('click', () => selectTool(tool.id));
      return card;
    }));
    container.appendChild(el('div', { class: 'section-landing' }, [eyebrow, title, intro, grid]));
  });

  document.querySelectorAll('.nav-item').forEach((item) => item.classList.remove('active'));
  setBreadcrumb({ sectionName: category.name });
  setGroupExpanded(category.slug, true);
  document.title = `${category.name} — cybersec-toolkit`;
}

// ---------- Routing (hash = single source of truth) ----------
function route() {
  const hash = window.location.hash.replace('#', '');
  if (!hash) {
    renderHome();
    return;
  }
  if (hash.startsWith('section:')) {
    const slug = hash.slice('section:'.length);
    const category = CATEGORIES.find((c) => c.slug === slug);
    if (category) {
      renderSectionLanding(category);
      return;
    }
    renderHome();
    return;
  }
  const found = findToolWithCategory(hash);
  if (found) {
    renderTool(hash);
    return;
  }
  renderHome();
}

/** Navigates to a hash: updates window.location.hash (single source of
 * truth), which triggers the hashchange listener to actually render.
 * Navigating to the hash that's already active won't fire hashchange,
 * so route directly in that case. */
function navigateToHash(hash) {
  if (window.location.hash.replace('#', '') === hash) {
    route();
  } else {
    window.location.hash = hash;
  }
}

function selectTool(toolId) {
  navigateToHash(toolId);
  clearSearch();
}

function navigateToSection(slug) {
  navigateToHash(`section:${slug}`);
}

window.addEventListener('hashchange', route);

// ---------- Sidebar: pinned Recipe Chain ----------
function buildPinned() {
  clear(navPinned);
  const item = el('button', { class: 'nav-item', 'data-tool-id': RECIPE_TOOL.id }, [el('span', {}, RECIPE_TOOL.name)]);
  item.addEventListener('click', () => selectTool(RECIPE_TOOL.id));
  navPinned.appendChild(item);
}

// ---------- Sidebar: collapsible category groups (design spec §2B) ----------
function buildNav() {
  clear(nav);

  categoriesContainer = el('div', { id: 'nav-groups' });
  resultsContainer = el('div', { id: 'nav-results', class: 'nav-results' });
  resultsContainer.style.display = 'none';
  nav.appendChild(categoriesContainer);
  nav.appendChild(resultsContainer);

  for (const category of CATEGORIES) {
    const chevron = el('button', {
      class: 'nav-chevron',
      'aria-label': `Toggle ${category.name}`,
      'aria-expanded': 'false'
    }, '▸');
    const label = el('button', { class: 'nav-category-label' }, [
      el('span', {}, category.name),
      el('span', { class: 'nav-category-count' }, String(category.tools.length))
    ]);
    label.addEventListener('click', () => navigateToSection(category.slug));
    chevron.addEventListener('click', () => {
      const currentlyExpanded = navGroupEls[category.slug].body.classList.contains('expanded');
      setGroupExpanded(category.slug, !currentlyExpanded);
    });
    const headerRow = el('div', { class: 'nav-category-row' }, [label, chevron]);

    const bodyInner = el('div', {});
    for (const tool of category.tools) {
      const badge = EXTERNAL_API_TOOL_IDS.has(tool.id) ? el('span', { class: 'badge' }, '🌐') : null;
      const item = el('button', { class: 'nav-item', 'data-tool-id': tool.id }, [el('span', {}, tool.name), badge]);
      item.addEventListener('click', () => selectTool(tool.id));
      bodyInner.appendChild(item);
    }
    const body = el('div', { class: 'nav-group-body' }, [bodyInner]);

    categoriesContainer.appendChild(headerRow);
    categoriesContainer.appendChild(body);

    navGroupEls[category.slug] = { chevron, label, body };
    const initiallyExpanded = Object.prototype.hasOwnProperty.call(expandedState, category.slug)
      ? expandedState[category.slug]
      : false;
    setGroupExpanded(category.slug, initiallyExpanded, { persist: false });
  }
}

// ---------- Quick search / filter (design spec §2A) ----------
function excerptFor(copy, q) {
  const what = copy.what || '';
  const when = copy.when || '';
  const source = what.toLowerCase().includes(q) ? what : (when.toLowerCase().includes(q) ? when : what);
  return source.length > 110 ? `${source.slice(0, 107)}…` : source;
}

function highlightMatch(text, q) {
  if (!q) return [text];
  const idx = text.toLowerCase().indexOf(q);
  if (idx === -1) return [text];
  return [text.slice(0, idx), el('mark', {}, text.slice(idx, idx + q.length)), text.slice(idx + q.length)];
}

function computeSearchResults(query) {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const results = [];
  for (const category of allCategoriesForLookup()) {
    for (const tool of category.tools) {
      const copy = TOOL_COPY[tool.id] || { what: '', when: '' };
      const nameMatch = tool.name.toLowerCase().includes(q);
      const descOrSectionMatch = `${copy.what} ${copy.when} ${category.name}`.toLowerCase().includes(q);
      if (nameMatch || descOrSectionMatch) {
        results.push({
          tool,
          category,
          nameMatch,
          excerpt: nameMatch ? null : excerptFor(copy, q)
        });
      }
    }
  }
  // Name-match hits ranked above description-only hits (stable sort keeps
  // registry order within each rank).
  results.sort((a, b) => Number(b.nameMatch) - Number(a.nameMatch));
  return results;
}

function setSearchMode(active) {
  categoriesContainer.style.display = active ? 'none' : '';
  resultsContainer.style.display = active ? '' : 'none';
}

function updateHighlightClasses() {
  const items = resultsContainer.querySelectorAll('.nav-result-item');
  items.forEach((item, i) => item.classList.toggle('highlighted', i === highlightedIndex));
  const activeItem = items[highlightedIndex];
  if (activeItem) activeItem.scrollIntoView({ block: 'nearest' });
}

function moveHighlight(delta) {
  if (!currentResults.length) return;
  highlightedIndex = (highlightedIndex + delta + currentResults.length) % currentResults.length;
  updateHighlightClasses();
}

function activateHighlighted() {
  const r = currentResults[highlightedIndex];
  if (r) selectTool(r.tool.id);
}

function renderSearchResults(query) {
  const q = query.trim().toLowerCase();
  clear(resultsContainer);
  currentResults = computeSearchResults(query);
  highlightedIndex = currentResults.length ? 0 : -1;

  if (currentResults.length === 0) {
    const browseLink = el('a', { href: '#', class: 'browse-all-link' }, 'Browse all sections');
    browseLink.addEventListener('click', (e) => {
      e.preventDefault();
      clearSearch();
    });
    resultsContainer.appendChild(el('div', { class: 'nav-results-empty' }, [
      `No tools match "${query.trim()}". `,
      browseLink
    ]));
    return;
  }

  currentResults.forEach((r, i) => {
    const item = el('button', { class: 'nav-result-item' }, [
      el('div', { class: 'nav-result-name' }, highlightMatch(r.tool.name, q)),
      el('div', { class: 'nav-result-section' }, r.category.name),
      r.excerpt ? el('div', { class: 'nav-result-excerpt' }, r.excerpt) : null
    ]);
    item.addEventListener('click', () => selectTool(r.tool.id));
    item.addEventListener('mouseenter', () => {
      highlightedIndex = i;
      updateHighlightClasses();
    });
    resultsContainer.appendChild(item);
  });
  updateHighlightClasses();
}

function clearSearch() {
  searchInput.value = '';
  setSearchMode(false);
  clear(resultsContainer);
  currentResults = [];
  highlightedIndex = -1;
  const activeItem = nav.querySelector('.nav-item.active') || navPinned.querySelector('.nav-item.active');
  if (activeItem) activeItem.scrollIntoView({ block: 'nearest' });
}

let searchDebounceTimer = null;
searchInput.addEventListener('input', () => {
  clearTimeout(searchDebounceTimer);
  const query = searchInput.value;
  searchDebounceTimer = setTimeout(() => {
    if (query.trim()) {
      setSearchMode(true);
      renderSearchResults(query);
    } else {
      setSearchMode(false);
      clear(resultsContainer);
      currentResults = [];
      highlightedIndex = -1;
    }
  }, 120);
});

searchInput.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    e.preventDefault();
    clearSearch();
    searchInput.blur();
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    moveHighlight(1);
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    moveHighlight(-1);
  } else if (e.key === 'Enter') {
    e.preventDefault();
    activateHighlighted();
  }
});

// Global "/" focuses the search box (GitHub/Linear/Vercel convention),
// unless the user is already typing into some other field.
window.addEventListener('keydown', (e) => {
  if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
  const target = e.target;
  const isTyping = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable);
  if (isTyping) return;
  e.preventDefault();
  searchInput.focus();
});

document.getElementById('menu-toggle').addEventListener('click', () => {
  sidebar.classList.toggle('open');
});

// ---------- Init ----------
function init() {
  searchInput.placeholder = `Search ${TOTAL_TOOL_COUNT} tools…`;
  buildPinned();
  buildNav();
  route();
}

init();
