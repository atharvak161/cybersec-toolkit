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
import { CIPHER_TOOLS } from './ui/cipher-tools.js';
import { HASHING_TOOLS } from './ui/hashing-tools.js';
import { CRYPTO_TOOLS } from './ui/crypto-tools.js';
import { RECIPE_TOOL } from './ui/recipe-tools.js';
import { AUTO_DECODE_TOOLS } from './ui/auto-decode-tools.js';
import { PASSWORD_TOOLS } from './ui/password-tools.js';
import { FILES_TOOLS } from './ui/files-tools.js';
import { NETWORK_TOOLS } from './ui/network-tools.js';
import { EMAIL_TOOLS } from './ui/email-tools.js';
import { DEV_TOOLS } from './ui/dev-tools.js';
import { PENTEST_TOOLS } from './ui/pentest-tools.js';
import { TOOL_COPY } from './data/tool-copy.js';
import { openCommandPalette } from './ui/command-palette.js';
import { attachTooltip } from './ui/tooltip.js';

// ---------- 1. Information architecture (design spec §1) ----------
// Recipe Chain and Auto-Decode are both pinned above the category system
// entirely — each is a cross-cutting "meta tool" (chains other tools /
// auto-tries every decoder in the toolkit) rather than a peer of a single
// codec belonging to one category.
const PINNED_CATEGORY = { name: 'Recipe Builder', slug: 'recipe-builder', tools: [RECIPE_TOOL, ...AUTO_DECODE_TOOLS] };

const CATEGORIES = [
  {
    name: 'Encoding & Ciphers',
    slug: 'encoding-ciphers',
    tools: [...ENCODING_TOOLS, ...CIPHER_TOOLS],
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
    name: 'Email Authentication',
    slug: 'email-authentication',
    tools: EMAIL_TOOLS,
    intro: "Look up, generate, and troubleshoot the DNS records and headers that determine whether mail from a domain is trusted — SPF, DKIM, DMARC, BIMI, and a combined domain health check, plus a raw email header analyzer that traces the delivery path and authentication verdicts. Reach for this when you're setting up a domain's mail security, chasing down why legitimate mail is landing in spam, or triaging a suspicious message's headers."
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

const EXTERNAL_API_TOOL_IDS = new Set([
  'hibp', 'dns-lookup', 'whois-lookup', 'ip-geo',
  'spf-lookup', 'dkim-lookup', 'dmarc-lookup', 'bimi-lookup', 'domain-health'
]);

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

// ---------- Hover-preview tooltips (design spec v4 §3) ----------
// Tooltips attached to dynamically-rebuilt DOM (dashboard/section-landing
// cards, sidebar search results) are tracked per render batch and torn
// down before the next batch is built, so listeners never leak/stack.
let contentTooltipCleanups = [];
function clearContentTooltips() {
  contentTooltipCleanups.forEach((fn) => typeof fn === 'function' && fn());
  contentTooltipCleanups = [];
}
let searchResultTooltipCleanups = [];
function clearSearchResultTooltips() {
  searchResultTooltipCleanups.forEach((fn) => typeof fn === 'function' && fn());
  searchResultTooltipCleanups = [];
}

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
  clearContentTooltips();
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

// Truncates a copy sentence to just its first sentence (design spec §1 pt 4:
// dashboard cards are tighter on space than section-landing pages, so a
// 2-sentence category.intro is cut down to its first sentence only).
function firstSentenceOnly(text) {
  const idx = text.indexOf('. ');
  return idx === -1 ? text : text.slice(0, idx + 1);
}

// ---------- Rendering: home / tool / section landing ----------
function renderHome() {
  swapContent((container) => {
    const eyebrow = el('p', { class: 'section-eyebrow' }, 'CYBERSEC-TOOLKIT · 100% CLIENT-SIDE');
    const title = el('h1', { class: 'home-title' }, `${TOTAL_TOOL_COUNT} tools, ${allCategoriesForLookup().length} sections, zero servers.`);
    const meta = el('p', { class: 'dashboard-meta tabular-nums' }, `Nothing you type is sent anywhere except the ${EXTERNAL_API_TOOL_IDS.size} tools explicitly marked 🌐 (HIBP breach check; DNS, WHOIS, and IP geolocation lookups; SPF, DKIM, DMARC, and BIMI lookups; and the combined Domain Health check), each of which shows exactly what it calls before you use it.`);

    // One hero card per pinned tool — same dashboard-hero treatment Recipe
    // Chain always had. Recipe Chain keeps its existing "Recipe Builder"
    // branded title (PINNED_CATEGORY.name predates the second pinned tool);
    // Auto-Decode has no separate brand name, so its own tool name is used.
    const heroes = PINNED_CATEGORY.tools.map((tool) => {
      const heroCopy = TOOL_COPY[tool.id];
      const heroTitle = tool.id === RECIPE_TOOL.id ? PINNED_CATEGORY.name : tool.name;
      const hero = el('button', { class: 'landing-card dashboard-hero' }, [
        el('h3', { class: 'landing-card-title' }, heroTitle),
        el('p', { class: 'landing-card-desc' }, heroCopy ? heroCopy.what : '')
      ]);
      hero.addEventListener('click', () => selectTool(tool.id));
      contentTooltipCleanups.push(attachTooltip(hero, () => [tool.name]));
      return hero;
    });

    const grid = el('div', { class: 'card-grid' }, CATEGORIES.map((category) => {
      const isPentest = category.slug === 'pentest-ctf-reference';
      const card = el('button', { class: isPentest ? 'landing-card dashboard-card-info' : 'landing-card' }, [
        el('div', { class: 'landing-card-header' }, [
          el('h3', { class: 'landing-card-title' }, category.name),
          el('span', { class: 'landing-card-count' }, `${category.tools.length} tools`)
        ]),
        el('p', { class: 'landing-card-desc' }, firstSentenceOnly(category.intro))
      ]);
      card.addEventListener('click', () => navigateToSection(category.slug));
      contentTooltipCleanups.push(attachTooltip(card, () => category.tools.map((t) => t.name)));
      return card;
    }));

    container.appendChild(el('div', { class: 'dashboard' }, [eyebrow, title, meta, ...heroes, grid]));
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
      const badge = EXTERNAL_API_TOOL_IDS.has(tool.id) ? el('span', { class: 'badge' }, '🌐') : null;
      const card = el('button', { class: 'landing-card' }, [
        el('div', { class: 'landing-card-header' }, [
          el('h3', { class: 'landing-card-title' }, tool.name),
          badge
        ]),
        el('p', { class: 'landing-card-desc' }, copy ? copy.what : '')
      ]);
      card.addEventListener('click', () => selectTool(tool.id));
      // { when } only (no `what` key) — tooltip.js's object branch renders
      // just the "USE CASE" line for this shape; `what` is already visible
      // on the card face (landing-card-desc), so it's omitted here per spec.
      contentTooltipCleanups.push(attachTooltip(card, () => ({ when: copy ? copy.when : '' })));
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

// ---------- Sidebar: pinned meta-tools (Recipe Chain, Auto-Decode) ----------
function buildPinned() {
  clear(navPinned);
  for (const tool of PINNED_CATEGORY.tools) {
    const item = el('button', { class: 'nav-item', 'data-tool-id': tool.id }, [el('span', {}, tool.name)]);
    item.addEventListener('click', () => selectTool(tool.id));
    navPinned.appendChild(item);
    // Sidebar nav is built exactly once at init and never torn down, so the
    // cleanup fn attachTooltip returns has no rebuild moment to run at here.
    attachTooltip(item, () => TOOL_COPY[tool.id] || { what: '', when: '' });
  }
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
      attachTooltip(item, () => TOOL_COPY[tool.id] || { what: '', when: '' });
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
  clearSearchResultTooltips();
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
    const badge = EXTERNAL_API_TOOL_IDS.has(r.tool.id) ? el('span', { class: 'badge' }, '🌐') : null;
    const item = el('button', { class: 'nav-result-item' }, [
      el('div', { class: 'nav-result-name' }, [...highlightMatch(r.tool.name, q), badge]),
      el('div', { class: 'nav-result-section' }, r.category.name),
      r.excerpt ? el('div', { class: 'nav-result-excerpt' }, r.excerpt) : null
    ]);
    item.addEventListener('click', () => selectTool(r.tool.id));
    item.addEventListener('mouseenter', () => {
      highlightedIndex = i;
      updateHighlightClasses();
    });
    searchResultTooltipCleanups.push(attachTooltip(item, () => TOOL_COPY[r.tool.id] || { what: '', when: '' }));
    resultsContainer.appendChild(item);
  });
  updateHighlightClasses();
}

function clearSearch() {
  searchInput.value = '';
  setSearchMode(false);
  clearSearchResultTooltips();
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
      clearSearchResultTooltips();
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

// Global Cmd+K / Ctrl+K opens the command palette (design spec v4 §2) — a
// second, additional path alongside "/", not a replacement. Unlike "/",
// this fires unconditionally regardless of focus (even inside a tool's own
// input/textarea), per the spec's explicit "power-user path" decision.
// Reuses the exact same search index (computeSearchResults) and navigation
// (selectTool) the sidebar already uses — no forked matching logic.
window.addEventListener('keydown', (e) => {
  if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== 'k') return;
  e.preventDefault();
  openCommandPalette({ searchFn: computeSearchResults, onSelect: selectTool });
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
