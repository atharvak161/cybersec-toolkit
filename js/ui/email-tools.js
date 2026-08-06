import {
  lookupSpf, lookupDkim, lookupDmarc, lookupBimi,
  generateDmarc, lookupDomainHealth
} from '../lib/email-auth.js';
import { analyzeEmailHeaders } from '../lib/email-headers.js';
import { el, toolHeader, clear, resultLine, showError, externalApiBadge, copyButton } from './helpers.js';
import { TOOL_COPY } from '../data/tool-copy.js';

const DNS_BADGE_TEXT = 'Calls dns.google (Google Public DNS-over-HTTPS JSON API, no key required) — same lookup the DNS Lookup tool uses.';

const SEVERITY_COLOR = { pass: 'var(--accent)', warn: 'var(--warning)', fail: 'var(--danger)' };

function verdictColor(v) {
  if (!v) return 'var(--text-dim, inherit)';
  const lower = v.toLowerCase();
  if (['pass', 'reject', 'r'].includes(lower)) return 'var(--accent)';
  if (['softfail', 'neutral', 'quarantine', 'none'].includes(lower)) return 'var(--warning)';
  if (['fail', 'permerror', 'temperror'].includes(lower)) return 'var(--danger)';
  return 'inherit';
}

function warningList(warnings) {
  if (!warnings || !warnings.length) return null;
  const list = el('ul', { class: 'warning-list' });
  for (const w of warnings) list.appendChild(el('li', {}, w));
  return list;
}

function domainField(placeholder = 'example.com') {
  return el('input', { type: 'text', placeholder });
}

// ---------- 1. SPF Lookup ----------
function renderSpfLookup(container) {
  clear(container);
  container.appendChild(externalApiBadge(DNS_BADGE_TEXT));
  container.appendChild(toolHeader(TOOL_COPY['spf-lookup']));

  const domain = domainField();
  const runBtn = el('button', { class: 'btn' }, 'Lookup');
  const resultsBox = el('div', {});
  const errorNode = el('div', {});

  runBtn.addEventListener('click', async () => {
    clear(resultsBox);
    clear(errorNode);
    try {
      const r = await lookupSpf(domain.value.trim());
      const card = el('div', { class: 'card' });
      card.appendChild(resultLine('Overall policy (all)', r.all ? `${r.all}all` : (r.redirect ? `redirect=${r.redirect}` : 'none specified')));
      card.appendChild(resultLine('DNS-lookup mechanisms used', `${r.lookupCount} / 10 (RFC 7208 limit)`));
      if (r.multipleRecords) card.appendChild(resultLine('Multiple SPF records', 'yes — invalid per RFC 7208'));
      const w = warningList(r.warnings);
      if (w) card.appendChild(w);
      resultsBox.appendChild(card);

      const table = el('table', { class: 'data-table' }, [
        el('tr', {}, [el('th', {}, 'Qualifier'), el('th', {}, 'Mechanism'), el('th', {}, 'Value')]),
        ...r.mechanisms.map((m) => el('tr', {}, [
          el('td', {}, m.qualifier || '—'),
          el('td', {}, m.type),
          el('td', {}, m.value || '—')
        ]))
      ]);
      resultsBox.appendChild(table);

      const rawBox = el('div', { class: 'card' }, [el('label', {}, 'Raw record'), el('div', { class: 'result-line' }, r.raw)]);
      resultsBox.appendChild(rawBox);
    } catch (err) {
      showError(errorNode, err);
    }
  });

  container.appendChild(el('div', { class: 'card' }, [
    el('div', { class: 'field-row' }, [el('label', {}, 'Domain'), domain, runBtn]),
    errorNode
  ]));
  container.appendChild(resultsBox);
}

// ---------- 2. DKIM Lookup ----------
function renderDkimLookup(container) {
  clear(container);
  container.appendChild(externalApiBadge(DNS_BADGE_TEXT));
  container.appendChild(toolHeader(TOOL_COPY['dkim-lookup']));

  const domain = domainField();
  const selector = el('input', { type: 'text', placeholder: 'default', value: 'default' });
  const runBtn = el('button', { class: 'btn' }, 'Lookup');
  const resultsBox = el('div', {});
  const errorNode = el('div', {});

  runBtn.addEventListener('click', async () => {
    clear(resultsBox);
    clear(errorNode);
    try {
      const r = await lookupDkim(domain.value.trim(), selector.value.trim() || 'default');
      const card = el('div', { class: 'card' });
      card.appendChild(resultLine('Queried name', r.name));
      card.appendChild(resultLine('Version', r.version));
      card.appendChild(resultLine('Key type', r.keyType));
      card.appendChild(resultLine('Service type', r.serviceType));
      const status = r.revoked ? 'REVOKED (p= present but empty)' : r.missingKey ? 'MISSING (no p= tag)' : 'present';
      card.appendChild(el('p', {
        style: `color:${r.revoked || r.missingKey ? 'var(--danger)' : 'var(--accent)'}; font-weight:600`
      }, `Public key: ${status}`));
      const w = warningList(r.warnings);
      if (w) card.appendChild(w);
      resultsBox.appendChild(card);
      resultsBox.appendChild(el('div', { class: 'card' }, [el('label', {}, 'Raw record'), el('div', { class: 'result-line' }, r.raw)]));
    } catch (err) {
      showError(errorNode, err);
    }
  });

  container.appendChild(el('div', { class: 'card' }, [
    el('div', { class: 'field-row' }, [el('label', {}, 'Domain'), domain, el('label', {}, 'Selector'), selector, runBtn]),
    errorNode
  ]));
  container.appendChild(resultsBox);
}

// ---------- 3. DMARC Lookup ----------
function renderDmarcLookup(container) {
  clear(container);
  container.appendChild(externalApiBadge(DNS_BADGE_TEXT));
  container.appendChild(toolHeader(TOOL_COPY['dmarc-lookup']));

  const domain = domainField();
  const runBtn = el('button', { class: 'btn' }, 'Lookup');
  const resultsBox = el('div', {});
  const errorNode = el('div', {});

  runBtn.addEventListener('click', async () => {
    clear(resultsBox);
    clear(errorNode);
    try {
      const r = await lookupDmarc(domain.value.trim());
      const card = el('div', { class: 'card' });
      card.appendChild(el('p', { style: `color:${verdictColor(r.policy)}; font-weight:600` }, r.policyExplanation));
      card.appendChild(resultLine('Policy (p)', r.policy));
      card.appendChild(resultLine('Subdomain policy (sp)', r.subdomainPolicy));
      card.appendChild(resultLine('Percentage applied (pct)', `${r.pct}%`));
      card.appendChild(resultLine('DKIM alignment (adkim)', r.adkim === 's' ? 'strict' : 'relaxed'));
      card.appendChild(resultLine('SPF alignment (aspf)', r.aspf === 's' ? 'strict' : 'relaxed'));
      card.appendChild(resultLine('Failure options (fo)', r.fo));
      card.appendChild(resultLine('Aggregate reports (rua)', r.rua.join(', ') || '—'));
      card.appendChild(resultLine('Forensic reports (ruf)', r.ruf.join(', ') || '—'));
      const w = warningList(r.warnings);
      if (w) card.appendChild(w);
      resultsBox.appendChild(card);
      resultsBox.appendChild(el('div', { class: 'card' }, [el('label', {}, 'Raw record'), el('div', { class: 'result-line' }, r.raw)]));
    } catch (err) {
      showError(errorNode, err);
    }
  });

  container.appendChild(el('div', { class: 'card' }, [
    el('div', { class: 'field-row' }, [el('label', {}, 'Domain'), domain, runBtn]),
    errorNode
  ]));
  container.appendChild(resultsBox);
}

// ---------- 4. BIMI Lookup ----------
function renderBimiLookup(container) {
  clear(container);
  container.appendChild(externalApiBadge(DNS_BADGE_TEXT));
  container.appendChild(toolHeader(TOOL_COPY['bimi-lookup']));

  const domain = domainField();
  const selector = el('input', { type: 'text', placeholder: 'default', value: 'default' });
  const runBtn = el('button', { class: 'btn' }, 'Lookup');
  const resultsBox = el('div', {});
  const errorNode = el('div', {});

  runBtn.addEventListener('click', async () => {
    clear(resultsBox);
    clear(errorNode);
    try {
      const r = await lookupBimi(domain.value.trim(), selector.value.trim() || 'default');
      const card = el('div', { class: 'card' });
      card.appendChild(resultLine('Queried name', r.name));
      card.appendChild(resultLine('Logo SVG URL (l=)', r.logoUrl || '—'));
      card.appendChild(resultLine('VMC certificate URL (a=)', r.vmcUrl || 'not present (self-asserted logo, no Verified Mark Certificate)'));
      resultsBox.appendChild(card);
      resultsBox.appendChild(el('div', { class: 'card' }, [el('label', {}, 'Raw record'), el('div', { class: 'result-line' }, r.raw)]));

      // Best-effort cross-check: BIMI requires DMARC at enforcement to
      // actually display in most mailbox providers. Don't fail the whole
      // lookup if the DMARC check itself errors — just note it.
      const dmarcCard = el('div', { class: 'card' });
      dmarcCard.appendChild(el('h3', {}, 'DMARC enforcement cross-check'));
      try {
        const dmarc = await lookupDmarc(domain.value.trim());
        const enforced = ['quarantine', 'reject'].includes(dmarc.policy);
        dmarcCard.appendChild(el('p', {
          style: `color:${enforced ? 'var(--accent)' : 'var(--warning)'}; font-weight:600`
        }, enforced
          ? `DMARC policy is p=${dmarc.policy} — enforcement requirement met.`
          : `DMARC policy is p=${dmarc.policy} — most mailbox providers require p=quarantine or p=reject for BIMI to display.`));
      } catch (dmarcErr) {
        dmarcCard.appendChild(el('p', { style: 'color:var(--danger); font-weight:600' },
          `No DMARC record found — BIMI will not display without DMARC at enforcement (p=quarantine or p=reject).`));
      }
      resultsBox.appendChild(dmarcCard);
    } catch (err) {
      showError(errorNode, err);
    }
  });

  container.appendChild(el('div', { class: 'card' }, [
    el('div', { class: 'field-row' }, [el('label', {}, 'Domain'), domain, el('label', {}, 'Selector'), selector, runBtn]),
    errorNode
  ]));
  container.appendChild(resultsBox);
}

// ---------- 5. DMARC Generator (pure, no network) ----------
function renderDmarcGenerator(container) {
  clear(container);
  container.appendChild(toolHeader(TOOL_COPY['dmarc-generator']));

  const policySelect = el('select', {}, ['none', 'quarantine', 'reject'].map((v) => el('option', { value: v }, v)));
  const spSelect = el('select', {}, ['(inherit from p)', 'none', 'quarantine', 'reject'].map((v) => el('option', { value: v === '(inherit from p)' ? '' : v }, v)));
  const ruaInput = el('input', { type: 'text', placeholder: 'mailto:dmarc-reports@example.com' });
  const rufInput = el('input', { type: 'text', placeholder: 'mailto:forensic@example.com (optional)' });
  const pctInput = el('input', { type: 'number', value: '100', min: '0', max: '100', style: 'width:90px' });
  const adkimSelect = el('select', {}, [['r', 'relaxed (r)'], ['s', 'strict (s)']].map(([v, label]) => el('option', { value: v }, label)));
  const aspfSelect = el('select', {}, [['r', 'relaxed (r)'], ['s', 'strict (s)']].map(([v, label]) => el('option', { value: v }, label)));
  const foInput = el('input', { type: 'text', placeholder: '0 (optional, e.g. 0, 1, d, 1:d)', style: 'width:200px' });
  const generateBtn = el('button', { class: 'btn' }, 'Generate record');
  const output = el('input', { type: 'text', readonly: 'true', class: 'output', style: 'font-size:15px' });
  const errorNode = el('div', {});

  generateBtn.addEventListener('click', () => {
    clear(errorNode);
    output.value = '';
    try {
      output.value = generateDmarc({
        policy: policySelect.value,
        subdomainPolicy: spSelect.value,
        rua: ruaInput.value,
        ruf: rufInput.value,
        pct: pctInput.value,
        adkim: adkimSelect.value,
        aspf: aspfSelect.value,
        fo: foInput.value
      });
    } catch (err) {
      showError(errorNode, err);
    }
  });

  container.appendChild(el('div', { class: 'card' }, [
    el('div', { class: 'field-row' }, [
      el('div', {}, [el('label', {}, 'Policy (p)'), policySelect]),
      el('div', {}, [el('label', {}, 'Subdomain policy (sp)'), spSelect])
    ]),
    el('label', { style: 'margin-top:10px' }, 'Aggregate reports (rua) — comma-separated mailto: URIs'), ruaInput,
    el('label', { style: 'margin-top:10px' }, 'Forensic reports (ruf) — comma-separated mailto: URIs'), rufInput,
    el('div', { class: 'field-row', style: 'margin-top:10px' }, [
      el('div', {}, [el('label', {}, 'Percentage (pct)'), pctInput]),
      el('div', {}, [el('label', {}, 'DKIM alignment (adkim)'), adkimSelect]),
      el('div', {}, [el('label', {}, 'SPF alignment (aspf)'), aspfSelect])
    ]),
    el('label', { style: 'margin-top:10px' }, 'Failure options (fo)'), foInput,
    el('div', { class: 'field-row', style: 'margin-top:10px' }, [generateBtn]),
    errorNode,
    el('label', { style: 'margin-top:10px' }, 'Generated TXT record — publish at _dmarc.yourdomain.com'), output,
    el('div', { class: 'field-row', style: 'margin-top:6px' }, [copyButton(() => output.value)])
  ]));
}

// ---------- 6. Domain Health Lookup (combined) ----------
function healthCheckCard(title, result, renderOk) {
  const card = el('div', { class: 'card' });
  card.appendChild(el('h3', {}, title));
  if (result.ok) {
    card.appendChild(el('p', { style: 'color:var(--accent); font-weight:600' }, 'Present'));
    renderOk(card, result.data);
  } else {
    card.appendChild(el('p', { style: 'color:var(--danger); font-weight:600' }, `Absent — ${result.error}`));
  }
  return card;
}

function renderDomainHealth(container) {
  clear(container);
  container.appendChild(externalApiBadge(DNS_BADGE_TEXT + ' Runs the DMARC, SPF, and BIMI lookups for one domain in a single pass.'));
  container.appendChild(toolHeader(TOOL_COPY['domain-health']));

  const domain = domainField();
  const runBtn = el('button', { class: 'btn' }, 'Run health check');
  const resultsBox = el('div', {});
  const errorNode = el('div', {});

  runBtn.addEventListener('click', async () => {
    clear(resultsBox);
    clear(errorNode);
    runBtn.disabled = true;
    runBtn.textContent = 'Checking…';
    try {
      const health = await lookupDomainHealth(domain.value.trim());

      const summary = el('div', { class: 'card' });
      const scoreLabel = { pass: 'PASS — email authentication looks solid', warn: 'WARN — email authentication has gaps', fail: 'FAIL — critical email authentication records missing' }[health.overall.score];
      summary.appendChild(el('p', { style: `color:${SEVERITY_COLOR[health.overall.score]}; font-weight:700; font-size:15px` }, scoreLabel));
      const issuesList = warningList(health.overall.issues);
      if (issuesList) summary.appendChild(issuesList);
      resultsBox.appendChild(summary);

      resultsBox.appendChild(healthCheckCard('DMARC', health.dmarc, (card, data) => {
        card.appendChild(resultLine('Policy', `p=${data.policy}${data.subdomainPolicy !== data.policy ? `, sp=${data.subdomainPolicy}` : ''}`));
        card.appendChild(resultLine('Explanation', data.policyExplanation));
      }));
      resultsBox.appendChild(healthCheckCard('SPF', health.spf, (card, data) => {
        card.appendChild(resultLine('Policy', data.all ? `${data.all}all` : (data.redirect ? `redirect=${data.redirect}` : 'no catch-all')));
        card.appendChild(resultLine('DNS lookups used', `${data.lookupCount} / 10`));
      }));
      resultsBox.appendChild(healthCheckCard('BIMI', health.bimi, (card, data) => {
        card.appendChild(resultLine('Logo URL', data.logoUrl || '—'));
        card.appendChild(resultLine('VMC certificate', data.vmcUrl || 'not present'));
      }));
    } catch (err) {
      showError(errorNode, err);
    }
    runBtn.disabled = false;
    runBtn.textContent = 'Run health check';
  });

  container.appendChild(el('div', { class: 'card' }, [
    el('div', { class: 'field-row' }, [el('label', {}, 'Domain'), domain, runBtn]),
    errorNode
  ]));
  container.appendChild(resultsBox);
}

// ---------- 7. Email Header Analyzer (pure, no network) ----------
function renderHeaderAnalyzer(container) {
  clear(container);
  container.appendChild(toolHeader(TOOL_COPY['header-analyzer']));
  container.appendChild(el('p', { class: 'tool-copy-line' }, [
    el('strong', {}, 'How to get the raw headers: '),
    'In Gmail: open the message -> the ⋮ menu -> "Show original". In Outlook: File -> Properties -> "Internet headers". Paste the full raw block below.'
  ]));

  const input = el('textarea', { rows: '12', placeholder: 'Delivered-To: you@example.com\nReceived: from …\nAuthentication-Results: …\nFrom: sender@example.com\n…' });
  const runBtn = el('button', { class: 'btn' }, 'Analyze headers');
  const resultsBox = el('div', {});
  const errorNode = el('div', {});

  runBtn.addEventListener('click', () => {
    clear(resultsBox);
    clear(errorNode);
    try {
      const { basics, receivedChain, authentication } = analyzeEmailHeaders(input.value);

      const basicsCard = el('div', { class: 'card' });
      basicsCard.appendChild(el('h3', {}, 'Message'));
      basicsCard.appendChild(resultLine('From', basics.from || '—'));
      basicsCard.appendChild(resultLine('To', basics.to || '—'));
      basicsCard.appendChild(resultLine('Subject', basics.subject || '—'));
      basicsCard.appendChild(resultLine('Date', basics.date || '—'));
      basicsCard.appendChild(resultLine('Message-ID', basics.messageId || '—'));
      resultsBox.appendChild(basicsCard);

      const authCard = el('div', { class: 'card' });
      authCard.appendChild(el('h3', {}, 'Authentication verdicts'));
      const { spf, dkim, dmarc } = authentication.verdicts;
      authCard.appendChild(el('div', { class: 'field-row' }, [
        el('span', { style: `font-weight:700; color:${verdictColor(spf)}` }, `SPF: ${spf || 'not reported'}`),
        el('span', { style: `font-weight:700; color:${verdictColor(dkim)}` }, `DKIM: ${dkim || 'not reported'}`),
        el('span', { style: `font-weight:700; color:${verdictColor(dmarc)}` }, `DMARC: ${dmarc || 'not reported'}`)
      ]));
      if (authentication.dkimSignatures.length) {
        authCard.appendChild(el('p', { class: 'tool-desc', style: 'margin-top:8px' },
          `${authentication.dkimSignatures.length} DKIM-Signature header(s): ${authentication.dkimSignatures.map((s) => `d=${s.domain || '?'} s=${s.selector || '?'} a=${s.algorithm || '?'}`).join('; ')}. (Signature presence only — this is a passive reader, not a cryptographic verifier.)`));
      }
      if (authentication.arcChainPresent) {
        authCard.appendChild(el('p', { class: 'tool-desc' }, `ARC chain present: ${authentication.arcHopCount} seal(s) — message was forwarded through at least one ARC-aware intermediary.`));
      }
      resultsBox.appendChild(authCard);

      const chainCard = el('div', { class: 'card' });
      chainCard.appendChild(el('h3', {}, `Delivery path — ${receivedChain.hopCount} hop${receivedChain.hopCount === 1 ? '' : 's'}`));
      if (!receivedChain.hopCount) {
        chainCard.appendChild(el('p', { class: 'tool-desc' }, 'No Received: headers found in the pasted block.'));
      } else {
        const table = el('table', { class: 'data-table' }, [
          el('tr', {}, [el('th', {}, '#'), el('th', {}, 'From'), el('th', {}, 'By'), el('th', {}, 'Protocol'), el('th', {}, 'Timestamp')]),
          ...receivedChain.hops.map((h) => el('tr', {}, [
            el('td', { class: 'tabular-nums' }, String(h.hop)),
            el('td', {}, h.from || '—'),
            el('td', {}, h.by || '—'),
            el('td', {}, h.protocol || '—'),
            el('td', {}, h.dateRaw || '—')
          ]))
        ]);
        chainCard.appendChild(table);
        if (receivedChain.gaps.length) {
          const gapList = el('ul', { class: 'warning-list' });
          for (const g of receivedChain.gaps) {
            const minutes = Math.round(Math.abs(g.deltaMs) / 60000);
            gapList.appendChild(el('li', {}, `${minutes}-minute gap between hop ${g.afterHop} and hop ${g.beforeHop}.`));
          }
          chainCard.appendChild(gapList);
        }
      }
      resultsBox.appendChild(chainCard);
    } catch (err) {
      showError(errorNode, err);
    }
  });

  container.appendChild(el('div', { class: 'card' }, [
    el('label', {}, 'Raw email headers'), input,
    el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
    errorNode
  ]));
  container.appendChild(resultsBox);
}

export const EMAIL_TOOLS = [
  { id: 'spf-lookup', name: 'SPF Lookup', render: renderSpfLookup },
  { id: 'dkim-lookup', name: 'DKIM Lookup', render: renderDkimLookup },
  { id: 'dmarc-lookup', name: 'DMARC Lookup', render: renderDmarcLookup },
  { id: 'bimi-lookup', name: 'BIMI Lookup', render: renderBimiLookup },
  { id: 'dmarc-generator', name: 'DMARC Record Generator', render: renderDmarcGenerator },
  { id: 'domain-health', name: 'Domain Health Lookup', render: renderDomainHealth },
  { id: 'header-analyzer', name: 'Email Header Analyzer', render: renderHeaderAnalyzer }
];
