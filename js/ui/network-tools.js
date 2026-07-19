import { calculateIpv4Subnet, calculateIpv6Subnet } from '../lib/cidr.js';
import { lookupDns, lookupWhois, lookupIpGeo } from '../lib/net-lookups.js';
import { analyzeHeaders } from '../lib/http-headers.js';
import { searchPorts } from '../lib/ports-reference.js';
import { el, toolHeader, clear, resultLine, showError, externalApiBadge } from './helpers.js';
import { TOOL_COPY } from '../data/tool-copy.js';

export const NETWORK_TOOLS = [
  {
    id: 'cidr',
    name: 'CIDR / Subnet Calculator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY.cidr));

      const input = el('input', { type: 'text', placeholder: '192.168.1.10/24', value: '192.168.1.10/24' });
      const runBtn = el('button', { class: 'btn' }, 'Calculate');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      runBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(resultsBox);
        try {
          const card = el('div', { class: 'card' });
          if (input.value.includes(':')) {
            const r = calculateIpv6Subnet(input.value);
            card.appendChild(resultLine('Network address', r.networkAddress));
            card.appendChild(resultLine('Last address', r.lastAddress));
            card.appendChild(resultLine('Prefix', '/' + r.prefix));
            card.appendChild(resultLine('Total addresses', r.totalAddresses));
          } else {
            const r = calculateIpv4Subnet(input.value);
            card.appendChild(resultLine('Network address', r.networkAddress));
            card.appendChild(resultLine('Broadcast address', r.broadcastAddress));
            card.appendChild(resultLine('Netmask', r.netmask));
            card.appendChild(resultLine('Wildcard mask', r.wildcardMask));
            card.appendChild(resultLine('Usable host range', `${r.firstUsable} – ${r.lastUsable}`));
            card.appendChild(resultLine('Usable hosts', r.usableHosts.toLocaleString()));
            card.appendChild(resultLine('Total addresses', r.totalAddresses.toLocaleString()));
          }
          resultsBox.appendChild(card);
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'CIDR'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'dns-lookup',
    name: 'DNS Lookup',
    render(container) {
      clear(container);
      container.appendChild(externalApiBadge('Calls dns.google (Google Public DNS-over-HTTPS JSON API, no key required).'));
      container.appendChild(toolHeader(TOOL_COPY['dns-lookup']));

      const domain = el('input', { type: 'text', placeholder: 'example.com' });
      const type = el('select', {}, ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'].map((t) => el('option', { value: t }, t)));
      const runBtn = el('button', { class: 'btn' }, 'Lookup');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      runBtn.addEventListener('click', async () => {
        clear(resultsBox);
        clear(errorNode);
        try {
          const { records } = await lookupDns(domain.value, type.value);
          if (!records.length) {
            resultsBox.appendChild(el('p', {}, 'No records found.'));
          } else {
            const table = el('table', { class: 'data-table' }, [
              el('tr', {}, [el('th', {}, 'Name'), el('th', {}, 'Type'), el('th', {}, 'TTL'), el('th', {}, 'Data')]),
              ...records.map((r) => el('tr', {}, [el('td', {}, r.name), el('td', {}, String(r.type)), el('td', {}, String(r.ttl)), el('td', {}, r.data)]))
            ]);
            resultsBox.appendChild(table);
          }
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'Domain'), domain, el('label', {}, 'Type'), type, runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'whois-lookup',
    name: 'WHOIS Lookup (RDAP)',
    render(container) {
      clear(container);
      container.appendChild(externalApiBadge('Calls rdap.org (IETF/IANA-standardized WHOIS successor, no key required).'));
      container.appendChild(toolHeader(TOOL_COPY['whois-lookup']));

      const domain = el('input', { type: 'text', placeholder: 'example.com' });
      const runBtn = el('button', { class: 'btn' }, 'Lookup');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      runBtn.addEventListener('click', async () => {
        clear(resultsBox);
        clear(errorNode);
        try {
          const r = await lookupWhois(domain.value);
          const card = el('div', { class: 'card' });
          card.appendChild(resultLine('Domain', r.domain || '—'));
          card.appendChild(resultLine('Registrar', r.registrar || '—'));
          card.appendChild(resultLine('Registered', r.registrationDate || '—'));
          card.appendChild(resultLine('Expires', r.expirationDate || '—'));
          card.appendChild(resultLine('Status', (r.statuses || []).join(', ') || '—'));
          card.appendChild(resultLine('Nameservers', (r.nameservers || []).join(', ') || '—'));
          resultsBox.appendChild(card);
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
  },
  {
    id: 'ip-geo',
    name: 'IP Geolocation Lookup',
    render(container) {
      clear(container);
      container.appendChild(externalApiBadge('Calls ipapi.co (no key required for basic lookups).'));
      container.appendChild(toolHeader(TOOL_COPY['ip-geo']));

      const ip = el('input', { type: 'text', placeholder: '8.8.8.8' });
      const runBtn = el('button', { class: 'btn' }, 'Lookup');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      runBtn.addEventListener('click', async () => {
        clear(resultsBox);
        clear(errorNode);
        try {
          const r = await lookupIpGeo(ip.value);
          if (r.error) throw new Error(r.error);
          const card = el('div', { class: 'card' });
          card.appendChild(resultLine('IP', r.ip));
          card.appendChild(resultLine('City', r.city));
          card.appendChild(resultLine('Region', r.region));
          card.appendChild(resultLine('Country', `${r.country} (${r.countryCode})`));
          card.appendChild(resultLine('Coordinates', `${r.latitude}, ${r.longitude}`));
          card.appendChild(resultLine('Organization', r.org));
          card.appendChild(resultLine('Timezone', r.timezone));
          resultsBox.appendChild(card);
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'IP address'), ip, runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'http-headers',
    name: 'HTTP Security Headers Checker',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['http-headers']));
      container.appendChild(el('p', { class: 'tool-copy-line' }, [
        el('strong', {}, 'How to get headers: '),
        "In Chrome/Firefox devtools, open the Network tab, reload the page, click the document request, and copy the Response Headers (Firefox: right-click a header → \"Copy Headers\"; Chrome: view source under Headers). Paste the raw block below — one \"Name: value\" pair per line."
      ]));
      container.appendChild(el('p', { class: 'tool-copy-line' }, [
        el('strong', {}, 'Why not just fetch the URL directly? '),
        "This toolkit is 100% client-side with no backend proxy, so a direct fetch() from your browser is subject to the target site's CORS policy — most sites will block it, and that's expected, not a bug. Pasting headers you already have (from devtools, or from curl -I) sidesteps CORS entirely."
      ]));

      const input = el('textarea', { rows: '10', placeholder: 'HTTP/1.1 200 OK\nContent-Type: text/html\nStrict-Transport-Security: max-age=63072000\n…' });
      const runBtn = el('button', { class: 'btn' }, 'Analyze headers');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      runBtn.addEventListener('click', () => {
        clear(resultsBox);
        clear(errorNode);
        try {
          const { present, missing, infoLeaks } = analyzeHeaders(input.value);

          const summary = el('div', { class: 'card' });
          summary.appendChild(el('p', { style: `color:${missing.length ? 'var(--warning)' : 'var(--accent)'}; font-weight:600` },
            missing.length ? `${missing.length} security header${missing.length === 1 ? '' : 's'} missing.` : 'All checked security headers are present.'
          ));
          resultsBox.appendChild(summary);

          if (missing.length) {
            const missingCard = el('div', { class: 'card' });
            missingCard.appendChild(el('h3', {}, 'Missing'));
            for (const h of missing) {
              missingCard.appendChild(el('div', { class: 'ref-item' }, [
                el('p', { class: 'ref-item-title' }, h.label),
                el('p', { class: 'ref-item-note' }, h.why)
              ]));
            }
            resultsBox.appendChild(missingCard);
          }

          if (present.length) {
            const presentCard = el('div', { class: 'card' });
            presentCard.appendChild(el('h3', {}, 'Present'));
            for (const h of present) presentCard.appendChild(resultLine(h.label, h.value));
            resultsBox.appendChild(presentCard);
          }

          if (infoLeaks.length) {
            const leakCard = el('div', { class: 'card' });
            leakCard.appendChild(el('h3', {}, 'Minor information disclosure'));
            for (const h of infoLeaks) {
              leakCard.appendChild(el('div', { class: 'ref-item' }, [
                el('p', { class: 'ref-item-title' }, `${h.label}: ${h.value}`),
                el('p', { class: 'ref-item-note' }, h.note)
              ]));
            }
            resultsBox.appendChild(leakCard);
          }
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Pasted response headers'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'ports-reference',
    name: 'Well-Known Ports Reference',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(TOOL_COPY['ports-reference']));

      const searchInput = el('input', { type: 'text', class: 'ref-search', placeholder: 'Search by port, protocol, or service name…' });
      const resultsBox = el('div', {});

      function renderResults(query) {
        clear(resultsBox);
        const results = searchPorts(query);
        if (results.length === 0) {
          resultsBox.appendChild(el('p', { class: 'tool-desc' }, `No ports match "${query}".`));
          return;
        }
        const table = el('table', { class: 'data-table' }, [
          el('tr', {}, [el('th', {}, 'Port'), el('th', {}, 'Proto'), el('th', {}, 'Service'), el('th', {}, 'Description')]),
          ...results.map((p) => el('tr', {}, [
            el('td', { class: 'tabular-nums' }, String(p.port)), el('td', {}, p.proto), el('td', {}, p.name), el('td', {}, p.desc)
          ]))
        ]);
        resultsBox.appendChild(table);
      }

      searchInput.addEventListener('input', () => renderResults(searchInput.value));

      container.appendChild(el('div', { class: 'card' }, [searchInput]));
      renderResults('');
      container.appendChild(resultsBox);
    }
  }
];
