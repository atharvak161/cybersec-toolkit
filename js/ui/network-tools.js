import { calculateIpv4Subnet, calculateIpv6Subnet } from '../lib/cidr.js';
import { testRegex, COMMON_PATTERNS } from '../lib/regex-patterns.js';
import { analyzeUrl } from '../lib/phishing.js';
import { lookupDns, lookupWhois, lookupIpGeo } from '../lib/net-lookups.js';
import { el, toolHeader, clear, resultLine, showError, externalApiBadge } from './helpers.js';

export const NETWORK_TOOLS = [
  {
    id: 'cidr',
    name: 'CIDR / Subnet Calculator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Enter an IPv4 or IPv6 CIDR (e.g. 192.168.1.0/24 or 2001:db8::/32).'));

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
    id: 'regex-tester',
    name: 'Regex Tester',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Test a regular expression against sample text, or pick from a small library of common patterns.'));

      const presetSelect = el('select', {}, [
        el('option', { value: '' }, '— pick a common pattern —'),
        ...COMMON_PATTERNS.map((p) => el('option', { value: p.name }, p.name))
      ]);
      const patternInput = el('input', { type: 'text', placeholder: 'Regex pattern (without slashes)' });
      const flagsInput = el('input', { type: 'text', placeholder: 'Flags e.g. gi', value: 'g' });
      const textInput = el('textarea', { rows: '5', placeholder: 'Text to search…' });
      const runBtn = el('button', { class: 'btn' }, 'Test');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});

      presetSelect.addEventListener('change', () => {
        const preset = COMMON_PATTERNS.find((p) => p.name === presetSelect.value);
        if (preset) {
          patternInput.value = preset.pattern;
          flagsInput.value = preset.flags + 'g';
        }
      });

      runBtn.addEventListener('click', () => {
        clear(errorNode);
        clear(resultsBox);
        try {
          const matches = testRegex(patternInput.value, flagsInput.value, textInput.value);
          resultsBox.appendChild(el('p', { class: 'tool-desc' }, `${matches.length} match${matches.length === 1 ? '' : 'es'}`));
          const table = el('table', { class: 'data-table' }, [
            el('tr', {}, [el('th', {}, '#'), el('th', {}, 'Match'), el('th', {}, 'Index'), el('th', {}, 'Groups')]),
            ...matches.map((m, i) => el('tr', {}, [
              el('td', {}, String(i + 1)), el('td', {}, m.match), el('td', {}, String(m.index)),
              el('td', {}, m.groups.filter((g) => g !== undefined).join(', ') || '—')
            ]))
          ]);
          resultsBox.appendChild(table);
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'Preset'), presetSelect]),
        el('div', { class: 'field-row' }, [
          el('div', { style: 'flex:1' }, [el('label', {}, 'Pattern'), patternInput]),
          el('div', { style: 'width:120px' }, [el('label', {}, 'Flags'), flagsInput])
        ]),
        el('label', { style: 'margin-top:10px' }, 'Text'), textInput,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'phishing-checker',
    name: 'Phishing URL Heuristic Checker',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Pure client-side pattern analysis — NOT a live blocklist lookup. Flags IP-literal hosts, excessive subdomains, punycode/homograph indicators, and lookalike domains against common brands.'));

      const input = el('input', { type: 'text', placeholder: 'https://example.com/path' });
      const runBtn = el('button', { class: 'btn' }, 'Analyze');
      const resultsBox = el('div', {});

      runBtn.addEventListener('click', () => {
        clear(resultsBox);
        const result = analyzeUrl(input.value);
        const card = el('div', { class: 'card' });
        const riskColor = { minimal: 'var(--accent)', low: 'var(--info)', medium: 'var(--warning)', high: 'var(--danger)' }[result.risk] || 'var(--text)';
        card.appendChild(el('p', { style: `color:${riskColor}; font-weight:700; font-size:16px` }, `Risk: ${result.risk.toUpperCase()} (score ${result.score}/100)`));
        const list = el('ul', {});
        for (const r of result.reasons) list.appendChild(el('li', {}, r));
        card.appendChild(list);
        resultsBox.appendChild(card);
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'URL'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn])
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
      container.appendChild(toolHeader('Look up DNS records for a domain via a public resolver — not a scan, just a standard DNS query.'));

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
      container.appendChild(toolHeader('Look up domain registration info via RDAP — a read-only public registry query, not active scanning.'));

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
      container.appendChild(toolHeader('Approximate geolocation for a public IP address, via a public read-only API.'));

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
  }
];
