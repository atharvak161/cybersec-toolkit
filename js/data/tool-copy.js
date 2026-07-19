/**
 * Tool description copy — "what it does" + "when to use it" for every
 * tool in the toolkit (48 entries: 35 v1/v2 tools + 13 v3 additions).
 * Source: docs/design/cybersec-toolkit-v3-tool-copy.md (org repo, not
 * shipped with this project) — pasted here verbatim per the v3 design
 * spec's instruction not to rewrite the substance. Keyed by tool id so
 * every tool-*.js UI module can pull its copy from one place instead of
 * duplicating description strings inline.
 */

export const TOOL_COPY = {
  // ---------- Recipe Builder ----------
  'recipe-chain': {
    what: 'Chains multiple encode, hash, and crypto operations into an ordered pipeline and shows the live output after every step.',
    when: "You've got a blob that's base64-then-gzip-then-hex, or you're reverse-engineering what transform produced a string, and you need to stack operations and watch the intermediate output instead of running each tool by hand one at a time."
  },

  // ---------- Section 1: Encoding & Ciphers ----------
  hex: {
    what: 'Converts text to and from hexadecimal byte representation.',
    when: "You're staring at a raw byte dump or a \\x-escaped string in a config file and need to read it as text, or the other way around."
  },
  base64: {
    what: 'Encodes and decodes standard Base64 (RFC 4648).',
    when: "You've got a JWT segment, an email attachment, or an API payload that's clearly base64 and you want the plain content without spinning up a script."
  },
  base32: {
    what: 'Encodes and decodes standard Base32 (RFC 4648).',
    when: "You're reading a TOTP secret or a DNS TXT record that's Base32-encoded and need the underlying value."
  },
  base58: {
    what: 'Encodes and decodes Bitcoin-alphabet Base58 (no 0/O/I/l).',
    when: "You're decoding a Bitcoin address or another Base58Check-style identifier and need to see the raw bytes underneath."
  },
  base85: {
    what: 'Encodes and decodes the Adobe variant of Ascii85.',
    when: "You've pulled a binary blob out of a PDF or PostScript file and it's Ascii85-wrapped — this unwraps it."
  },
  base91: {
    what: 'Encodes and decodes basE91, a denser alternative to Base64.',
    when: 'You come across basE91 in a CTF challenge or a compact data format and need a quick decode without installing a library.'
  },
  url: {
    what: 'Percent-encodes and decodes text for safe use in URLs.',
    when: "You're debugging a query string with mangled %xx sequences, or need to safely embed a value with spaces or special characters into a URL."
  },
  binary: {
    what: 'Converts text to and from space-separated 8-bit binary groups.',
    when: "You're working through a CTF puzzle or a low-level exercise that hands you raw binary and you want it back as readable text."
  },
  uuencode: {
    what: 'Encodes and decodes the classic Unix-to-Unix uuencode format.',
    when: "You've inherited an old email attachment or Usenet-era file dump that still uses begin/end uuencoding and need to extract the content."
  },
  'rot13-caesar': {
    what: 'Shifts letters by a fixed amount — 13 by default (ROT13), or any shift you set.',
    when: 'You spot an obviously letter-shifted forum post or CTF hint and want the plaintext without doing the arithmetic yourself.'
  },
  punycode: {
    what: 'Converts an internationalized domain name between Unicode and its ASCII xn-- form.',
    when: 'You see an xn-- prefix in a URL and want to know what it actually spells before deciding whether to trust it.'
  },
  morse: {
    what: 'Encodes and decodes text to and from Morse code (dots and dashes).',
    when: 'A CTF challenge, puzzle, or old radio-log excerpt hands you a string of dots and dashes and you need the plain text fast.'
  },

  // ---------- Section 2: Hashing & Integrity ----------
  'hash-generator': {
    what: 'Computes MD5, SHA-1, SHA-256, SHA-512, SHA-3-256, and CRC32 digests of any text you paste in.',
    when: 'You need to check a hash a vendor published against your own copy of a string, or generate a checksum to paste into a bug report or changelog.'
  },
  hmac: {
    what: 'Computes an HMAC (SHA-1/256/384/512) over a message using a key you supply.',
    when: "You're verifying a webhook signature or testing an API integration that signs requests with HMAC and need to confirm your implementation produces the expected value."
  },
  'hash-identifier': {
    what: "Looks at a hash's length and character set and suggests which algorithm(s) it's likely to be.",
    when: 'You find a bare hex string in a leaked file or a config and need a starting guess for what produced it — treat the result as a lead, not proof, since several algorithms share output lengths.'
  },
  'file-hash-checker': {
    what: "Drag a file in and get its MD5/SHA-1/SHA-256 and other hashes, computed entirely in your browser.",
    when: 'You downloaded an installer or ISO and want to confirm its hash matches what the publisher listed, without uploading the file anywhere.'
  },

  // ---------- Section 3: Cryptography ----------
  'jwt-decoder': {
    what: 'Decodes a JWT\'s header and payload and flags issues like alg:none or an expired exp claim.',
    when: 'You found a JWT in a request and want to see what\'s inside it — claims, expiry, algorithm — without a signature check.'
  },
  aes: {
    what: 'Encrypts or decrypts text with AES-GCM using a password-derived key (PBKDF2), via the browser\'s native Web Crypto.',
    when: 'You need to quickly encrypt a short secret to paste somewhere else, or decrypt something a colleague sent you that they encrypted the same way.'
  },
  rsa: {
    what: 'Generates an RSA keypair and encrypts or decrypts text with RSA-OAEP, via Web Crypto.',
    when: 'You need a throwaway RSA keypair to test an integration, or need to decrypt a small payload someone encrypted with a public key you hold the private half of.'
  },
  'file-aes': {
    what: 'Encrypts or decrypts an entire file — not just pasted text — with AES-GCM using a password you set.',
    when: "You need to send a sensitive file over an untrusted channel and want to encrypt it client-side first, or you've received an encrypted file and have the password to open it."
  },
  totp: {
    what: 'Generates the current time-based one-time password (RFC 6238) from a shared secret — the same algorithm your authenticator app uses.',
    when: "You're setting up or testing 2FA for your own account or a staging environment and need to generate a code from the secret without reaching for your phone."
  },
  x509: {
    what: 'Parses a PEM or DER certificate and shows its subject, issuer, validity window, and extensions.',
    when: 'You want to check when a certificate expires or who issued it, without running openssl x509 -text on a machine that might not have it installed.'
  },

  // ---------- Section 4: Passwords & Credential Safety ----------
  'password-strength': {
    what: "Estimates a password's entropy and flags common weaknesses — patterns, dictionary words, low character variety.",
    when: "You're choosing a password for something that matters and want a sanity check beyond \"the site's strength meter said good.\""
  },
  hibp: {
    what: 'Checks whether a password appears in the Have I Been Pwned breach corpus, using k-anonymity so only a hash prefix ever leaves your browser.',
    when: "You're about to reuse an old password and want to know if it's already been leaked in a breach before you commit to it."
  },
  'wordlist-demo': {
    what: 'Looks up a hash against a bundled 300-entry list of extremely common passwords — a small educational demo, not a cracking tool.',
    when: 'You want to show yourself, a student, or a team how trivially a hash of password123 reverses via a lookup table, to make the case for better password hygiene.'
  },
  'password-generator': {
    what: 'Generates cryptographically random passwords with a length and character set you configure.',
    when: 'A signup form demands "12+ characters, one symbol, one number" and you want a strong password that satisfies it in one click, instead of typing something you\'ll end up reusing.'
  },
  diceware: {
    what: 'Generates a multi-word passphrase using cryptographically random selection from a wordlist (the Diceware method).',
    when: "You want a passphrase that's actually easy to type and remember — correct-horse-battery-staple-style — but still has real entropy, for something like a disk-encryption password or a password manager master password."
  },

  // ---------- Section 5: Files & Metadata ----------
  exif: {
    what: "Reads an image's EXIF metadata — camera model, timestamp, GPS coordinates if present — and can produce a stripped copy with it removed.",
    when: "You're about to post a photo publicly and want to check whether it's carrying GPS coordinates or other metadata you didn't mean to share, and strip it if so."
  },
  'magic-bytes': {
    what: "Reads a file's leading bytes and identifies its real type, regardless of its file extension.",
    when: 'Someone sends you a file named invoice.pdf and you want to confirm it\'s actually a PDF — and not, say, an executable — before opening it.'
  },
  steganography: {
    what: "Detects and extracts data hidden in an image's least-significant bits, a common beginner steganography technique.",
    when: "You're working a CTF challenge that hands you a suspiciously plain PNG and hints at \"hidden data.\""
  },
  'base64-image': {
    what: 'Pastes a base64 string or data URI and renders it as an image inline.',
    when: "You've got a base64 blob from an API response, or a data:image/... URI in some HTML or CSS, and want to see what it actually is without writing it to a file first."
  },

  // ---------- Section 6: Network & Recon ----------
  cidr: {
    what: 'Breaks down a CIDR block into network address, broadcast address, usable range, and host count (IPv4, with basic IPv6 support).',
    when: "You're planning subnets or reviewing a firewall rule and need to know exactly which addresses 10.0.4.0/22 actually covers."
  },
  'dns-lookup': {
    what: "Queries a public DNS-over-HTTPS resolver (dns.google) for a domain's records.",
    when: "You want to check a domain's A/MX/TXT records — say, verifying an SPF or DKIM record you just set — without opening a terminal."
  },
  'whois-lookup': {
    what: 'Looks up domain registration data via RDAP, the IETF-standardized WHOIS successor.',
    when: 'You want to know who registered a domain and when it expires — for example, while triaging a suspicious link.'
  },
  'ip-geo': {
    what: 'Looks up the approximate geographic location and network owner of an IP address.',
    when: "You're looking at an unfamiliar IP in a server log and want a first-pass read on where it's coming from and who owns the block."
  },
  'http-headers': {
    what: 'Analyzes a set of HTTP response headers — pasted from your browser\'s devtools — and flags missing or weak security headers (CSP, HSTS, X-Frame-Options, and others).',
    when: "You're reviewing your own site's security posture and want to paste in the response headers from the Network tab to see what's missing, without fighting CORS by trying to fetch the page directly."
  },
  'ports-reference': {
    what: 'A searchable reference table of well-known ports and the protocols or services conventionally running on them.',
    when: "You see port 1433 in an nmap scan or a firewall rule and want an instant reminder that it's MSSQL, without switching tabs to search it."
  },

  // ---------- Section 7: Developer Utilities ----------
  'regex-tester': {
    what: 'Tests a regular expression against sample text live, with a library of common patterns to start from.',
    when: "You're writing a validation regex and want to confirm it matches — and doesn't over-match — real examples before it goes into production code."
  },
  'text-diff': {
    what: 'Shows a line-by-line or character-level diff between two blocks of text.',
    when: 'You want to see exactly what changed between two versions of a config file or a piece of output without opening a full diff tool.'
  },
  epoch: {
    what: 'Converts between Unix epoch time and human-readable date/time, in either direction.',
    when: "You're reading a log line with a raw epoch timestamp and need to know what time that actually was."
  },
  'qr-code': {
    what: 'Generates a QR code from text, or decodes an existing QR code image back to text.',
    when: 'You need a quick QR code for a URL or Wi-Fi credential to hand someone, or you want to check what a QR code actually points to before scanning it with your phone.'
  },
  'json-formatter': {
    what: 'Pretty-prints, validates, and reformats JSON, XML, or YAML.',
    when: "You've got a minified API response or a hand-edited config file and want it validated and readably indented before you try to debug it."
  },
  homoglyph: {
    what: 'Scans text for visually-confusable characters — Cyrillic "а" versus Latin "a," for example — and flags exactly where they appear.',
    when: "A domain name or username looks almost right but something feels off; this pinpoints exactly which character has been swapped for a lookalike."
  },
  'phishing-checker': {
    what: 'Runs a URL through a set of client-side heuristics — subdomain depth, keyword stuffing, hyphens, IP-literal hosts, punycode — and flags suspicious signals.',
    when: "You've got a link from an unsolicited email or text and want a quick second opinion on how suspicious it looks before deciding whether to click it."
  },

  // ---------- Section 8: Pentest & CTF Reference ----------
  'reverse-shell': {
    what: 'Generates a reverse shell one-liner for your chosen shell or language — bash, nc, python, perl, php, ruby, powershell, socat, and others — paired with the matching listener command.',
    when: "You've got authorized access to a box in a CTF or a pentest engagement and need the right one-liner and listener syntax for whatever shell is actually available on the target, without hunting through five browser tabs."
  },
  'injection-cheatsheet': {
    what: 'A static reference of common injection payload patterns — SQLi, XSS, LFI/RFI, command injection, SSTI.',
    when: "You're testing your own application or an authorized engagement or CTF target for injection flaws and want the standard proof-of-concept payloads on hand, the same way you'd reach for PortSwigger's or OWASP's cheat sheets."
  },
  'privesc-checklist': {
    what: 'A checklist of Linux and Windows enumeration commands — SUID binaries, sudo rights, kernel version, scheduled tasks — plus links to public references like GTFOBins.',
    when: "You've got an authorized low-privilege foothold on a box, in a CTF or a pentest lab, and need the standard enumeration steps to work toward escalation without re-Googling the same commands every time."
  }
};

/** Short "what it does" line for section-landing cards. Falls back to '' if unknown. */
export function whatItDoes(toolId) {
  return TOOL_COPY[toolId] ? TOOL_COPY[toolId].what : '';
}
