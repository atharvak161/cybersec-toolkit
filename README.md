# cybersec-toolkit

**Live demo: https://atharvak161.github.io/cybersec-toolkit/**

A static, client-side-only cybersecurity utility toolkit. Plain HTML/CSS/JS,
no build step, no framework, no bundler — open `index.html` (or serve the
directory) and it runs. Nothing you type is ever sent to a server, except
nine explicitly-disclosed tools that call a public read-only API (each is
marked with a 🌐 badge in the UI and listed below).

## Purpose & Ethical Use

This toolkit exists for **education, learning, and legitimate security work**:
CTF practice, verifying file integrity, inspecting your own JWTs/certificates,
generating and testing your own passwords, understanding common attacker
techniques (phishing heuristics, hash identification, steganography) well
enough to defend against them, and general-purpose encoding/hashing/crypto
utilities that any engineer or student runs into regularly.

It is **not** intended for, and must not be used for:
- Unauthorized access to systems, accounts, or data you do not own or have
  explicit permission to test.
- Harassment, stalking, or looking up information about a person without
  their consent or a legitimate authorized context.
- Real password cracking against production systems — the "common-password
  hash lookup" tool is a 300-entry **educational demo**, clearly labeled as
  such, not a real cracking tool (no large wordlists are bundled).
- Actively scanning, enumerating, or probing third-party systems. The
  OSINT/lookup tools (WHOIS, DNS, IP geolocation, phishing checker, and
  the SPF/DKIM/DMARC/BIMI/Domain Health email-authentication lookups)
  only query public, read-only data sources (a public DNS resolver, the
  IETF's RDAP registry protocol, a public IP-geolocation API) or run pure
  client-side heuristics — none of them perform active scanning or
  enumeration of a target system. A DKIM or BIMI lookup does require a
  selector (the tool defaults to the common "default" selector) but is
  still a single passive DNS TXT read, not enumeration.

The three v3 **Pentest & CTF Reference** tools — Reverse Shell Generator,
Injection Payload Cheatsheet, and Privilege Escalation Enumeration
Checklist — extend the same rule: they are **reference and generator
tools only**, intended strictly for **authorized penetration testing
engagements and CTF/lab contexts**. Same category of tool as revshells.com,
PayloadsAllTheThings, or GTFOBins — not a substitute for having explicit
permission to test the target you're pointing them at. None of the three
makes a network call or executes anything: the Reverse Shell Generator
only prints a payload/listener command pair as text (it never opens a
connection or spawns a process), and the Injection Cheatsheet and
Privilege Escalation Checklist are static, client-side reference data —
you still have to run every command yourself, on a system you're
authorized to be on.

If you're unsure whether a use case is appropriate, don't do it.

## What's client-side vs. external

Everything in this toolkit runs entirely in your browser. The **only**
exceptions — each shown with a 🌐 "calls an external API" badge in the UI —
are:

| Tool | External call | What's sent |
|---|---|---|
| HIBP Breach Check | `api.pwnedpasswords.com` (k-anonymity range API) | Only the first 5 hex characters of the SHA-1 hash of your password — never the password or full hash |
| DNS Lookup | `dns.google` (Google Public DNS-over-HTTPS JSON API) | The domain name and record type you enter |
| WHOIS Lookup | `rdap.org` (RDAP — the IETF/IANA-standardized WHOIS successor) | The domain name you enter |
| IP Geolocation | `ipapi.co` | The IP address you enter |
| SPF Lookup | `dns.google` (same DoH API as DNS Lookup) | The domain name you enter |
| DKIM Lookup | `dns.google` (same DoH API as DNS Lookup) | The domain name and selector you enter |
| DMARC Lookup | `dns.google` (same DoH API as DNS Lookup) | The domain name you enter |
| BIMI Lookup | `dns.google` (same DoH API as DNS Lookup) | The domain name and selector you enter (also runs a DMARC lookup as a cross-check) |
| Domain Health Lookup | `dns.google` (same DoH API as DNS Lookup) | The domain name you enter (runs the DMARC, SPF, and BIMI lookups above in one pass) |

All nine are free, public, no-API-key-required endpoints — no secret is
baked into the client code (there's nothing to steal), and no user data is
compiled or logged by this toolkit itself. The five email-authentication
lookups reuse the exact same `dns.google` DNS-over-HTTPS plumbing as DNS
Lookup — no new external host was introduced to build them.

## Architecture

- No build step. `index.html` loads `js/app.js` as an ES module; everything
  else is plain ES modules imported from there.
- **v4 navigation (10 sections):** the sidebar is a pinned Recipe Builder
  entry point plus 9 collapsible category groups — Encoding & Ciphers,
  Hashing & Integrity, Cryptography, Passwords & Credential Safety, Files
  & Metadata, Network & Recon, Email Authentication, Developer Utilities,
  and Pentest & CTF Reference (10 sections total, 58 tools). Each category has its own
  section landing page (an intro blurb plus a card grid of its tools),
  collapsible/expandable group state persisted to `localStorage`, and a
  quick-search box (press `/`) that filters across all tools by name. The
  URL hash is the single source of truth for navigation, so direct links,
  and browser back/forward, both work correctly.
- All pure logic (encode/decode/hash/crypto/parsing functions) lives in
  `js/lib/*.js`, independent of the DOM, so it can be — and is — unit
  tested directly with Node (see `test/run-tests.js`).
  `js/ui/*.js` contains the (thin) DOM-wiring layer per tool category.
- Any cryptography that Web Crypto supports (AES-GCM, RSA-OAEP, HMAC,
  SHA-1/256/384/512) uses the browser-native `crypto.subtle` API —
  never a hand-rolled implementation. See `js/lib/aes.js`, `js/lib/rsa.js`,
  `js/lib/hashing.js`.

### Why hand-written instead of vendored, for MD5/SHA-3/CRC32/Punycode/QR

The original plan (per the brief) was to vendor small, pinned-version,
well-known third-party implementations for the handful of hash algorithms
Web Crypto doesn't support (MD5, SHA-3, CRC32), plus Punycode and a QR
encode/decode library. While building this, the build environment's safety
tooling declined to execute code fetched from a CDN by the agent (a
code-provenance safety gate on running agent-downloaded third-party code) —
so rather than ship un-vetted vendor files that were never actually
exercised, every one of these was **hand-written directly from the public
specification**:

- `js/lib/vendor/md5.js` — RFC 1321
- `js/lib/vendor/sha3.js` — FIPS 202 (Keccak-*f*[1600])
- `js/lib/vendor/crc32.js` — the standard reflected CRC-32/ISO-HDLC algorithm
- `js/lib/vendor/punycode.js` — RFC 3492 (Bootstring)
- `js/lib/qr-encode.js` / `js/lib/qr-decode.js` — ISO/IEC 18004 (QR Code)

Each cites its source specification in a header comment, and each is
validated against the relevant standard's own published test vectors in
`test/run-tests.js` (RFC 1321 vectors for MD5, NIST FIPS 202 vectors for
SHA-3, the canonical CRC-32/ISO-HDLC check value, the RFC 3492 sample
strings for Punycode). None of these are security-critical primitives —
MD5/CRC32 are used only as legacy/checksum digests, never for anything
that needs to resist attack; anything that does (AES, RSA, HMAC) uses
Web Crypto, full stop.

**QR code scope note:** the hand-written QR encoder/decoder supports byte
mode, versions 1-4, and error-correction levels L/M — **with one exception:
Version 4 / Level M is not supported.** Per ISO/IEC 18004, V4/M is the one
combo in this range that requires 2 interleaved Reed-Solomon blocks rather
than a single block; every other version/level combo this encoder handles
(V1-4 at L, V1-3 at M) is a genuine single RS block. An earlier build
incorrectly treated V4/M as a single block, which produced spec-invalid
codes that this project's own round-trip test didn't catch (it just reads
back whatever bytes were written) but which failed to scan entirely against
an independent scanner (verified with `zbarimg`/pyzbar — 20/20 test strings
in the affected byte range failed to decode). Rather than implement real
multi-block RS interleaving (a bigger feature, not worth the risk), V4/M is
simply excluded: if you request Level M with an input long enough to need
it (roughly 43-62 bytes), the encoder transparently falls back to Level L
instead (and reports the level it actually used); if the input doesn't fit
at any supported version/level combo at all (beyond ~78 bytes), it throws a
clear "input too large for supported QR levels, try a shorter string or
Level L" error rather than silently producing a broken code. Effective byte
capacity: V1-L=17, V1-M=14, V2-L=32, V2-M=26, V3-L=53, V3-M=42, V4-L=78 (no
V4-M). The decoder reads back this project's own generated matrices (and
clean, axis-aligned scans) correctly — verified by round-trip tests and a
live browser check — but it is not a full perspective-correcting photo
scanner the way a production QR library is.

## Tool list

### v1

| Tool | Status |
|---|---|
| Hex encode/decode | Working |
| Base64 encode/decode | Working |
| Base32 encode/decode | Working |
| Base58 encode/decode | Working |
| URL encode/decode | Working |
| Binary encode/decode | Working |
| ROT13 / Caesar cipher | Working |
| Classical Cipher Cracker (Caesar/Atbash/Vigenère/XOR/rail-fence, auto-ranked) | Working |
| Enigma Machine (settings-based simulator) | Working |
| MD5 / SHA-1 / SHA-256 / SHA-512 / SHA-3-256 / CRC32 (Hash Generator) | Working |
| HMAC generator (HS1/256/384/512) | Working |
| Hash-type identifier | Working (heuristic — many algorithms share output lengths) |
| File hash checker (drag a file, get its hashes) | Working |
| JWT decoder/inspector (flags `alg:none`, expiry, optional HMAC verify) | Working |
| AES-GCM encrypt/decrypt (Web Crypto, PBKDF2-derived key) | Working |
| RSA keypair generation + encrypt/decrypt (Web Crypto, RSA-OAEP) | Working |
| Recipe chaining (CyberChef-lite, drag-to-reorder, live output) | Working — the standout feature |
| Password strength / entropy analyzer | Working |
| HIBP breach check (k-anonymity, external API, disclosed) | Working |
| EXIF metadata viewer/stripper | Working |
| CIDR/subnet calculator (IPv4 + basic IPv6) | Working |
| Regex tester + common-pattern library | Working |
| QR code generate + decode | Working (scoped to versions 1-4, levels L/M except V4/M, which is unsupported and falls back to Level L — see above) |

### v2 (additive, same app)

| Tool | Status |
|---|---|
| Steganography LSB detect/extract (images) | Working — educational, labeled as such |
| Recipe export/import (URL param / JSON) | Working |
| X.509 certificate/PEM decoder | Working (hand-written ASN.1/DER TLV parser; cross-validated against Node's built-in `X509Certificate` on a locally-generated test cert) |
| Common-password hash-lookup demo (300-entry, capped) | Working — clearly labeled educational, not a cracking tool |
| WHOIS lookup (RDAP, external API, disclosed) | Working (shows a friendly "No WHOIS record found for this domain." message for unregistered domains instead of a raw JSON-parse error) |
| DNS lookup (dns.google, external API, disclosed) | Working |
| Phishing URL heuristic checker | Working (pure client-side heuristics; note: the lookalike-domain check uses a naive "last two labels" registrable-domain guess, which can miss domains under multi-part public suffixes like `.co.uk` or when a lookalike brand name is used as a *subdomain* rather than the registrable domain — the other heuristics, e.g. subdomain depth/keywords/hyphens/IP-literal/punycode, still catch most such cases) |
| File type / magic-byte identifier | Working |
| Base85 (Ascii85), Base91, UUEncode | Working |
| Punycode / IDN encode-decode | Working (hand-written, see above) |
| Epoch/timestamp converter | Working |
| IP geolocation lookup (ipapi.co, external API, disclosed) | Working |
| Text diff tool | Working |

### v3 (additive, same app — 13 new tools, plus the 9-section nav reorg above)

| Tool | Status |
|---|---|
| Morse Code encode/decode | Working |
| TOTP / 2FA Code Generator (RFC 6238, from a shared secret) | Working |
| Password Generator (configurable length/character set, cryptographically random) | Working |
| Diceware Passphrase Generator (wordlist-based, cryptographically random) | Working |
| File Encryption/Decryption (AES-GCM, whole file, password-derived key via Web Crypto) | Working |
| HTTP Security Headers Checker (paste headers from devtools; flags missing/weak CSP, HSTS, X-Frame-Options, etc.) | Working (paste-based by design — avoids a CORS-blocked live fetch) |
| Homoglyph / Lookalike Detector (flags visually-confusable characters, e.g. Cyrillic vs. Latin) | Working |
| JSON/XML/YAML Formatter (pretty-print, validate, reformat) | Working |
| Base64 Image Previewer (paste a base64 string or data URI, render inline) | Working |
| Well-Known Ports Reference (searchable port/protocol/service table) | Working |
| Reverse Shell Generator — *Pentest & CTF Reference* (payload + matching listener, multiple shells/languages) | Working — text generation only, no network call or execution; see [Purpose & Ethical Use](#purpose--ethical-use) |
| Injection Payload Cheatsheet — *Pentest & CTF Reference* (SQLi, XSS, LFI/RFI, command injection, SSTI patterns) | Working — static reference only |
| Privilege Escalation Enumeration Checklist — *Pentest & CTF Reference* (Linux/Windows enumeration steps + GTFOBins/LOLBAS links) | Working — static reference only |

### v4 (additive, same app — 7 new tools: Email Authentication, a new 10th section)

| Tool | Status |
|---|---|
| SPF Lookup (dns.google, external API, disclosed) | Working — counts DNS-lookup mechanisms against the RFC 7208 limit of 10 and warns if exceeded |
| DKIM Lookup (dns.google, external API, disclosed) | Working — domain + selector, flags a missing or revoked (empty `p=`) key |
| DMARC Lookup (dns.google, external API, disclosed) | Working — explains the policy in plain English, warns on `p=none` or no record |
| BIMI Lookup (dns.google, external API, disclosed) | Working — cross-checks that DMARC is at enforcement (quarantine/reject), which most mailbox providers require to display the logo |
| DMARC Record Generator | Working — pure, no network call; validates `rua`/`ruf` as `mailto:` URIs, `pct` range, and `fo` syntax before emitting the record |
| Domain Health Lookup (dns.google, external API, disclosed) | Working — runs the DMARC + SPF + BIMI lookups above for one domain and shows a pass/warn/fail summary; reuses their parsing logic rather than duplicating it |
| Email Header Analyzer | Working — pure text parsing, no network; orders `Received:` hops into a delivery-path timeline (flagging >5-minute gaps) and surfaces SPF/DKIM/DMARC verdicts from `Authentication-Results`/`Received-SPF`/`DKIM-Signature`/ARC headers. Distinct from the v3 HTTP Security Headers Checker, which analyzes web response headers, not email headers |

## Running the tests

```
npm test
# or
node --test test/run-tests.js
```

`test/run-tests.js` uses only Node's built-in `node:test` + `node:assert` —
no external test framework. It checks every pure logic module against
known/published test vectors (RFC 1321 MD5 vectors, NIST SHA test vectors,
RFC 4648 Base64/32 vectors, the IETF Base58 draft's vectors, the RFC 3492
Punycode sample, AES/RSA encrypt-then-decrypt round trips via Node's own
Web Crypto implementation, a real self-signed certificate generated with
`openssl` and cross-checked against Node's built-in `X509Certificate`, and
more).

`test/manual-sanity-check.js` is a separate, human-readable script that
exercises the recipe chain and several other tools end-to-end and prints
before/after output for eyeballing.

## Deployment

Not part of this build phase. This is a static site with no server-side
requirements — deploying it (GitHub Pages or any static host) is a
separate, later step.
