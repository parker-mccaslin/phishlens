# PhishLens

PhishLens is a local-first Debian/Ubuntu tool for reviewing suspicious messages. Version 0.2 uses independent, deterministic indicators; AI does not decide whether a message is a scam. Analysis and history stay on this computer. The Gemini key is only used for the optional setup connection check.

## Run on Ubuntu

```bash
./scripts/install.sh
./scripts/run.sh
```

Open http://127.0.0.1:8000. The installer uses `sudo` only when it needs to install missing system packages with apt. Node.js is needed for the frontend build, not when running PhishLens. A modern Node/npm installation is expected for development; install it separately if absent.

For development, activate `.venv`, install `requirements.txt`, run `npm --prefix frontend install`, then `npm --prefix frontend run build`. Start the server with `uvicorn backend.main:app --host 127.0.0.1 --port 8000`.

Run checks with `.venv/bin/pytest` and `npm --prefix frontend run build`.

## Privacy and storage

The server binds to loopback only. It does not fetch analyzed URLs. Analysis text and local history are stored in SQLite at `~/.local/share/phishlens/history.sqlite3`; history can be cleared in Settings. Configuration is stored in `~/.config/phishlens/config.toml` with directory mode 0700 and file mode 0600. `GEMINI_API_KEY` (or `PHISHLENS_API_KEY`) overrides the configured key. Keys are never returned by the API; only a masked status is exposed.

Domain registration age checks are off by default and can be enabled in Settings. When enabled, PhishLens reads IANA’s RDAP DNS bootstrap registry to find each suffix’s authoritative service, then sends up to five extracted registered domain names per message to those registry services. IANA’s bootstrap request itself contains no analyzed domain. No message text or URL paths are sent, and analyzed links are never opened. The registry maps suffixes to RDAP servers, and RDAP domain queries retrieve registration events ([IANA bootstrap registry](https://www.iana.org/assignments/rdap-dns), [RFC 9224](https://datatracker.ietf.org/doc/html/rfc9224), [RFC 9082](https://datatracker.ietf.org/doc/html/rfc9082), [RFC 9083](https://datatracker.ietf.org/doc/html/rfc9083)). PhishLens treats a registration date 30 days old or newer as a caution signal. Missing or unavailable dates are reported as unknown and do not affect the score. Registry data can be incomplete or vary by registry.

Domain reputation checks are a separate opt-in setting and use the Spamhaus Domain Blocklist (DBL) through the computer’s configured DNS resolver. The queried domain is visible to that resolver and Spamhaus; message text and URL paths are not sent. DBL identifies domains associated with phishing, spam, malware, and other abuse, and its response codes distinguish abuse categories ([Spamhaus DBL](https://www.spamhaus.org/faqs/domain-blocklist/)). Spamhaus’ free DNS query service is subject to eligibility and fair-use terms; eligible individual users may need to create an account and keep contact details current ([terms](https://www.spamhaus.com/terms-of-use-fair-use-policy-for-free-data-query-service/)). Public resolvers or networks that block or anonymize these queries can make results unavailable. PhishLens reports such cases as unknown; an unknown result does not affect the score.

The optional Gemini connection check sends a short fixed test prompt and does not send analyzed content. If you use Gemini in a future version, what Google does with submitted data depends on whether you use unpaid or paid services. Read [Google's current Gemini API terms](https://ai.google.dev/gemini-api/terms) before using it with sensitive information.

## What v0.2 detects

Message indicators look for urgency, account threats, credential or payment requests, and nine scam patterns: fake invoices, delivery notices, password resets, bank impersonation, job scams, prize scams, tech support, government impersonation, and crypto scams. URL checks inspect domains and paths for registered-domain structure, HTTPS, URL shorteners, IP hosts, punycode or non-ASCII names, excessive subdomains, suspicious path words, and supported brand mismatches. Analyzed links are never opened.

The score adds documented weights once per distinct indicator. Confidence reflects the number of distinct positive indicators that agree; it is not a probability. With no positive indicators the result is “Unable to determine,” not a safety verdict. HTTPS does not mean a site is legitimate. Indicators are heuristic and can miss scams or flag legitimate messages.

Domain-age and reputation checks use the separate optional providers described above. Both settings default off, so the default analysis performs no external lookup. Registered-domain parsing recognizes a limited set of common multi-label suffixes. Ambiguous structures return “unknown” rather than an assumed registrable domain. Brand mismatch checks cover only the explicit brand/domain mapping in the source.

## Structure

- `backend/`: FastAPI app, local config/history
- `analyzers/`: independent deterministic indicators
- `risk/`: score and outcome mapping
- `ai/`: reserved stubs for v0.3 (not used for analysis)
- `privacy/`: reserved stub for v0.4
- `frontend/`: React + Vite single-page interface
- `examples/`: sample messages
- `tests/`: offline unit/API tests

No accuracy claims are made. Later roadmap modules are intentionally stubs.
