# SpamCrackers

**The reference layer for Email Abuse Intelligence, and a transparent standard for email authentication.**

[![verify](https://github.com/Sohadot/SpamCrackers/actions/workflows/verify.yml/badge.svg)](https://github.com/Sohadot/SpamCrackers/actions/workflows/verify.yml)

Live: **[spamcrackers.com](https://spamcrackers.com/)**

SpamCrackers is a static, privacy-first site with two halves that reinforce each other:

1. **A tool** — grade any domain's email authentication (SPF, DKIM, DMARC, MX) live in the browser, against the transparent **SpamCrackers Standard** (A+ to F). No server, no storage, no tracking.
2. **A reference** — the **Email Abuse Intelligence Reference Model**: a defensive, analytical classification of how email abuse works, across six pillars and 163 techniques, each with a stable identifier.

The loop is the point: **Tool → Diagnosis → Reference → Remediation → Recheck.**

## Site map

| Path | What it is |
| --- | --- |
| `/` | The domain-check tool, the Standard section, the live registry, FAQ, waitlist |
| `/standard/` | The SpamCrackers Standard for Email Authentication (canonical, citable) |
| `/observatory/` | Live index of how well-known domains score against the Standard |
| `/playbook/` | Step-by-step remediation for SPF, DKIM, DMARC and MX (HowTo) |
| `/glossary/` | 40 cross-linked email-abuse and authentication terms |
| `/intelligence/` | The umbrella: six pillars of the reference model |
| `/intelligence/{phishing,bec,mal,scam,spoofing}/` | The individual pillars |
| `/intelligence/techniques/` | Searchable index of all 163 techniques |
| `/intelligence/patterns/` | Patterns Library — campaign archetypes composed from the techniques (+ `patterns.json`) |
| `/intelligence/governance/` | Identifier scheme, versioning, changelog, citation, licensing |
| `/intelligence/model.json` | The complete model as machine-readable JSON (+ `model.schema.json`) |

## The reference model

Email Abuse Intelligence Reference Model **v1.0** — six active pillars, all defensive and classification-level (no operational content):

| Code | Pillar | Techniques |
| --- | --- | ---: |
| `SPM` | Spam Campaign Intelligence | 28 |
| `PHI` | Phishing Intelligence | 30 |
| `BEC` | Business Email Compromise | 27 |
| `MAL` | Malware Delivery | 29 |
| `SCM` | Scam & Fraud | 25 |
| `SPO` | Spoofing & Impersonation | 24 |
| | **Total** | **163** |

Every element carries a stable identifier in the `EAI` namespace (e.g. `SPO-AU-03`). The model is published as JSON under **CC BY 4.0** and is machine-verifiable against `intelligence/model.schema.json`.

## Quality gate

All checks are consolidated into one deterministic script:

```sh
node scripts/verify.js
```

It verifies, per page and site-wide: document metadata, a single `h1`, a Content-Security-Policy meta, no duplicate ids, balanced markup, inline-JS syntax, JSON-LD (required fields, a consistent Organization entity, resolvable breadcrumb and DefinedTerm URLs), the internal-link graph (zero broken), sitemap and feed integrity, and `model.json` conformance to its schema. It exits non-zero on any failure and runs in CI on every push and pull request (`.github/workflows/verify.yml`).

## Principles

- **Static & private** — no server-side code, no accounts, no tracking. Domain checks run in-browser over DNS-over-HTTPS.
- **Defensive by definition** — the model classifies and defends; it never provides operational attack content. See [governance](https://spamcrackers.com/intelligence/governance/).
- **Deterministic** — the same input always maps to the same identifier and grade; the rubric is public.
- **Accessible** — WCAG AA contrast, reduced-motion aware, keyboard-focus states, both light and dark themes.

## Citation & license

The reference model content (taxonomy, technique descriptions, identifiers) is licensed **CC BY 4.0**. To cite the work, use [`CITATION.cff`](./CITATION.cff) or:

> SpamCrackers. *Email Abuse Intelligence — Reference Model v1.0*. https://spamcrackers.com/intelligence/

Contributions and change rules: see [`CONTRIBUTING.md`](./CONTRIBUTING.md). Security posture: see [`SECURITY.md`](./SECURITY.md).
