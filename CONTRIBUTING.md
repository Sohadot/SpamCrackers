# Contributing

SpamCrackers is a deterministic reference asset. Changes are welcome, but they must preserve its two guarantees: it stays **defensive-only**, and its identifiers stay **stable**.

## Before you push

Run the quality gate and make sure it passes:

```sh
node scripts/verify.js
```

CI runs the same gate on every push and pull request (`.github/workflows/verify.yml`); a red gate cannot merge. The gate checks structure, security headers (meta CSP), accessibility invariants, JSON-LD, the internal-link graph, sitemap, feed, and `model.json` conformance.

## Governance rules

**1. Identifiers are permanent.** Never reuse or renumber a published id (`SPM-…`, `PHI-…`, etc.). If a technique is superseded, mark it deprecated — do not delete it. New techniques take the next free number within their phase.

**2. The model is versioned with SemVer** (`MAJOR.MINOR.PATCH`):
- **MAJOR** — a breaking change to structure or the identifier scheme.
- **MINOR** — additive: a new pillar, phase, technique, or taxonomy class.
- **PATCH** — clarifications and wording; no id changes.

Record every release in the [governance changelog](https://spamcrackers.com/intelligence/governance/).

**3. `model.json` is generated, not hand-edited.** It is derived deterministically from the built pillar pages, so the data can never drift from the pages. If you change a technique's text on a pillar page, regenerate the JSON and confirm `verify.js` still passes.

**4. Defensive scope is absolute.** No version, patch or contribution may add operational attack content — no payloads, kits, step-by-step methods for conducting abuse, or directories of targets. Every entry stays at the level of *classification and defence*: what it is, how it is observed, how it is countered.

## Style

- Reuse the existing design tokens and components; keep both light and dark themes working and WCAG AA contrast intact.
- Every page ships the shared meta CSP, a canonical URL, a single `h1`, breadcrumbs, JSON-LD with the canonical Organization entity, and the feed `rel="alternate"` link.
- Keep the internal-link graph intact — `verify.js` will fail on any broken link or anchor.
