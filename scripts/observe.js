#!/usr/bin/env node
/*
 * SpamCrackers Observatory — server-side measurement.
 * Grades the canonical domain set (observatory/domains.json) against the
 * SpamCrackers Standard over public DNS (DoH), writing a dated, machine-
 * readable record: observatory/latest.json + observatory/history/<date>.json.
 *
 * The rubric is identical to the site's fast pass: SPF (25/18/10) +
 * DMARC (25 reject / 20 quarantine / 10 record-only) + MX (25), normalised
 * to 100 over a 75-point max. DKIM is intentionally excluded (selector
 * discovery is not reliable from DNS alone) — the same honest caveat the
 * Standard states. Rubric and DNS classification live in observatory-core.js.
 *
 * Integrity rules:
 *  - A query that is not answered (HTTP error, timeout, SERVFAIL/REFUSED,
 *    truncated or malformed response) fails that domain; it is never scored
 *    as an absent record. Any failed domain aborts the whole run.
 *  - Each domain entry carries the evidence its score was computed from
 *    (measurement time, resolver, query name/type, RCODE, relevant records).
 *  - Nothing is written unless every domain was measured and the complete
 *    record passes auditRecord(); outputs are staged to temp files and only
 *    renamed into place once all of them were staged successfully.
 *
 * Usage:  node scripts/observe.js
 */
"use strict";
const fs = require("fs");
const path = require("path");
const core = require("./observatory-core");

const DEFAULT_ROOT = path.resolve(__dirname, "..");

function stageAndCommit(files) {
  const staged = [];
  try {
    for (const [dest, body] of files) {
      const tmp = dest + ".tmp-" + process.pid;
      fs.writeFileSync(tmp, body);
      staged.push([tmp, dest]);
    }
  } catch (e) {
    for (const [tmp] of staged) { try { fs.unlinkSync(tmp); } catch { /* ignore */ } }
    throw e;
  }
  let i = 0;
  try { for (; i < staged.length; i++) fs.renameSync(staged[i][0], staged[i][1]); }
  catch (e) {
    for (const [tmp] of staged.slice(i)) { try { fs.unlinkSync(tmp); } catch { /* ignore */ } }
    throw e;
  }
}

async function run(opts = {}) {
  const ROOT = opts.root || DEFAULT_ROOT;
  const OBS = path.join(ROOT, "observatory");
  const HIST = path.join(OBS, "history");
  const out = opts.log || ((s) => process.stdout.write(s));
  const clock = opts.clock || (() => new Date());

  const cfg = JSON.parse(fs.readFileSync(path.join(OBS, "domains.json"), "utf8"));
  const list = [];
  for (const cat of cfg.categories) for (const d of cat.domains) list.push({ domain: d, category: cat.name });
  // read (and fail on) the catalog before measuring, so a bad catalog cannot
  // surface only after latest.json/history were already replaced
  const catPath = path.join(ROOT, "catalog.json");
  const cat = JSON.parse(fs.readFileSync(catPath, "utf8"));

  // previous snapshot for deltas
  let prev = null;
  try { prev = JSON.parse(fs.readFileSync(path.join(OBS, "latest.json"), "utf8")); } catch { /* first run */ }
  const prevScore = {};
  if (prev && Array.isArray(prev.domains)) for (const p of prev.domains) prevScore[p.domain] = p.score;

  const now = clock();
  const measuredDate = now.toISOString().slice(0, 10);

  const domains = [];
  const failed = [];
  for (const item of list) {
    try {
      const m = await core.measure(item.domain, { transport: opts.transport, retryDelayMs: opts.retryDelayMs, clock });
      const ps = item.domain in prevScore ? prevScore[item.domain] : null;
      domains.push({ domain: item.domain, category: item.category, score: m.score, grade: m.grade,
        dmarc: m.dmarc, spf: m.spf, mx: m.mx, prevScore: ps, delta: ps == null ? null : m.score - ps,
        evidence: m.evidence });
      out(`  ${item.domain.padEnd(18)} ${m.grade.padEnd(2)} ${String(m.score).padStart(3)}  DMARC ${m.dmarc}\n`);
    } catch (e) {
      failed.push({ domain: item.domain, kind: e.kind || "error", message: e.message });
      out(`  ${item.domain.padEnd(18)} ERROR [${e.kind || "error"}] ${e.message}\n`);
    }
  }

  if (failed.length) {
    out(`\nAborting: ${failed.length} domain(s) failed to measure — not writing a partial record. Existing files left unchanged.\n`);
    return { ok: false, failed, wrote: [] };
  }

  const counts = {
    domains: domains.length,
    armored: domains.filter((d) => d.score >= 85).length,
    dmarcReject: domains.filter((d) => d.dmarc === "reject").length,
    exposed: domains.filter((d) => d.score < 50).length,
  };

  const latest = {
    standard: "SpamCrackers Standard v1.0",
    method: "SPF + DMARC + MX over public DNS (DNS-over-HTTPS). DKIM is not included in the index grade.",
    license: "CC-BY-4.0",
    url: "https://spamcrackers.com/observatory/",
    generated: now.toISOString(),
    measuredDate,
    previous: prev ? prev.measuredDate || null : null,
    counts,
    domains,
  };

  const audit = core.auditRecord(latest, list.map((x) => x.domain));
  if (audit.length) {
    out(`\nAborting: assembled record failed its audit — nothing written.\n` + audit.map((m) => "  ✗ " + m + "\n").join(""));
    return { ok: false, failed: audit.map((m) => ({ domain: null, kind: "audit", message: m })), wrote: [] };
  }

  // compact daily archive (format unchanged; idempotent per day)
  const snap = { measuredDate, generated: now.toISOString(), counts,
    scores: Object.fromEntries(domains.map((d) => [d.domain, { score: d.score, grade: d.grade, dmarc: d.dmarc }])) };

  // rename order matters: history, then catalog, then latest.json last, so
  // latest.json is the commit point (see core.auditPublication)
  const files = [[path.join(HIST, measuredDate + ".json"), JSON.stringify(snap, null, 2) + "\n"]];
  // keep the citable catalog in sync: its observatory version tracks the
  // measuredDate, which verify.js enforces field-for-field.
  const obs = cat.datasets.find((d) => d.id === "observatory");
  if (obs && (obs.version !== measuredDate || cat.generated !== measuredDate)) {
    obs.version = measuredDate;
    cat.generated = measuredDate;
    files.push([catPath, JSON.stringify(cat, null, 2) + "\n"]);
  }
  files.push([path.join(OBS, "latest.json"), JSON.stringify(latest, null, 2) + "\n"]);

  fs.mkdirSync(HIST, { recursive: true });
  stageAndCommit(files);
  if (files.some(([p]) => p === catPath)) out(`synced catalog.json observatory version -> ${measuredDate}\n`);
  out(`\nmeasured ${domains.length} domains — armored ${counts.armored}, DMARC reject ${counts.dmarcReject}, exposed ${counts.exposed}\n`);
  out(`wrote observatory/latest.json + observatory/history/${measuredDate}.json\n`);
  return { ok: true, failed: [], wrote: files.map(([p]) => path.relative(ROOT, p)) };
}

module.exports = { run };

if (require.main === module) {
  run().then((r) => process.exit(r.ok ? 0 : 1), (e) => { console.error("observe failed:", e); process.exit(1); });
}
