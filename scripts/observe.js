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
 * Standard states.
 *
 * Deterministic and side-effect-free apart from the two output files.
 * Usage:  node scripts/observe.js
 */
"use strict";
const fs = require("fs");
const path = require("path");
const https = require("https");

const ROOT = path.resolve(__dirname, "..");
const OBS = path.join(ROOT, "observatory");
const HIST = path.join(OBS, "history");

function doh(name, type, tries = 3) {
  return new Promise((resolve, reject) => {
    const attempt = (n) => {
      const req = https.get(
        "https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=" + type,
        { headers: { accept: "application/dns-json" }, timeout: 8000 },
        (r) => {
          let d = "";
          r.on("data", (c) => (d += c));
          r.on("end", () => { try { resolve(JSON.parse(d)); } catch (e) { n > 1 ? attempt(n - 1) : reject(e); } });
        }
      );
      req.on("timeout", () => { req.destroy(); n > 1 ? attempt(n - 1) : reject(new Error("timeout")); });
      req.on("error", (e) => { n > 1 ? attempt(n - 1) : reject(e); });
    };
    attempt(tries);
  });
}
const txt = (j) =>
  !j || !j.Answer ? [] : j.Answer.filter((a) => a.type === 16).map((a) => String(a.data).replace(/^"|"$/g, "").replace(/" +"/g, ""));

function grade(score) {
  if (score >= 95) return "A+";
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  if (score >= 30) return "D";
  return "F";
}

async function measure(domain) {
  const [a, b, c] = await Promise.all([
    doh(domain, "TXT"),
    doh("_dmarc." + domain, "TXT").catch(() => ({})),
    doh(domain, "MX").catch(() => ({})),
  ]);
  const spf = txt(a).find((t) => /^v=spf1/i.test(t));
  const dmarcRec = txt(b).find((t) => /v=DMARC1/i.test(t));
  const mxCount = c && c.Answer ? c.Answer.filter((x) => x.type === 15).length : 0;

  let s = 0, spfQual = "none", dmarc = "none";
  if (spf) { spfQual = spf.indexOf("-all") > -1 ? "-all" : (spf.indexOf("~all") > -1 ? "~all" : "soft"); s += spfQual === "-all" ? 25 : (spfQual === "~all" ? 18 : 10); }
  if (dmarcRec) { dmarc = ((dmarcRec.match(/p=([a-z]+)/i) || [])[1] || "none").toLowerCase(); s += dmarc === "reject" ? 25 : (dmarc === "quarantine" ? 20 : 10); }
  if (mxCount) s += 25;

  const score = Math.round((s / 75) * 100);
  return { score, grade: grade(score), dmarc, spf: spf ? spfQual : "none", mx: mxCount > 0 };
}

async function main() {
  const cfg = JSON.parse(fs.readFileSync(path.join(OBS, "domains.json"), "utf8"));
  const list = [];
  for (const cat of cfg.categories) for (const d of cat.domains) list.push({ domain: d, category: cat.name });

  // previous snapshot for deltas
  let prev = null;
  try { prev = JSON.parse(fs.readFileSync(path.join(OBS, "latest.json"), "utf8")); } catch { /* first run */ }
  const prevScore = {};
  if (prev && Array.isArray(prev.domains)) for (const p of prev.domains) prevScore[p.domain] = p.score;

  const now = new Date();
  const measuredDate = now.toISOString().slice(0, 10);

  const domains = [];
  let ok = 0, failed = 0;
  for (const item of list) {
    try {
      const m = await measure(item.domain);
      const ps = item.domain in prevScore ? prevScore[item.domain] : null;
      domains.push({ domain: item.domain, category: item.category, score: m.score, grade: m.grade,
        dmarc: m.dmarc, spf: m.spf, mx: m.mx, prevScore: ps, delta: ps == null ? null : m.score - ps });
      ok++;
      process.stdout.write(`  ${item.domain.padEnd(18)} ${m.grade.padEnd(2)} ${String(m.score).padStart(3)}  DMARC ${m.dmarc}\n`);
    } catch (e) {
      failed++;
      process.stdout.write(`  ${item.domain.padEnd(18)} ERROR ${e.message}\n`);
    }
  }

  if (failed) { console.error(`\nAborting: ${failed} domain(s) failed to measure — not writing a partial record.`); process.exit(1); }

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

  fs.mkdirSync(HIST, { recursive: true });
  fs.writeFileSync(path.join(OBS, "latest.json"), JSON.stringify(latest, null, 2) + "\n");
  // compact daily archive (idempotent per day)
  const snap = { measuredDate, generated: now.toISOString(), counts,
    scores: Object.fromEntries(domains.map((d) => [d.domain, { score: d.score, grade: d.grade, dmarc: d.dmarc }])) };
  fs.writeFileSync(path.join(HIST, measuredDate + ".json"), JSON.stringify(snap, null, 2) + "\n");

  console.log(`\nmeasured ${ok} domains — armored ${counts.armored}, DMARC reject ${counts.dmarcReject}, exposed ${counts.exposed}`);
  console.log(`wrote observatory/latest.json + observatory/history/${measuredDate}.json`);
}
main().catch((e) => { console.error("observe failed:", e); process.exit(1); });
