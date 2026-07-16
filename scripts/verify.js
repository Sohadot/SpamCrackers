#!/usr/bin/env node
/*
 * SpamCrackers — deterministic quality gate.
 * Runs structural, security, accessibility, structured-data, link-integrity,
 * sitemap, feed and model-conformance checks across the whole static site.
 * Exit code 0 = all pass, 1 = one or more failures.
 *
 * Usage:  node scripts/verify.js
 */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const fails = [];
const notes = [];
const fail = (m) => fails.push(m);

function walk(dir) {
  let out = [];
  for (const name of fs.readdirSync(dir)) {
    if (name === ".git" || name === "node_modules" || name === "scripts") continue;
    const p = path.join(dir, name);
    if (fs.statSync(p).isDirectory()) out = out.concat(walk(p));
    else if (name.endsWith(".html")) out.push(p);
  }
  return out;
}
const rel = (p) => path.relative(ROOT, p);

const files = walk(ROOT).sort();

/* ---------------- per-page checks ---------------- */
const REQ = {
  WebSite: ["url", "name"],
  Organization: ["name", "url", "logo"],
  SoftwareApplication: ["name", "applicationCategory", "offers"],
  FAQPage: ["mainEntity"],
  TechArticle: ["headline", "url"],
  DefinedTermSet: ["name", "hasDefinedTerm"],
  BreadcrumbList: ["itemListElement"],
  HowTo: ["name", "step"],
  CollectionPage: ["name", "url"],
};

const idsCache = {};
function idsOf(file) {
  if (idsCache[file]) return idsCache[file];
  let s; try { s = fs.readFileSync(file, "utf8"); } catch { return (idsCache[file] = null); }
  return (idsCache[file] = new Set([...s.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
}
function resolvePath(urlPath) {
  let c = urlPath.split("?")[0].split("#")[0];
  if (c.endsWith("/")) c += "index.html";
  let fp = path.join(ROOT, c);
  if (fs.existsSync(fp) && fs.statSync(fp).isFile()) return fp;
  if (fs.existsSync(path.join(fp, "index.html"))) return path.join(fp, "index.html");
  if (fs.existsSync(fp + ".html")) return fp + ".html";
  return null;
}
function resolveAbs(u) {
  const m = u.match(/^https:\/\/spamcrackers\.com(\/[^#]*)?(#(.+))?$/);
  if (!m) return { external: true };
  const f = resolvePath(m[1] || "/");
  return { file: f, frag: m[3] };
}

for (const file of files) {
  const r = rel(file);
  const s = fs.readFileSync(file, "utf8");

  if (!/<html[^>]*\slang=/.test(s)) fail(`${r}: missing <html lang>`);
  if (!/<meta name="viewport"/.test(s)) fail(`${r}: missing viewport`);
  if (!/<title>[^<]+<\/title>/.test(s)) fail(`${r}: missing/empty <title>`);
  if (!/<meta name="description" content="[^"]+"/.test(s)) fail(`${r}: missing description`);
  if (!/rel="canonical"/.test(s)) fail(`${r}: missing canonical`);
  const h1 = (s.match(/<h1[ >]/g) || []).length;
  if (h1 !== 1) fail(`${r}: expected 1 <h1>, found ${h1}`);
  const csp = (s.match(/http-equiv="Content-Security-Policy"/g) || []).length;
  if (csp !== 1) fail(`${r}: expected 1 meta CSP, found ${csp}`);
  if ((s.match(/application\/atom\+xml/g) || []).length !== 1) fail(`${r}: missing feed rel=alternate`);
  if (!/overflow-x:hidden/.test(s)) fail(`${r}: missing overflow-x:hidden safety net`);

  // duplicate ids
  const ids = [...s.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]);
  const dup = [...new Set(ids.filter((v, i) => ids.indexOf(v) !== i))];
  if (dup.length) fail(`${r}: duplicate ids ${dup.join(",")}`);

  // div balance
  if ((s.match(/<div/g) || []).length !== (s.match(/<\/div>/g) || []).length) fail(`${r}: unbalanced <div>`);

  // target=_blank without rel
  if ((s.match(/target="_blank"(?![^>]*\brel=)/g) || []).length) fail(`${r}: target=_blank without rel`);

  // inline app script parses
  const jm = s.match(/<script>([\s\S]*?)<\/script>/);
  if (jm) { try { new vm.Script(jm[1]); } catch (e) { fail(`${r}: inline JS syntax error: ${e.message}`); } }

  // JSON-LD
  const lm = s.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
  if (lm) {
    let o; try { o = JSON.parse(lm[1]); } catch (e) { fail(`${r}: JSON-LD parse error`); o = null; }
    if (o) {
      const g = o["@graph"] || [o];
      if (!g.some((n) => n["@id"] === "https://spamcrackers.com/#organization"))
        fail(`${r}: JSON-LD missing canonical Organization @id`);
      for (const n of g) {
        const t = n["@type"];
        if (REQ[t]) for (const k of REQ[t]) if (!(k in n)) fail(`${r}: ${t} missing "${k}"`);
        if (n.publisher && n.publisher["@type"] === "Organization")
          fail(`${r}: ${t} has inline publisher (should be @id ref)`);
        if (t === "Organization" && n.logo && !n.logo.url) fail(`${r}: Organization.logo.url missing`);
        if (t === "FAQPage") (n.mainEntity || []).forEach((q, i) => {
          if (!q.name || !(q.acceptedAnswer && q.acceptedAnswer.text)) fail(`${r}: FAQ Q${i} incomplete`);
        });
        if (t === "BreadcrumbList") (n.itemListElement || []).forEach((li) => {
          if (!li.position || !li.name || !li.item) fail(`${r}: breadcrumb item incomplete`);
          else { const x = resolveAbs(li.item); if (!x.external && !x.file) fail(`${r}: breadcrumb URL unresolved ${li.item}`); }
        });
        if (t === "DefinedTermSet") (n.hasDefinedTerm || []).forEach((dt) => {
          if (dt["@id"]) { const x = resolveAbs(dt["@id"]);
            if (!x.external) { if (!x.file) fail(`${r}: DefinedTerm URL unresolved ${dt["@id"]}`);
              else if (x.frag && !idsOf(x.file).has(x.frag)) fail(`${r}: DefinedTerm anchor missing ${dt["@id"]}`); } }
        });
      }
    }
  }
}

/* ---------------- internal link crawl ---------------- */
let linkTotal = 0, linkBroken = 0;
for (const file of files) {
  const s = fs.readFileSync(file, "utf8").replace(/<script[\s\S]*?<\/script>/g, "").replace(/<style[\s\S]*?<\/style>/g, "");
  for (const m of s.matchAll(/href="([^"]+)"/g)) {
    const h = m[1];
    if (/^(https?:|mailto:|tel:|data:)/.test(h)) continue;
    linkTotal++;
    let target, frag;
    if (h.startsWith("#")) { target = file; frag = h.slice(1); }
    else if (h.startsWith("/")) { const p = h.split("#"); target = resolvePath(p[0]); frag = p[1]; }
    else { const p = h.split("#"); const rp = path.join(path.dirname(file), p[0]); target = fs.existsSync(rp) ? rp : null; frag = p[1]; }
    if (!target) { linkBroken++; fail(`link ${rel(file)} -> ${h} (no target)`); continue; }
    if (frag) { const ids = idsOf(target); if (ids && !ids.has(frag)) { linkBroken++; fail(`link ${rel(file)} -> ${h} (no #${frag})`); } }
  }
}
notes.push(`internal links: ${linkTotal} checked, ${linkBroken} broken`);

/* ---------------- sitemap ---------------- */
try {
  const sm = fs.readFileSync(path.join(ROOT, "sitemap.xml"), "utf8");
  const locs = [...sm.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  for (const l of locs) { const x = resolveAbs(l); if (!x.external && !x.file) fail(`sitemap: unresolved ${l}`); }
  notes.push(`sitemap: ${locs.length} urls, all resolve`);
} catch { fail("sitemap.xml missing"); }

/* ---------------- feed ---------------- */
try {
  const feed = fs.readFileSync(path.join(ROOT, "feed.xml"), "utf8");
  if (!feed.includes("http://www.w3.org/2005/Atom")) fail("feed.xml: missing Atom namespace");
  const eo = (feed.match(/<entry>/g) || []).length, ec = (feed.match(/<\/entry>/g) || []).length;
  if (eo !== ec) fail(`feed.xml: unbalanced entries ${eo}/${ec}`);
  for (const d of [...feed.matchAll(/<updated>([^<]+)<\/updated>/g)].map((m) => m[1]))
    if (isNaN(Date.parse(d))) fail(`feed.xml: bad date ${d}`);
  notes.push(`feed.xml: ${eo} entries, well-formed`);
} catch { fail("feed.xml missing"); }

/* ---------------- robots ---------------- */
try {
  const rob = fs.readFileSync(path.join(ROOT, "robots.txt"), "utf8");
  if (!/Sitemap:\s*https:\/\/spamcrackers\.com\/sitemap\.xml/.test(rob)) fail("robots.txt: missing Sitemap line");
} catch { fail("robots.txt missing"); }

/* ---------------- model.json conformance ---------------- */
try {
  const model = JSON.parse(fs.readFileSync(path.join(ROOT, "intelligence/model.json"), "utf8"));
  const idRe = /^[A-Z]{3}-[A-Z]{2,3}-\d{2}$/, phRe = /^[A-Z]{3}-[A-Z]{2,3}$/, pcRe = /^[A-Z]{3}$/;
  if (!/^\d+\.\d+\.\d+$/.test(model.version)) fail("model.json: bad version");
  if (model.counts.techniques !== model.techniques.length) fail("model.json: technique count mismatch");
  const reqK = ["id", "pillar", "phase", "name", "description", "signals", "defense", "url"];
  for (const t of model.techniques) {
    if (!idRe.test(t.id)) fail(`model.json: bad id ${t.id}`);
    if (!phRe.test(t.phase)) fail(`model.json: bad phase ${t.phase}`);
    if (!pcRe.test(t.pillar)) fail(`model.json: bad pillar ${t.pillar}`);
    for (const k of reqK) if (!t[k] || !String(t[k]).length) fail(`model.json: ${t.id} missing ${k}`);
  }
  notes.push(`model.json: ${model.techniques.length} techniques conform to schema`);

  /* ---- patterns.json conformance (references must resolve into model.json) ---- */
  try {
    const pat = JSON.parse(fs.readFileSync(path.join(ROOT, "intelligence/patterns.json"), "utf8"));
    const modelIds = new Set(model.techniques.map((t) => t.id));
    const patRe = /^EAP-\d{2}$/;
    if (!/^\d+\.\d+\.\d+$/.test(pat.version)) fail("patterns.json: bad version");
    if (pat.counts.patterns !== pat.patterns.length) fail("patterns.json: pattern count mismatch");
    let refs = 0;
    for (const p of pat.patterns) {
      if (!patRe.test(p.id)) fail(`patterns.json: bad pattern id ${p.id}`);
      for (const k of ["name", "url", "summary", "chain", "signals"])
        if (!p[k] || !p[k].length) fail(`patterns.json: ${p.id} missing ${k}`);
      if (!p.breakpoint || !p.breakpoint.technique) fail(`patterns.json: ${p.id} missing breakpoint`);
      for (const step of p.chain || []) {
        refs++;
        if (!modelIds.has(step.technique)) fail(`patterns.json: ${p.id} references unknown technique ${step.technique}`);
      }
      if (p.breakpoint && !modelIds.has(p.breakpoint.technique))
        fail(`patterns.json: ${p.id} breakpoint references unknown technique ${p.breakpoint.technique}`);
    }
    notes.push(`patterns.json: ${pat.patterns.length} patterns, ${refs} technique refs all resolve to model.json`);

    /* ---- bidirectional invariant: every reference has its backlink on the card ---- */
    const PILLAR_FILE = {
      SPM: "intelligence/index.html", PHI: "intelligence/phishing/index.html",
      BEC: "intelligence/bec/index.html", MAL: "intelligence/mal/index.html",
      SCM: "intelligence/scam/index.html", SPO: "intelligence/spoofing/index.html",
    };
    const srcCache = {};
    const readPillar = (f) => (srcCache[f] = srcCache[f] || fs.readFileSync(path.join(ROOT, f), "utf8"));
    const cardSlice = (src, tid) => {
      const start = src.indexOf(`<article class="tcard" id="${tid}">`);
      if (start === -1) return null;
      const end = src.indexOf("</article>", start);
      return end === -1 ? null : src.slice(start, end);
    };
    let backChecked = 0;
    for (const p of pat.patterns) {
      const anchor = String(p.url).split("#")[1];
      const techs = new Set((p.chain || []).map((s) => s.technique));
      if (p.breakpoint && p.breakpoint.technique) techs.add(p.breakpoint.technique);
      for (const tid of techs) {
        const f = PILLAR_FILE[tid.slice(0, 3)];
        if (!f) { fail(`backlink: ${tid} has no pillar file`); continue; }
        const card = cardSlice(readPillar(f), tid);
        if (card == null) { fail(`backlink: card ${tid} not found in ${f}`); continue; }
        backChecked++;
        if (!card.includes(`/intelligence/patterns/#${anchor}`))
          fail(`backlink: ${tid} card missing backlink to pattern ${p.id} (#${anchor})`);
      }
    }
    notes.push(`patterns backlinks: ${backChecked} technique cards carry their pattern backlink`);
  } catch (e) { fail("patterns.json invalid: " + e.message); }
} catch (e) { fail("model.json invalid: " + e.message); }

/* ---------------- observatory data ---------------- */
try {
  const cfg = JSON.parse(fs.readFileSync(path.join(ROOT, "observatory/domains.json"), "utf8"));
  const canon = new Set();
  for (const cat of cfg.categories) for (const d of cat.domains) {
    if (canon.has(d)) fail(`domains.json: duplicate ${d}`);
    canon.add(d);
  }
  // page must watch exactly the canonical set
  const page = fs.readFileSync(path.join(ROOT, "observatory/index.html"), "utf8");
  const onPage = new Set([...page.matchAll(/data-domain="([^"]+)"/g)].map((m) => m[1]));
  for (const d of canon) if (!onPage.has(d)) fail(`observatory: ${d} in domains.json but not on the page`);
  for (const d of onPage) if (!canon.has(d)) fail(`observatory: ${d} on the page but not in domains.json`);

  // latest.json record conformance
  const rec = JSON.parse(fs.readFileSync(path.join(ROOT, "observatory/latest.json"), "utf8"));
  const grades = new Set(["A+", "A", "B", "C", "D", "F"]);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(rec.measuredDate)) fail("latest.json: bad measuredDate");
  if (isNaN(Date.parse(rec.generated))) fail("latest.json: bad generated timestamp");
  if (!rec.counts || rec.counts.domains !== rec.domains.length) fail("latest.json: counts.domains mismatch");
  const recSet = new Set();
  for (const d of rec.domains) {
    recSet.add(d.domain);
    if (!canon.has(d.domain)) fail(`latest.json: ${d.domain} not in canonical set`);
    if (typeof d.score !== "number" || d.score < 0 || d.score > 100) fail(`latest.json: ${d.domain} bad score`);
    if (!grades.has(d.grade)) fail(`latest.json: ${d.domain} bad grade ${d.grade}`);
    if (!d.dmarc || !d.category) fail(`latest.json: ${d.domain} missing dmarc/category`);
  }
  for (const d of canon) if (!recSet.has(d)) fail(`latest.json: missing measurement for ${d}`);
  notes.push(`observatory: ${canon.size} domains, page + latest.json + domains.json in sync`);

  /* catalog.json must stay in sync with the artifacts it describes */
  const cat = JSON.parse(fs.readFileSync(path.join(ROOT, "catalog.json"), "utf8"));
  const model2 = JSON.parse(fs.readFileSync(path.join(ROOT, "intelligence/model.json"), "utf8"));
  const pat2 = JSON.parse(fs.readFileSync(path.join(ROOT, "intelligence/patterns.json"), "utf8"));
  const expect = { "reference-model": model2.version, "patterns-library": pat2.version, "observatory": rec.measuredDate };
  let catUrls = 0;
  const checkUrl = (u) => { const x = resolveAbs(u); if (!x.external && !x.file) fail(`catalog.json: unresolved url ${u}`); else catUrls++; };
  for (const d of cat.datasets) {
    if (d.id in expect && String(d.version) !== String(expect[d.id]))
      fail(`catalog.json: ${d.id} version ${d.version} != source ${expect[d.id]}`);
    checkUrl(d.landingPage);
    for (const dist of d.distribution || []) checkUrl(dist.url);
  }
  if (String((cat.documents.find((x) => x.id === "governance") || {}).version) !== String(model2.version))
    fail("catalog.json: governance version != model version");
  for (const doc of cat.documents) checkUrl(doc.url);
  notes.push(`catalog.json: ${cat.datasets.length} datasets, ${cat.documents.length} docs, ${catUrls} urls resolve, versions in sync`);
} catch (e) { fail("observatory/catalog data invalid: " + e.message); }

/* ---------------- report ---------------- */
console.log("SpamCrackers — verify");
console.log(`pages: ${files.length}`);
notes.forEach((n) => console.log("  · " + n));
if (fails.length) {
  console.log(`\nFAIL — ${fails.length} issue(s):`);
  fails.slice(0, 60).forEach((m) => console.log("  ✗ " + m));
  process.exit(1);
}
console.log("\n✓ ALL CHECKS PASSED");
