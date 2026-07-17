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
        if (t === "DataCatalog") (n.dataset || []).forEach((ds, i) => {
          if (!ds.name || !ds.description) fail(`${r}: DataCatalog dataset ${i} missing name/description (Google Dataset requires description)`);
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

/* ---------------- architecture decisions ---------------- */
try {
  const dec = JSON.parse(fs.readFileSync(path.join(ROOT, "decisions.json"), "utf8"));
  const page = fs.readFileSync(path.join(ROOT, "decisions/index.html"), "utf8");
  const pageIds = idsOf(path.join(ROOT, "decisions/index.html"));
  const adrRe = /^ADR-\d{4}$/;
  if (!/^\d+\.\d+\.\d+$/.test(dec.version)) fail("decisions.json: bad version");
  if (dec.counts.decisions !== dec.decisions.length) fail("decisions.json: count mismatch");
  const seen = new Set();
  for (const d of dec.decisions) {
    if (!adrRe.test(d.id)) fail(`decisions.json: bad id ${d.id}`);
    if (seen.has(d.id)) fail(`decisions.json: duplicate id ${d.id}`);
    seen.add(d.id);
    for (const k of ["title", "status", "url", "context", "decision", "tradeoff"])
      if (!d[k] || !String(d[k]).length) fail(`decisions.json: ${d.id} missing ${k}`);
    if (!Array.isArray(d.alternatives) || !d.alternatives.length) fail(`decisions.json: ${d.id} needs alternatives`);
    for (const a of d.alternatives || []) if (!a.option || !a.rejectedBecause) fail(`decisions.json: ${d.id} incomplete alternative`);
    const frag = String(d.url).split("#")[1];
    if (!frag || !pageIds.has(frag)) fail(`decisions.json: ${d.id} anchor #${frag} not on page`);
  }
  const pageCount = (page.match(/<article class="adr /g) || []).length;
  if (pageCount !== dec.decisions.length) fail(`decisions: page has ${pageCount} cards, json has ${dec.decisions.length}`);
  notes.push(`decisions.json: ${dec.decisions.length} ADRs, ids valid, anchors + count in sync with page`);
} catch (e) { fail("decisions data invalid: " + e.message); }

/* ---------------- evidence & confidence model ---------------- */
try {
  const ev = JSON.parse(fs.readFileSync(path.join(ROOT, "intelligence/evidence.json"), "utf8"));
  const evPage = idsOf(path.join(ROOT, "intelligence/evidence/index.html"));
  const umbrella = fs.readFileSync(path.join(ROOT, "intelligence/index.html"), "utf8");
  if (!/^\d+\.\d+\.\d+$/.test(ev.version)) fail("evidence.json: bad version");
  if (ev.counts.evidenceClasses !== ev.evidenceClasses.length) fail("evidence.json: class count mismatch");
  if (ev.counts.confidenceTiers !== ev.confidenceTiers.length) fail("evidence.json: tier count mismatch");
  const evRe = /^EAI-EV-[A-Z]+$/, cfRe = /^EAI-CONF-[1-9]$/;
  for (const c of ev.evidenceClasses) {
    if (!evRe.test(c.id)) fail(`evidence.json: bad class id ${c.id}`);
    for (const k of ["name", "captures", "directlyObserved", "url"]) if (!c[k]) fail(`evidence.json: ${c.id} missing ${k}`);
    const frag = String(c.url).split("#")[1];
    if (!frag || !evPage.has(frag)) fail(`evidence.json: ${c.id} anchor #${frag} not on page`);
    // canonical codes must also appear on the umbrella reference page
    if (!umbrella.includes(c.id)) fail(`evidence.json: class ${c.id} not present on the umbrella reference page`);
  }
  let lvl = 0;
  for (const t of ev.confidenceTiers) {
    if (!cfRe.test(t.id)) fail(`evidence.json: bad tier id ${t.id}`);
    if (t.level !== lvl + 1) fail(`evidence.json: tier levels must be sequential (got ${t.level})`);
    lvl = t.level;
    for (const k of ["name", "rule", "use", "url"]) if (!t[k]) fail(`evidence.json: ${t.id} missing ${k}`);
    const frag = String(t.url).split("#")[1];
    if (!frag || !evPage.has(frag)) fail(`evidence.json: ${t.id} anchor #${frag} not on page`);
  }
  notes.push(`evidence.json: ${ev.evidenceClasses.length} classes + ${ev.confidenceTiers.length} tiers, ids valid, anchors + umbrella codes in sync`);
} catch (e) { fail("evidence data invalid: " + e.message); }

/* ---------------- map: generated counts must match sources ---------------- */
try {
  const mp = fs.readFileSync(path.join(ROOT, "map/index.html"), "utf8");
  const model3 = JSON.parse(fs.readFileSync(path.join(ROOT, "intelligence/model.json"), "utf8"));
  const pat3 = JSON.parse(fs.readFileSync(path.join(ROOT, "intelligence/patterns.json"), "utf8"));
  const ev3 = JSON.parse(fs.readFileSync(path.join(ROOT, "intelligence/evidence.json"), "utf8"));
  const dec3 = JSON.parse(fs.readFileSync(path.join(ROOT, "decisions.json"), "utf8"));
  const src = {
    techniques: model3.counts.techniques,
    pillars: new Set(model3.techniques.map((t) => t.pillar)).size,
    patterns: pat3.counts.patterns,
    evClasses: ev3.counts.evidenceClasses,
    tiers: ev3.counts.confidenceTiers,
    decisions: dec3.counts.decisions,
  };
  let checked = 0;
  for (const m of mp.matchAll(/data-src="([^"]+)">(\d+)<\/span>/g)) {
    const [, key, val] = m;
    if (!(key in src)) { fail(`map: unknown count source ${key}`); continue; }
    checked++;
    if (Number(val) !== src[key]) fail(`map: ${key} shows ${val} but source is ${src[key]}`);
  }
  if (!checked) fail("map: no generated counts found (build may be stale)");
  notes.push(`map: ${checked} generated counts match their sources`);
} catch (e) { fail("map invalid: " + e.message); }

/* ---------------- llms.txt links must resolve ---------------- */
try {
  const llms = fs.readFileSync(path.join(ROOT, "llms.txt"), "utf8");
  let n = 0;
  for (const m of llms.matchAll(/\]\((https:\/\/spamcrackers\.com[^)]*)\)/g)) {
    const x = resolveAbs(m[1]);
    if (!x.external && !x.file) fail(`llms.txt: unresolved link ${m[1]}`);
    else n++;
  }
  if (!n) fail("llms.txt: no internal links found (file missing or malformed)");
  notes.push(`llms.txt: ${n} internal links resolve`);
} catch (e) { fail("llms.txt invalid: " + e.message); }

/* ---------------- taxonomy.json (derived from pillar pages) ---------------- */
try {
  const tax = JSON.parse(fs.readFileSync(path.join(ROOT, "intelligence/taxonomy.json"), "utf8"));
  const PFILE = {
    SPM: "intelligence/index.html", PHI: "intelligence/phishing/index.html",
    BEC: "intelligence/bec/index.html", MAL: "intelligence/mal/index.html",
    SCM: "intelligence/scam/index.html", SPO: "intelligence/spoofing/index.html",
  };
  const axRe = /^[A-Z]{3}-TAX-[A-Z]$/, clRe = /^[A-Z]{2}\d$/;
  const pageCache = {};
  const pageOf = (p) => (pageCache[p] = pageCache[p] || fs.readFileSync(path.join(ROOT, PFILE[p]), "utf8"));
  if (!/^\d+\.\d+\.\d+$/.test(tax.version)) fail("taxonomy.json: bad version");
  if (tax.counts.axes !== tax.axes.length) fail("taxonomy.json: axis count mismatch");
  let classSum = 0;
  const axSeen = new Set();
  for (const ax of tax.axes) {
    if (!axRe.test(ax.id)) fail(`taxonomy.json: bad axis id ${ax.id}`);
    if (axSeen.has(ax.id)) fail(`taxonomy.json: duplicate axis ${ax.id}`);
    axSeen.add(ax.id);
    if (!PFILE[ax.pillar] || ax.id.slice(0, 3) !== ax.pillar) fail(`taxonomy.json: ${ax.id} pillar mismatch`);
    if (!ax.name || !ax.classes || !ax.classes.length) fail(`taxonomy.json: ${ax.id} missing name/classes`);
    const page = pageOf(ax.pillar);
    if (!page.includes(ax.id)) fail(`taxonomy.json: axis ${ax.id} not on ${PFILE[ax.pillar]}`);
    for (const c of ax.classes) {
      classSum++;
      if (!clRe.test(c.code)) fail(`taxonomy.json: ${ax.id} bad class code ${c.code}`);
      if (!c.name || !c.definition) fail(`taxonomy.json: ${ax.id}/${c.code} missing name/definition`);
      if (!page.includes(`>${c.code}</td>`)) fail(`taxonomy.json: class ${c.code} not on ${PFILE[ax.pillar]}`);
    }
  }
  if (tax.counts.classes !== classSum) fail(`taxonomy.json: class total ${tax.counts.classes} != ${classSum}`);
  notes.push(`taxonomy.json: ${tax.axes.length} axes, ${classSum} classes, ids valid + present on pillar pages`);
} catch (e) { fail("taxonomy data invalid: " + e.message); }

/* --------- model.json must stay faithfully derived from the pages --------- */
/* Re-extract techniques from the pillar pages with the generator's exact
 * logic and require model.json to match field-for-field, so a page edit
 * without regenerating the JSON is caught (CONTRIBUTING: it is generated). */
try {
  const model4 = JSON.parse(fs.readFileSync(path.join(ROOT, "intelligence/model.json"), "utf8"));
  const byId = Object.fromEntries(model4.techniques.map((t) => [t.id, t]));
  const PFILE = [
    ["SPM", "/intelligence/", "intelligence/index.html"], ["PHI", "/intelligence/phishing/", "intelligence/phishing/index.html"],
    ["BEC", "/intelligence/bec/", "intelligence/bec/index.html"], ["MAL", "/intelligence/mal/", "intelligence/mal/index.html"],
    ["SCM", "/intelligence/scam/", "intelligence/scam/index.html"], ["SPO", "/intelligence/spoofing/", "intelligence/spoofing/index.html"],
  ];
  const decode = (s) => s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").trim();
  const rx = /<article class="tcard" id="([A-Z]+-[A-Z]+-\d+)">[\s\S]*?<h4>([\s\S]*?)<\/h4>[\s\S]*?<dt>What it is<\/dt><dd>([\s\S]*?)<\/dd>[\s\S]*?<dt>Observable signals<\/dt><dd>([\s\S]*?)<\/dd>[\s\S]*?<dt class="def">Defensive response<\/dt><dd class="def">([\s\S]*?)<\/dd>/g;
  let extracted = 0;
  const seenIds = new Set();
  for (const [code, url, file] of PFILE) {
    const s = fs.readFileSync(path.join(ROOT, file), "utf8");
    let m; rx.lastIndex = 0;
    while ((m = rx.exec(s))) {
      if (m[1].split("-")[0] !== code) continue;
      extracted++; seenIds.add(m[1]);
      const t = byId[m[1]];
      if (!t) { fail(`model.json: ${m[1]} on ${file} but missing from model.json`); continue; }
      const want = { name: decode(m[2]), description: decode(m[3]), signals: decode(m[4]), defense: decode(m[5]),
        url: "https://spamcrackers.com" + url + "#" + m[1] };
      for (const k of Object.keys(want)) if (t[k] !== want[k])
        fail(`model.json: ${m[1]} ${k} out of sync with page (regenerate model.json)`);
    }
  }
  for (const t of model4.techniques) if (!seenIds.has(t.id)) fail(`model.json: ${t.id} not found on any pillar page`);
  if (extracted !== model4.techniques.length) fail(`model.json: extracted ${extracted} from pages, json has ${model4.techniques.length}`);
  notes.push(`model.json: ${extracted} techniques verified field-for-field against the pillar pages`);
} catch (e) { fail("model/page sync check failed: " + e.message); }

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
