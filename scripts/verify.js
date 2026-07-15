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
} catch (e) { fail("model.json invalid: " + e.message); }

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
