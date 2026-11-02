/*
 * Offline tests for the Observatory measurement path.
 * All DNS is served by fixture transports; real network access is disabled
 * below, so a test that accidentally reaches out fails instead of passing.
 *
 * Usage:  node --test scripts/test/
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const https = require("https");
const http = require("http");
const dns = require("dns");

// ---- hard network block -------------------------------------------------
const blocked = () => { throw new Error("network access is forbidden in offline tests"); };
https.get = https.request = http.get = http.request = blocked;
dns.lookup = dns.resolve = blocked;

const core = require("../observatory-core");
const { run } = require("../observe");
const ROOT = path.resolve(__dirname, "../..");

// ---- fixture helpers ----------------------------------------------------
const TYPE = { TXT: 16, MX: 15 };
const body = (name, type, status, answer, extra = {}) =>
  JSON.stringify({ Status: status, TC: false, RD: true, RA: true, AD: false, CD: false,
    Question: [{ name: name + ".", type: TYPE[type] }],
    ...(answer ? { Answer: answer.map((data) => ({ name: name + ".", type: TYPE[type], TTL: 300, data })) } : {}),
    ...extra });
const ok200 = (b) => ({ statusCode: 200, body: b });
const parse = (url) => { const u = new URL(url); return { name: u.searchParams.get("name"), type: u.searchParams.get("type") }; };

// zone: { "<name> <TYPE>": [status, answers] | fn(attempt) -> response }
function zoneTransport(zone, fallback) {
  const hits = {};
  const t = async (url) => {
    const { name, type } = parse(url);
    const key = `${name} ${type}`;
    hits[key] = (hits[key] || 0) + 1;
    const z = key in zone ? zone[key] : fallback ? fallback(name, type) : [3, null];
    if (typeof z === "function") return z(hits[key], name, type);
    return ok200(body(name, type, z[0], z[1]));
  };
  t.hits = hits;
  return t;
}
const healthy = (name, type) => {
  if (type === "MX") return [0, ["10 mx1." + name + ".", "20 mx2." + name + "."]];
  if (name.startsWith("_dmarc.")) return [0, ['"v=DMARC1; p=reject; rua=mailto:d@' + name.slice(7) + '"']];
  return [0, ['"google-site-verification=abc"', '"v=spf1 include:_spf.' + name + ' -all"']];
};
const opts = (transport) => ({ transport, retryDelayMs: 0, clock: () => new Date("2026-11-09T06:17:00.000Z") });

// =========================================================================
// 1. successful responses
// =========================================================================
test("success: full SPF -all + DMARC reject + MX scores 100 with evidence", async () => {
  const m = await core.measure("example.com", opts(zoneTransport({}, healthy)));
  assert.deepEqual({ score: m.score, grade: m.grade, dmarc: m.dmarc, spf: m.spf, mx: m.mx },
    { score: 100, grade: "A+", dmarc: "reject", spf: "-all", mx: true });
  const e = m.evidence;
  assert.equal(e.measuredAt, "2026-11-09T06:17:00.000Z");
  assert.equal(e.resolver, "https://dns.google/resolve");
  assert.deepEqual(e.queries.spf, { name: "example.com", type: "TXT", rcode: "NOERROR", answers: 2,
    records: ["v=spf1 include:_spf.example.com -all"] }); // unrelated TXT counted, not republished
  assert.deepEqual(e.queries.dmarc.records, ["v=DMARC1; p=reject; rua=mailto:d@example.com"]);
  assert.deepEqual(e.queries.mx.records, ["10 mx1.example.com.", "20 mx2.example.com."]);
});

test("success: multi-string TXT is joined exactly as before", async () => {
  const t = zoneTransport({ "example.com TXT": [0, ['"v=spf1 include:a " "~all"']] }, healthy);
  const m = await core.measure("example.com", opts(t));
  assert.equal(m.spf, "~all");
  assert.deepEqual(m.evidence.queries.spf.records, ["v=spf1 include:a ~all"]);
});

// =========================================================================
// 2. legitimate absence (answered, record not there) is still scored
// =========================================================================
test("absence: NXDOMAIN _dmarc, NODATA MX, TXT without SPF -> scored, distinguishable", async () => {
  const t = zoneTransport({
    "example.com TXT": [0, ['"some-verification=1"']],
    "_dmarc.example.com TXT": [3, null],
    "example.com MX": [0, null],
  });
  const m = await core.measure("example.com", opts(t));
  assert.deepEqual({ score: m.score, grade: m.grade, dmarc: m.dmarc, spf: m.spf, mx: m.mx },
    { score: 0, grade: "F", dmarc: "none", spf: "none", mx: false });
  const q = m.evidence.queries;
  assert.equal(q.spf.rcode, "NOERROR"); assert.equal(q.spf.answers, 1); assert.deepEqual(q.spf.records, []);
  assert.equal(q.dmarc.rcode, "NXDOMAIN"); assert.equal(q.dmarc.answers, 0);
  assert.equal(q.mx.rcode, "NOERROR"); assert.equal(q.mx.answers, 0);
});

test("absence: null MX (RFC 7505 '0 .') is published but not credited", async () => {
  const t = zoneTransport({ "example.com MX": [0, ["0 ."]] }, healthy);
  const m = await core.measure("example.com", opts(t));
  assert.equal(m.mx, false); assert.equal(m.score, 67);
  assert.deepEqual(m.evidence.queries.mx.records, ["0 ."]);
});

// =========================================================================
// 3. transient / resolver errors must FAIL, never score as absent
// =========================================================================
const failing = [
  ["SERVFAIL on _dmarc", { "_dmarc.example.com TXT": [2, null] }, "dns-error", /SERVFAIL/],
  ["REFUSED on MX", { "example.com MX": [5, null] }, "dns-error", /REFUSED/],
  ["unknown RCODE on TXT", { "example.com TXT": [9, null] }, "dns-error", /RCODE9/],
  ["HTTP 503", { "example.com MX": () => ({ statusCode: 503, body: "unavailable" }) }, "http", /HTTP 503/],
  ["HTTP 429 with a JSON body that looks valid", { "_dmarc.example.com TXT": (n, nm, ty) => ({ statusCode: 429, body: body(nm, ty, 0, null) }) }, "http", /HTTP 429/],
  ["timeout", { "_dmarc.example.com TXT": () => { throw new core.MeasurementError("timeout", "no response within 8000ms"); } }, "timeout", /no response/],
  ["socket error", { "example.com MX": () => { throw new Error("ECONNRESET"); } }, "network", /ECONNRESET/],
];
for (const [label, zone, kind, re] of failing) {
  test(`transient: ${label} -> MeasurementError(${kind}), retried, not scored`, async () => {
    const t = zoneTransport(zone, healthy);
    await assert.rejects(core.measure("example.com", opts(t)), (e) => e.kind === kind && re.test(e.message) && /after 3 attempts/.test(e.message));
    const failedKey = Object.keys(zone)[0];
    assert.equal(t.hits[failedKey], 3, "should retry the failing query 3 times");
  });
}

test("transient: SERVFAIL then NOERROR recovers and records the answered response", async () => {
  const t = zoneTransport({ "_dmarc.example.com TXT": (n, nm, ty) =>
    ok200(n === 1 ? body(nm, ty, 2, null) : body(nm, ty, 0, ['"v=DMARC1; p=quarantine"'])) }, healthy);
  const m = await core.measure("example.com", opts(t));
  assert.equal(m.dmarc, "quarantine"); assert.equal(m.evidence.queries.dmarc.rcode, "NOERROR");
  assert.equal(t.hits["_dmarc.example.com TXT"], 2);
});

// =========================================================================
// 4. malformed responses
// =========================================================================
const malformed = [
  ["non-JSON body", () => ok200("<html>oops</html>"), "malformed"],
  ["JSON array", () => ok200("[]"), "malformed"],
  ["missing Status", (n, nm, ty) => ok200(JSON.stringify({ Answer: [] })), "malformed"],
  ["Answer not an array", (n, nm, ty) => ok200(body(nm, ty, 0, null, { Answer: "v=spf1 -all" })), "malformed"],
  ["answer record without data", (n, nm, ty) => ok200(body(nm, ty, 0, null, { Answer: [{ type: 16 }] })), "malformed"],
  ["Question for another name", (n, nm, ty) => ok200(body("evil.example", ty, 0, ['"v=spf1 -all"'])), "malformed"],
  ["Question for another type", (n, nm, ty) => ok200(body(nm, "MX", 0, null)), "malformed"],
  ["NXDOMAIN with records", (n, nm, ty) => ok200(body(nm, ty, 3, ['"v=spf1 -all"'])), "malformed"],
  ["truncated (TC)", (n, nm, ty) => ok200(body(nm, ty, 0, null, { TC: true })), "truncated"],
];
for (const [label, fn, kind] of malformed) {
  test(`malformed: ${label} -> MeasurementError(${kind})`, async () => {
    const t = zoneTransport({ "example.com TXT": fn }, healthy);
    await assert.rejects(core.measure("example.com", opts(t)), (e) => e.kind === kind);
  });
}

// =========================================================================
// 5. rubric preserved
// =========================================================================
test("rubric: exhaustive SPF x DMARC x MX table matches the published constants", () => {
  const spfs = [[null, "none", 0], ["v=spf1 -all", "-all", 25], ["v=spf1 ~all", "~all", 18], ["v=spf1 ?all", "soft", 10]];
  const dmarcs = [[null, "none", 0], ["v=DMARC1; p=reject", "reject", 25], ["v=DMARC1; p=quarantine", "quarantine", 20],
    ["v=DMARC1; p=none", "none", 10], ["v=DMARC1; rua=mailto:x@y", "none", 10]];
  const mxs = [[[], false, 0], [["0 ."], false, 0], [["10 mx.example."], true, 25]];
  const g = (s) => (s >= 95 ? "A+" : s >= 85 ? "A" : s >= 70 ? "B" : s >= 50 ? "C" : s >= 30 ? "D" : "F");
  let n = 0;
  for (const [sr, sq, sp] of spfs) for (const [dr, dp, dpts] of dmarcs) for (const [mr, mxb, mp] of mxs) {
    const ev = { queries: {
      spf: { rcode: "NOERROR", records: sr ? [sr] : [] },
      dmarc: { rcode: sr ? "NOERROR" : "NXDOMAIN", records: dr ? [dr] : [] },
      mx: { rcode: "NOERROR", records: mr } } };
    const score = Math.round(((sp + dpts + mp) / 75) * 100);
    assert.deepEqual(core.derive(ev), { score, grade: g(score), dmarc: dp, spf: sq, mx: mxb });
    n++;
  }
  assert.equal(n, 60);
});

test("rubric: derive refuses evidence from an unanswered query", () => {
  const ev = { queries: { spf: { rcode: "NOERROR", records: [] }, dmarc: { rcode: "SERVFAIL", records: [] }, mx: { rcode: "NOERROR", records: [] } } };
  assert.throws(() => core.derive(ev), /not answered/);
});

test("rubric: every published score in latest.json + all history is reachable by the unchanged rubric", () => {
  const reachable = new Set();
  for (const sp of [0, 10, 18, 25]) for (const dp of [0, 10, 20, 25]) for (const mp of [0, 25]) reachable.add(Math.round(((sp + dp + mp) / 75) * 100));
  const files = [path.join(ROOT, "observatory/latest.json"),
    ...fs.readdirSync(path.join(ROOT, "observatory/history")).map((f) => path.join(ROOT, "observatory/history", f))];
  let n = 0;
  for (const f of files) {
    const j = JSON.parse(fs.readFileSync(f, "utf8"));
    const rows = j.domains || Object.values(j.scores);
    for (const r of rows) { assert.ok(reachable.has(r.score), `${f}: score ${r.score}`); assert.equal(r.grade, core.grade(r.score)); n++; }
  }
  assert.ok(n > 300);
});

// =========================================================================
// 6. end-to-end run(): aborts leave every file byte-identical
// =========================================================================
const sha = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
function sandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "obs-test-"));
  fs.cpSync(path.join(ROOT, "observatory"), path.join(dir, "observatory"), { recursive: true });
  fs.copyFileSync(path.join(ROOT, "catalog.json"), path.join(dir, "catalog.json"));
  return dir;
}
function snapshot(dir) {
  const out = {};
  const walk = (d) => { for (const n of fs.readdirSync(d)) { const p = path.join(d, n);
    if (fs.statSync(p).isDirectory()) walk(p); else out[path.relative(dir, p)] = sha(p); } };
  walk(dir);
  return out;
}
const runOpts = (dir, transport) => ({ root: dir, transport, retryDelayMs: 0, log: () => {},
  clock: () => new Date("2026-11-09T06:17:00.000Z") });

const aborts = [
  ["one persistent SERVFAIL (last domain)", { "_dmarc.x.com TXT": [2, null] }],
  ["one HTTP 500 (first domain)", { "google.com MX": () => ({ statusCode: 500, body: "" }) }],
  ["one malformed body", { "irs.gov TXT": () => ok200("not json") }],
  ["one timeout", { "stripe.com MX": () => { throw new core.MeasurementError("timeout", "no response within 8000ms"); } }],
];
for (const [label, zone] of aborts) {
  test(`partial-measurement abort: ${label} -> no file created, changed or left behind`, async () => {
    const dir = sandbox();
    const before = snapshot(dir);
    const r = await run(runOpts(dir, zoneTransport(zone, healthy)));
    assert.equal(r.ok, false); assert.equal(r.failed.length, 1); assert.deepEqual(r.wrote, []);
    assert.deepEqual(snapshot(dir), before);
    fs.rmSync(dir, { recursive: true });
  });
}

test("abort: an unreadable catalog.json fails before anything is written", async () => {
  const dir = sandbox();
  fs.writeFileSync(path.join(dir, "catalog.json"), "{broken");
  const before = snapshot(dir);
  await assert.rejects(run(runOpts(dir, zoneTransport({}, healthy))));
  assert.deepEqual(snapshot(dir), before);
  fs.rmSync(dir, { recursive: true });
});

test("success run: writes latest+history+catalog, history format unchanged, prior history untouched, audit passes", async () => {
  const dir = sandbox();
  const before = snapshot(dir);
  const r = await run(runOpts(dir, zoneTransport({ "_dmarc.x.com TXT": [3, null] }, healthy)));
  assert.equal(r.ok, true);
  assert.deepEqual(r.wrote.sort(), ["catalog.json", "observatory/history/2026-11-09.json", "observatory/latest.json"]);
  const after = snapshot(dir);
  for (const k of Object.keys(before))
    if (k.startsWith("observatory/history/")) assert.equal(after[k], before[k], `${k} must be unchanged`);
  assert.ok(!Object.keys(after).some((k) => /\.tmp-/.test(k)), "no temp files left");

  const rec = JSON.parse(fs.readFileSync(path.join(dir, "observatory/latest.json"), "utf8"));
  const canon = JSON.parse(fs.readFileSync(path.join(dir, "observatory/domains.json"), "utf8")).categories.flatMap((c) => c.domains);
  assert.deepEqual(core.auditRecord(rec, canon), []);
  assert.deepEqual(Object.keys(rec), ["standard", "method", "license", "url", "generated", "measuredDate", "previous", "counts", "domains"]);
  assert.equal(rec.previous, "2026-11-02");
  const x = rec.domains.find((d) => d.domain === "x.com");
  assert.equal(x.dmarc, "none"); assert.equal(x.evidence.queries.dmarc.rcode, "NXDOMAIN");
  assert.deepEqual(Object.keys(rec.domains[0]), ["domain", "category", "score", "grade", "dmarc", "spf", "mx", "prevScore", "delta", "evidence"]);

  const snap = JSON.parse(fs.readFileSync(path.join(dir, "observatory/history/2026-11-09.json"), "utf8"));
  assert.deepEqual(Object.keys(snap), ["measuredDate", "generated", "counts", "scores"]);
  assert.deepEqual(Object.keys(snap.scores["google.com"]), ["score", "grade", "dmarc"]);
  const cat = JSON.parse(fs.readFileSync(path.join(dir, "catalog.json"), "utf8"));
  assert.equal(cat.datasets.find((d) => d.id === "observatory").version, "2026-11-09");
  fs.rmSync(dir, { recursive: true });
});

// =========================================================================
// 7. audit gate (verify.js) catches tampering and unanswered evidence
// =========================================================================
async function goodRecord() {
  const dir = sandbox();
  await run(runOpts(dir, zoneTransport({}, healthy)));
  const rec = JSON.parse(fs.readFileSync(path.join(dir, "observatory/latest.json"), "utf8"));
  fs.rmSync(dir, { recursive: true });
  return rec;
}
const tamper = [
  ["score edited", (r) => { r.domains[0].score = 99; }, /evidence yields/],
  ["grade edited", (r) => { r.domains[0].grade = "B"; }, /grade/],
  ["rcode replaced by SERVFAIL", (r) => { r.domains[3].evidence.queries.dmarc.rcode = "SERVFAIL"; }, /not answered \(SERVFAIL\)/],
  ["evidence removed from one domain", (r) => { delete r.domains[5].evidence; }, /partial evidence/],
  ["record dropped from evidence", (r) => { r.domains[1].evidence.queries.spf.records = []; }, /evidence yields/],
  ["query for the wrong name", (r) => { r.domains[2].evidence.queries.mx.name = "other.com"; }, /mx query is for/],
  ["NXDOMAIN with answers", (r) => { const q = r.domains[2].evidence.queries.dmarc; q.rcode = "NXDOMAIN"; }, /NXDOMAIN with answers/],
  ["bad measuredAt", (r) => { r.domains[0].evidence.measuredAt = "yesterday"; }, /measuredAt/],
  ["counts edited", (r) => { r.counts.armored -= 1; }, /counts.armored/],
  ["domain dropped", (r) => { r.domains.pop(); r.counts.domains -= 1; r.counts.armored -= 1; r.counts.dmarcReject -= 1; }, /missing measurement/],
];
for (const [label, mut, re] of tamper) {
  test(`audit: detects ${label}`, async () => {
    const rec = await goodRecord();
    const canon = rec.domains.map((d) => d.domain);
    assert.deepEqual(core.auditRecord(rec, canon), []);
    mut(rec);
    const f = core.auditRecord(rec, canon);
    assert.ok(f.some((m) => re.test(m)), JSON.stringify(f));
  });
}

test("audit: the committed legacy latest.json (no evidence) is accepted as legacy", () => {
  const rec = JSON.parse(fs.readFileSync(path.join(ROOT, "observatory/latest.json"), "utf8"));
  const canon = JSON.parse(fs.readFileSync(path.join(ROOT, "observatory/domains.json"), "utf8")).categories.flatMap((c) => c.domains);
  assert.deepEqual(core.auditRecord(rec, canon), []);
});

// =========================================================================
// 8. legacy -> mandatory-evidence transition
// =========================================================================
test("transition: a legacy (evidence-less) record dated after the cutoff is rejected", () => {
  const rec = JSON.parse(fs.readFileSync(path.join(ROOT, "observatory/latest.json"), "utf8"));
  assert.ok(rec.measuredDate <= core.EVIDENCE_REQUIRED_AFTER, "committed record is within the legacy window");
  rec.measuredDate = "2026-11-09";
  const f = core.auditRecord(rec, null);
  assert.ok(f.some((m) => /evidence is mandatory/.test(m)), JSON.stringify(f));
});

test("transition: an evidence-bearing record dated after the cutoff is accepted", async () => {
  const rec = await goodRecord();
  assert.ok(rec.measuredDate > core.EVIDENCE_REQUIRED_AFTER);
  assert.deepEqual(core.auditRecord(rec, null), []);
});

// =========================================================================
// 9. publication consistency: every interrupted-rename state is detectable
// =========================================================================
function publicationFails(dir) {
  const rec = JSON.parse(fs.readFileSync(path.join(dir, "observatory/latest.json"), "utf8"));
  const hd = path.join(dir, "observatory/history");
  const dates = fs.readdirSync(hd).map((n) => n.slice(0, 10));
  let snap = null; try { snap = JSON.parse(fs.readFileSync(path.join(hd, rec.measuredDate + ".json"), "utf8")); } catch {}
  const cat = JSON.parse(fs.readFileSync(path.join(dir, "catalog.json"), "utf8"));
  const f = core.auditPublication(rec, snap, dates);
  if (cat.datasets.find((d) => d.id === "observatory").version !== rec.measuredDate) f.push("catalog version != latest");
  return f;
}

test("publication: the committed latest.json matches its history snapshot", () => {
  assert.deepEqual(publicationFails(ROOT), []);
});

for (const k of [0, 1, 2]) {
  test(`publication: crash after ${k} of 3 renames -> ${k ? "rejected by the gate" : "previous record intact"}, no temp files`, async () => {
    const dir = sandbox();
    const real = fs.renameSync; let n = 0;
    fs.renameSync = (a, b) => { if (++n > k) throw new Error("simulated crash"); return real(a, b); };
    try { await assert.rejects(run(runOpts(dir, zoneTransport({}, healthy))), /simulated crash/); }
    finally { fs.renameSync = real; }
    const f = publicationFails(dir);
    if (k === 0) assert.deepEqual(f, [], "nothing renamed -> previous publication intact");
    else assert.ok(f.length > 0, "interrupted state must be detected");
    assert.ok(!Object.keys(snapshot(dir)).some((x) => /\.tmp-/.test(x)), "no temp files left after a failed rename");
    fs.rmSync(dir, { recursive: true });
  });
}

test("publication: a completed run passes the publication gate", async () => {
  const dir = sandbox();
  await run(runOpts(dir, zoneTransport({}, healthy)));
  assert.deepEqual(publicationFails(dir), []);
  fs.rmSync(dir, { recursive: true });
});
