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
// Frozen legacy baseline, independent of whatever the live record currently is
// (tests also run after real measurements: before measuring, and again after a
// publication retry rebase). Built from the immutable legacy snapshot
// history/<EVIDENCE_REQUIRED_AFTER>.json; later live files are never copied in.
function legacyBaseline() {
  const cut = core.EVIDENCE_REQUIRED_AFTER;
  const snap = JSON.parse(fs.readFileSync(path.join(ROOT, "observatory/history", cut + ".json"), "utf8"));
  const cfg = JSON.parse(fs.readFileSync(path.join(ROOT, "observatory/domains.json"), "utf8"));
  const domains = cfg.categories.flatMap((c) => c.domains.map((d) => ({ domain: d, category: c.name,
    score: snap.scores[d].score, grade: snap.scores[d].grade, dmarc: snap.scores[d].dmarc, prevScore: null, delta: null })));
  return { standard: "SpamCrackers Standard v1.0", generated: snap.generated, measuredDate: cut, previous: null, counts: snap.counts, domains };
}
function sandbox() {
  const cut = core.EVIDENCE_REQUIRED_AFTER;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "obs-test-"));
  fs.mkdirSync(path.join(dir, "observatory/history"), { recursive: true });
  fs.copyFileSync(path.join(ROOT, "observatory/domains.json"), path.join(dir, "observatory/domains.json"));
  for (const n of fs.readdirSync(path.join(ROOT, "observatory/history")))
    if (/^\d{4}-\d{2}-\d{2}\.json$/.test(n) && n.slice(0, 10) <= cut)
      fs.copyFileSync(path.join(ROOT, "observatory/history", n), path.join(dir, "observatory/history", n));
  fs.writeFileSync(path.join(dir, "observatory/latest.json"), JSON.stringify(legacyBaseline(), null, 2) + "\n");
  const cat = JSON.parse(fs.readFileSync(path.join(ROOT, "catalog.json"), "utf8"));
  cat.datasets.find((d) => d.id === "observatory").version = cut; cat.generated = cut;
  fs.writeFileSync(path.join(dir, "catalog.json"), JSON.stringify(cat, null, 2) + "\n");
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
  assert.deepEqual(r.wrote.sort(), ["catalog.json", "observatory/evidence/2026-11-09.json", "observatory/history/2026-11-09.json", "observatory/latest.json"]);
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

test("audit: the committed latest.json passes the record audit (legacy or evidence era)", () => {
  const rec = JSON.parse(fs.readFileSync(path.join(ROOT, "observatory/latest.json"), "utf8"));
  const canon = JSON.parse(fs.readFileSync(path.join(ROOT, "observatory/domains.json"), "utf8")).categories.flatMap((c) => c.domains);
  assert.deepEqual(core.auditRecord(rec, canon), []);
});

// =========================================================================
// 8. legacy -> mandatory-evidence transition
// =========================================================================
test("transition: a legacy (evidence-less) record dated after the cutoff is rejected", () => {
  const rec = legacyBaseline();
  assert.deepEqual(core.auditRecord(rec, null), [], "the frozen legacy record is valid inside the legacy window");
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
  return core.auditObservatoryTree(dir, rec).fails; // the exact code verify.js runs
}

test("publication: the committed latest.json matches its history snapshot", () => {
  assert.deepEqual(publicationFails(ROOT), []);
});

for (const k of [0, 1, 2, 3]) {
  test(`publication: crash after ${k} of 4 renames -> ${k ? "rejected by the gate" : "previous record intact"}, no temp files`, async () => {
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

// =========================================================================
// 10. dated evidence sidecars: permanent per-week evidence archive
// =========================================================================
const W1 = "2026-11-09T06:17:00.000Z", W2 = "2026-11-16T06:17:00.000Z";
const weekOpts = (dir, transport, iso) => ({ root: dir, transport, retryDelayMs: 0, log: () => {}, clock: () => new Date(iso) });
const readJ = (dir, rel) => JSON.parse(fs.readFileSync(path.join(dir, rel), "utf8"));

async function twoWeeks() {
  const dir = sandbox();
  const r1 = await run(weekOpts(dir, zoneTransport({}, healthy), W1));
  assert.equal(r1.ok, true);
  const afterW1 = snapshot(dir);
  // week 2: x.com loses its DMARC record (legitimately), so scores change
  const r2 = await run(weekOpts(dir, zoneTransport({ "_dmarc.x.com TXT": [3, null] }, healthy), W2));
  assert.equal(r2.ok, true);
  return { dir, afterW1 };
}

test("archive: two consecutive weekly runs keep week 1 evidence byte-identical and fully auditable", async () => {
  const { dir, afterW1 } = await twoWeeks();
  const after = snapshot(dir);
  for (const f of ["observatory/history/2026-11-09.json", "observatory/evidence/2026-11-09.json"])
    assert.equal(after[f], afterW1[f], `${f} must survive week 2 unchanged`);
  for (const k of Object.keys(afterW1)) if (k.startsWith("observatory/history/")) assert.equal(after[k], afterW1[k]);

  const sc1 = readJ(dir, "observatory/evidence/2026-11-09.json"), snap1 = readJ(dir, "observatory/history/2026-11-09.json");
  assert.equal(sc1.snapshot, "history/2026-11-09.json");
  assert.equal(sc1.snapshotDigest, core.snapshotDigest(snap1));
  assert.equal(sc1.generated, snap1.generated);
  assert.equal(sc1.domains.length, 24);
  assert.ok(sc1.domains.every((d) => d.evidence.measuredAt === W1));
  assert.equal(sc1.domains.find((d) => d.domain === "x.com").evidence.queries.dmarc.rcode, "NOERROR");
  // week 1 scores are still recomputable from week 1 evidence, independent of latest.json
  for (const d of sc1.domains) assert.equal(core.derive(d.evidence).score, snap1.scores[d.domain].score);

  const latest = readJ(dir, "observatory/latest.json");
  assert.equal(latest.measuredDate, "2026-11-16"); assert.equal(latest.previous, "2026-11-09");
  assert.equal(latest.domains.find((d) => d.domain === "x.com").evidence.queries.dmarc.rcode, "NXDOMAIN");
  assert.deepEqual(core.auditObservatoryTree(dir, latest).fails, []);
  // legacy history keeps its original format and has no sidecar
  assert.ok(!fs.existsSync(path.join(dir, "observatory/evidence/2026-11-02.json")));
  assert.deepEqual(Object.keys(readJ(dir, "observatory/history/2026-11-16.json")), ["measuredDate", "generated", "counts", "scores"]);
  fs.rmSync(dir, { recursive: true });
});

const archiveTamper = [
  ["missing sidecar for an evidence-era snapshot", (dir) => fs.unlinkSync(path.join(dir, "observatory/evidence/2026-11-09.json")), /has no evidence sidecar/],
  ["snapshot edited after the fact (digest mismatch)", (dir) => { const p = "observatory/history/2026-11-09.json", j = readJ(dir, p);
    j.scores["google.com"].score = 1; fs.writeFileSync(path.join(dir, p), JSON.stringify(j, null, 2)); }, /snapshotDigest does not match/],
  ["sidecar bound to another run (generated)", (dir) => { const p = "observatory/evidence/2026-11-09.json", j = readJ(dir, p);
    j.generated = W2; fs.writeFileSync(path.join(dir, p), JSON.stringify(j)); }, /generated does not match/],
  ["sidecar pointing at another snapshot", (dir) => { const p = "observatory/evidence/2026-11-09.json", j = readJ(dir, p);
    j.snapshot = "history/2026-11-16.json"; fs.writeFileSync(path.join(dir, p), JSON.stringify(j)); }, /snapshot reference/],
  ["incomplete sidecar (domain dropped)", (dir) => { const p = "observatory/evidence/2026-11-09.json", j = readJ(dir, p);
    j.domains.pop(); fs.writeFileSync(path.join(dir, p), JSON.stringify(j)); }, /domain set differs/],
  ["sidecar with one domain's evidence removed", (dir) => { const p = "observatory/evidence/2026-11-09.json", j = readJ(dir, p);
    delete j.domains[3].evidence; fs.writeFileSync(path.join(dir, p), JSON.stringify(j)); }, /partial evidence/],
  ["sidecar evidence that no longer yields the snapshot score", (dir) => { const p = "observatory/evidence/2026-11-09.json", j = readJ(dir, p);
    j.domains[0].evidence.queries.mx.records = []; fs.writeFileSync(path.join(dir, p), JSON.stringify(j)); }, /evidence yields/],
  ["sidecar evidence from an unanswered query", (dir) => { const p = "observatory/evidence/2026-11-09.json", j = readJ(dir, p);
    j.domains[0].evidence.queries.spf.rcode = "SERVFAIL"; fs.writeFileSync(path.join(dir, p), JSON.stringify(j)); }, /not answered \(SERVFAIL\)/],
  ["orphan sidecar without a snapshot", (dir) => fs.copyFileSync(path.join(dir, "observatory/evidence/2026-11-09.json"),
    path.join(dir, "observatory/evidence/2026-11-12.json")), /has no matching history snapshot/],
  ["sidecar for a legacy-era date", (dir) => fs.copyFileSync(path.join(dir, "observatory/evidence/2026-11-09.json"),
    path.join(dir, "observatory/evidence/2026-11-02.json")), /legacy era/],
  ["latest.json evidence diverging from its sidecar", (dir) => { const p = "observatory/latest.json", j = readJ(dir, p);
    j.domains[0].evidence.measuredAt = W1; fs.writeFileSync(path.join(dir, p), JSON.stringify(j)); }, /differs from evidence\/2026-11-16/],
  ["unexpected file in evidence/", (dir) => fs.writeFileSync(path.join(dir, "observatory/evidence/notes.txt"), "x"), /unexpected file notes.txt/],
  ["staging file left by a force-killed run", (dir) => fs.writeFileSync(path.join(dir, "observatory/latest.json.tmp-4242"), "{"), /stray staging file observatory\/latest.json.tmp-4242/],
];
for (const [label, mut, re] of archiveTamper) {
  test(`archive gate: detects ${label}`, async () => {
    const { dir } = await twoWeeks();
    mut(dir);
    const f = core.auditObservatoryTree(dir, readJ(dir, "observatory/latest.json")).fails;
    assert.ok(f.some((m) => re.test(m)), JSON.stringify(f));
    fs.rmSync(dir, { recursive: true });
  });
}

test("archive: a failed week-2 run leaves week 1 history, evidence and latest untouched", async () => {
  const dir = sandbox();
  await run(weekOpts(dir, zoneTransport({}, healthy), W1));
  const before = snapshot(dir);
  const r = await run(weekOpts(dir, zoneTransport({ "_dmarc.x.com TXT": [2, null] }, healthy), W2));
  assert.equal(r.ok, false);
  assert.deepEqual(snapshot(dir), before);
  assert.deepEqual(core.auditObservatoryTree(dir, readJ(dir, "observatory/latest.json")).fails, []);
  fs.rmSync(dir, { recursive: true });
});

// =========================================================================
// 11. publication step: exhausted push retries must fail the workflow
// The commit step is extracted verbatim from observe.yml and executed with
// `bash -e` (GitHub's default run shell) against a stub git; no real git or
// network is involved.
// =========================================================================
const { spawnSync } = require("child_process");
function commitStep() {
  const lines = fs.readFileSync(path.join(ROOT, ".github/workflows/observe.yml"), "utf8").split("\n");
  const at = lines.findIndex((l) => /- name: Commit the refreshed record/.test(l));
  assert.ok(at > 0, "commit step not found in observe.yml");
  const run = lines.findIndex((l, i) => i > at && /^\s+run: \|\s*$/.test(l));
  const indent = lines[run + 1].match(/^\s*/)[0];
  const body = [];
  for (let i = run + 1; i < lines.length && (lines[i].startsWith(indent) || lines[i].trim() === ""); i++) body.push(lines[i].slice(indent.length));
  return body.join("\n");
}
function runCommitStep(env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "obs-push-"));
  fs.mkdirSync(path.join(dir, "bin"));
  fs.writeFileSync(path.join(dir, "bin/git"), `#!/bin/bash
echo "$*" >> "$STUB_DIR/calls"
case "$1" in
  diff) [ -n "$NO_CHANGE" ] && exit 0 || exit 1 ;;
  push) n=$(( $(cat "$STUB_DIR/pushes" 2>/dev/null || echo 0) + 1 )); echo $n > "$STUB_DIR/pushes"
        if [ "$PUSH_FAILS" = always ] || [ "$n" -le "\${PUSH_FAILS:-0}" ]; then echo "! [rejected] stub" >&2; exit 1; fi; exit 0 ;;
  pull) [ -n "$PULL_FAIL" ] && { echo "CONFLICT stub" >&2; exit 1; }; exit 0 ;;
  rev-parse) echo stub ;;
esac
exit 0
`);
  // stub node: stands in for the post-rebase gate (verify.js, offline tests)
  fs.writeFileSync(path.join(dir, "bin/node"), `#!/bin/bash
echo "node $*" >> "$STUB_DIR/calls"
if [ "$1" = scripts/verify.js ]; then
  v=$(( $(cat "$STUB_DIR/verifies" 2>/dev/null || echo 0) + 1 )); echo $v > "$STUB_DIR/verifies"
  { [ -n "$VERIFY_FAIL" ] || [ "$v" = "\${VERIFY_FAIL_ON:-0}" ]; } && { echo "FAIL stub verify" >&2; exit 1; }
fi
[ "$1" = --test ] && [ -n "$TESTS_FAIL" ] && { echo "not ok stub test" >&2; exit 1; }
exit 0
`);
  fs.writeFileSync(path.join(dir, "bin/sleep"), "#!/bin/sh\nexit 0\n");
  for (const b of ["git", "node", "sleep"]) fs.chmodSync(path.join(dir, "bin", b), 0o755);
  fs.writeFileSync(path.join(dir, "step.sh"), commitStep());
  const r = spawnSync("bash", ["-e", path.join(dir, "step.sh")], { cwd: dir, encoding: "utf8",
    env: { ...process.env, ...env, STUB_DIR: dir, PATH: path.join(dir, "bin") + path.delimiter + process.env.PATH } });
  const calls = fs.existsSync(path.join(dir, "calls")) ? fs.readFileSync(path.join(dir, "calls"), "utf8").trim().split("\n") : [];
  fs.rmSync(dir, { recursive: true });
  const ops = calls.filter((c) => /^(push|pull|commit|node )/.test(c)); // ordered publication-relevant calls
  return { status: r.status, out: r.stdout + r.stderr, pushes: calls.filter((c) => c.startsWith("push")).length,
    pulls: calls.filter((c) => c.startsWith("pull")).length,
    verifies: calls.filter((c) => c === "node scripts/verify.js").length,
    testRuns: calls.filter((c) => c === "node --test scripts/test/observatory.test.js").length, calls, ops };
}
// Invariant: every push after the first is preceded, since the last rebase, by
// a passing verify.js AND offline-test run (the stub only reaches the next
// call if the previous one passed, because the step stops on failure).
function assertEveryRetryReverified(ops) {
  let sinceRebase = null;
  for (const op of ops) {
    if (op.startsWith("pull")) sinceRebase = [];
    else if (op.startsWith("node ")) { if (sinceRebase) sinceRebase.push(op); }
    else if (op === "push" && sinceRebase) {
      assert.deepEqual(sinceRebase, ["node scripts/verify.js", "node --test scripts/test/observatory.test.js"],
        "push after a rebase without re-verification: " + ops.join(" | "));
      sinceRebase = null;
    }
  }
}

test("publish: every push attempt rejected -> step exits nonzero with an error", () => {
  const r = runCommitStep({ PUSH_FAILS: "always" });
  assert.notEqual(r.status, 0, r.out);
  assert.equal(r.pushes, 4);
  assert.equal(r.pulls, 3, "no pointless rebase after the final attempt");
  assert.equal(r.verifies, 3); assert.equal(r.testRuns, 3);
  assertEveryRetryReverified(r.ops);
  assert.match(r.out, /::error::Measurement commit was NOT pushed after 4 attempts/);
  assert.doesNotMatch(r.out, /Published measurement commit/);
});

test("publish: rejected twice, then accepted -> step succeeds and reports publication", () => {
  const r = runCommitStep({ PUSH_FAILS: "2" });
  assert.equal(r.status, 0, r.out);
  assert.equal(r.pushes, 3); assert.equal(r.pulls, 2);
  assert.equal(r.verifies, 2); assert.equal(r.testRuns, 2);
  assertEveryRetryReverified(r.ops);
  assert.match(r.out, /Published measurement commit/);
});

test("publish: first push accepted -> step succeeds without rebasing", () => {
  const r = runCommitStep({});
  assert.equal(r.status, 0, r.out);
  assert.equal(r.pushes, 1); assert.equal(r.pulls, 0);
  assert.equal(r.verifies, 0, "no rebase -> commit was already gated before the step"); assert.equal(r.testRuns, 0);
});

test("publish: rebase conflict while retrying -> step exits nonzero, nothing reported as published", () => {
  const r = runCommitStep({ PUSH_FAILS: "always", PULL_FAIL: "1" });
  assert.notEqual(r.status, 0, r.out);
  assert.equal(r.pushes, 1);
  assert.doesNotMatch(r.out, /Published measurement commit/);
});

test("publish: no change in measurements -> exits 0 without committing or pushing", () => {
  const r = runCommitStep({ NO_CHANGE: "1" });
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /nothing to commit/);
  assert.ok(!r.calls.some((c) => /^(commit|push)/.test(c)), r.calls.join(","));
});

// ---- Issue #43: a rebased commit must be re-verified before it is pushed ----
test("publish: successful rebase -> verify.js and offline tests run on the rebased tree, then push", () => {
  const r = runCommitStep({ PUSH_FAILS: "1" });
  assert.equal(r.status, 0, r.out);
  assert.match(r.ops[0], /^commit -m Observatory: weekly measurement \d{4}-\d{2}-\d{2}$/);
  assert.deepEqual(r.ops.slice(1),
    ["push", "pull --rebase --autostash", "node scripts/verify.js", "node --test scripts/test/observatory.test.js", "push"]);
  assert.match(r.out, /re-verifying stub before pushing/);
  assert.match(r.out, /Published measurement commit/);
});

test("publish: post-rebase verify.js fails -> nonzero exit, rebased commit never pushed", () => {
  const r = runCommitStep({ PUSH_FAILS: "1", VERIFY_FAIL: "1" });
  assert.notEqual(r.status, 0, r.out);
  assert.equal(r.pushes, 1, "only the original, pre-rebase push attempt may happen");
  assert.equal(r.ops[r.ops.length - 1], "node scripts/verify.js", "nothing runs after the failed verification");
  assert.equal(r.testRuns, 0);
  assert.match(r.out, /::error::Rebased measurement commit failed re-verification; it was NOT pushed\./);
  assert.doesNotMatch(r.out, /Published measurement commit/);
});

test("publish: post-rebase offline tests fail -> nonzero exit, rebased commit never pushed", () => {
  const r = runCommitStep({ PUSH_FAILS: "1", TESTS_FAIL: "1" });
  assert.notEqual(r.status, 0, r.out);
  assert.equal(r.pushes, 1);
  assert.deepEqual(r.ops.slice(-3), ["pull --rebase --autostash", "node scripts/verify.js", "node --test scripts/test/observatory.test.js"]);
  assert.match(r.out, /::error::Rebased measurement commit failed re-verification/);
  assert.doesNotMatch(r.out, /Published measurement commit/);
});

test("publish: verification fails on a later retry -> stops there, no further push", () => {
  // first rebase verifies cleanly, push is rejected again, second rebase fails
  // verification: exactly 2 pushes, and the failing tree is never pushed
  const r = runCommitStep({ PUSH_FAILS: "always", VERIFY_FAIL_ON: "2" });
  assert.notEqual(r.status, 0, r.out);
  assert.equal(r.pushes, 2);
  assert.equal(r.verifies, 2); assert.equal(r.testRuns, 1);
  assert.equal(r.ops[r.ops.length - 1], "node scripts/verify.js");
  assert.doesNotMatch(r.out, /Published measurement commit/);
});
