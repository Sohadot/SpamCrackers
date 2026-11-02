/*
 * SpamCrackers Observatory — measurement core (pure + injectable I/O).
 *
 * Shared by scripts/observe.js (measurement), scripts/verify.js (quality gate)
 * and scripts/test/ (offline tests). Separates three outcomes that the old
 * inline code conflated:
 *
 *   1. an answered query that has the record      (NOERROR + matching data)
 *   2. an answered query that lacks the record    (NOERROR/NODATA or NXDOMAIN)
 *   3. a query that was NOT answered              (HTTP error, timeout, network,
 *      SERVFAIL/REFUSED/other RCODE, truncation, malformed or mismatched body)
 *
 * Only 1 and 2 are evidence. 3 throws a MeasurementError and must never be
 * scored — an unanswered query is not proof that a record is absent.
 *
 * The rubric (SPF 25/18/10 + DMARC 25/20/10 + MX 25, normalised over 75; DKIM
 * excluded) is unchanged from the original observe.js and is computed only
 * from the evidence that is published alongside each score, so any reader can
 * recompute every published score from the record itself.
 */
"use strict";
const https = require("https");

const RESOLVER = "https://dns.google/resolve";
const TYPE = { TXT: 16, MX: 15 };
const RCODE = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED" };
// RCODEs that are an answer about the record set (presence or legitimate absence).
const ANSWERED = new Set(["NOERROR", "NXDOMAIN"]);
// Legacy -> evidence transition. 2026-11-02 is the last record measured
// without per-domain evidence. Any record measured after this date MUST carry
// evidence for every domain; verify.js fails otherwise. If another legacy run
// lands on main before this change merges, CI on the PR (which tests the merge
// result) fails until this date is moved to that run's measuredDate.
const EVIDENCE_REQUIRED_AFTER = "2026-11-02";

class MeasurementError extends Error {
  constructor(kind, message) { super(message); this.name = "MeasurementError"; this.kind = kind; }
}
const merr = (kind, msg) => new MeasurementError(kind, msg);
const normName = (s) => String(s).toLowerCase().replace(/\.$/, "");

/* ---------------- transport (the only network I/O) ---------------- */
function httpsTransport(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { accept: "application/dns-json" }, timeout: timeoutMs }, (r) => {
      let d = "";
      r.setEncoding("utf8");
      r.on("data", (c) => (d += c));
      r.on("end", () => resolve({ statusCode: r.statusCode, body: d }));
      r.on("error", (e) => reject(merr("network", e.message)));
    });
    req.on("timeout", () => req.destroy(merr("timeout", `no response within ${timeoutMs}ms`)));
    req.on("error", (e) => reject(e instanceof MeasurementError ? e : merr("network", e.message)));
  });
}

/* ---------------- response classification ---------------- */
// Returns { name, type, rcode, answer[] } for an answered query; throws otherwise.
function classify(name, type, res) {
  if (!res || res.statusCode !== 200) throw merr("http", `HTTP ${res ? res.statusCode : "no response"}`);
  let j;
  try { j = JSON.parse(res.body); } catch { throw merr("malformed", "body is not JSON"); }
  if (!j || typeof j !== "object" || Array.isArray(j)) throw merr("malformed", "body is not a JSON object");
  if (!Number.isInteger(j.Status)) throw merr("malformed", "missing integer DNS Status");
  if (j.TC === true) throw merr("truncated", "response truncated (TC=1)");
  if (j.Question !== undefined) {
    const q = Array.isArray(j.Question) ? j.Question[0] : null;
    if (!q || normName(q.name) !== normName(name) || q.type !== TYPE[type])
      throw merr("malformed", "Question section does not match the query");
  }
  const rcode = RCODE[j.Status] || "RCODE" + j.Status;
  if (!ANSWERED.has(rcode)) throw merr("dns-error", `DNS ${rcode}`);
  if (j.Answer !== undefined && !Array.isArray(j.Answer)) throw merr("malformed", "Answer is not an array");
  const answer = j.Answer || [];
  for (const a of answer)
    if (!a || typeof a !== "object" || !Number.isInteger(a.type) || typeof a.data !== "string")
      throw merr("malformed", "Answer record missing type/data");
  if (rcode === "NXDOMAIN" && answer.some((a) => a.type === TYPE[type]))
    throw merr("malformed", "NXDOMAIN carrying records of the queried type");
  return { name, type, rcode, answer };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function query(name, type, opts = {}) {
  const transport = opts.transport || httpsTransport;
  const tries = opts.tries || 3;
  const delay = opts.retryDelayMs == null ? 750 : opts.retryDelayMs;
  const url = RESOLVER + "?name=" + encodeURIComponent(name) + "&type=" + type;
  let last;
  for (let n = 1; n <= tries; n++) {
    try { return classify(name, type, await transport(url)); }
    catch (e) {
      last = e instanceof MeasurementError ? e : merr("network", e && e.message ? e.message : String(e));
      if (n < tries && delay) await sleep(delay * n);
    }
  }
  throw merr(last.kind, `${type} ${name}: ${last.message} (after ${tries} attempts)`);
}

/* ---------------- record extraction (identical predicates to the original) ---------------- */
const txtStrings = (r) =>
  r.answer.filter((a) => a.type === TYPE.TXT).map((a) => String(a.data).replace(/^"|"$/g, "").replace(/" +"/g, ""));
const isSpf = (t) => /^v=spf1/i.test(t);
const isDmarc = (t) => /v=DMARC1/i.test(t);
// a null MX (RFC 7505: "0 .") declares the domain receives no mail — not counted
const mxHost = (data) => String(data).replace(/^\d+\s+/, "").replace(/\.$/, "");

function grade(score) {
  if (score >= 95) return "A+";
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  if (score >= 30) return "D";
  return "F";
}

/* ---------------- rubric: evidence -> score (unchanged arithmetic) ---------------- */
const ROLES = [["spf", "TXT", (d) => d], ["dmarc", "TXT", (d) => "_dmarc." + d], ["mx", "MX", (d) => d]];

function derive(evidence) {
  const q = evidence && evidence.queries;
  if (!q) throw new Error("no evidence");
  for (const [role] of ROLES) {
    if (!q[role] || !ANSWERED.has(q[role].rcode)) throw new Error(`${role} query was not answered (${q[role] && q[role].rcode})`);
    if (!Array.isArray(q[role].records)) throw new Error(`${role} records missing`);
  }
  const spf = q.spf.records[0];
  const dmarcRec = q.dmarc.records[0];
  const mxCount = q.mx.records.filter((r) => mxHost(r) !== "").length;

  let s = 0, spfQual = "none", dmarc = "none";
  if (spf) { spfQual = spf.indexOf("-all") > -1 ? "-all" : (spf.indexOf("~all") > -1 ? "~all" : "soft"); s += spfQual === "-all" ? 25 : (spfQual === "~all" ? 18 : 10); }
  if (dmarcRec) { dmarc = ((dmarcRec.match(/p=([a-z]+)/i) || [])[1] || "none").toLowerCase(); s += dmarc === "reject" ? 25 : (dmarc === "quarantine" ? 20 : 10); }
  if (mxCount) s += 25;

  const score = Math.round((s / 75) * 100);
  return { score, grade: grade(score), dmarc, spf: spf ? spfQual : "none", mx: mxCount > 0 };
}

/* ---------------- one domain ---------------- */
async function measure(domain, opts = {}) {
  const clock = opts.clock || (() => new Date());
  const measuredAt = clock().toISOString();
  const [t, d, m] = await Promise.all(ROLES.map(([, type, nameOf]) => query(nameOf(domain), type, opts)));
  const entry = (r, all, keep) => ({ name: r.name, type: r.type, rcode: r.rcode, answers: all.length, records: all.filter(keep) });
  const evidence = {
    measuredAt,
    resolver: RESOLVER,
    queries: {
      spf: entry(t, txtStrings(t), isSpf),
      dmarc: entry(d, txtStrings(d), isDmarc),
      mx: entry(m, m.answer.filter((a) => a.type === TYPE.MX).map((a) => a.data), () => true),
    },
  };
  return { ...derive(evidence), evidence };
}

/* ---------------- record audit (used before writing and by verify.js) ---------------- */
// Returns a list of failure strings; [] = the record is internally consistent.
// Legacy records (written before evidence existed) carry no evidence at all
// and are reported as such; a record mixing both is rejected.
function auditRecord(rec, canon) {
  const f = [];
  const doms = Array.isArray(rec && rec.domains) ? rec.domains : [];
  if (!doms.length) return ["record has no domains"];
  const withEv = doms.filter((d) => d.evidence !== undefined).length;
  if (canon) {
    const seen = new Set(doms.map((d) => d.domain));
    for (const c of canon) if (!seen.has(c)) f.push(`missing measurement for ${c}`);
    if (seen.size !== doms.length) f.push("duplicate domain entries");
  }
  const c = rec.counts || {};
  if (c.domains !== doms.length) f.push("counts.domains mismatch");
  if (c.armored !== doms.filter((d) => d.score >= 85).length) f.push("counts.armored mismatch");
  if (c.dmarcReject !== doms.filter((d) => d.dmarc === "reject").length) f.push("counts.dmarcReject mismatch");
  if (c.exposed !== doms.filter((d) => d.score < 50).length) f.push("counts.exposed mismatch");
  if (withEv === 0) {
    if (!(String(rec.measuredDate) <= EVIDENCE_REQUIRED_AFTER))
      f.push(`record measured ${rec.measuredDate} (after ${EVIDENCE_REQUIRED_AFTER}) carries no evidence — evidence is mandatory`);
    return f;
  }
  if (withEv !== doms.length) { f.push(`evidence present for ${withEv}/${doms.length} domains (partial evidence)`); return f; }
  for (const d of doms) {
    const ev = d.evidence, p = `${d.domain}:`;
    if (!ev || isNaN(Date.parse(ev.measuredAt))) { f.push(`${p} evidence.measuredAt invalid`); continue; }
    if (typeof ev.resolver !== "string" || !/^https:\/\//.test(ev.resolver)) f.push(`${p} evidence.resolver invalid`);
    const q = ev.queries || {};
    let shapeOk = true;
    for (const [role, type, nameOf] of ROLES) {
      const e = q[role];
      if (!e) { f.push(`${p} missing ${role} query`); shapeOk = false; continue; }
      if (normName(e.name) !== normName(nameOf(d.domain)) || e.type !== type) { f.push(`${p} ${role} query is for ${e.name}/${e.type}`); shapeOk = false; }
      if (!ANSWERED.has(e.rcode)) { f.push(`${p} ${role} query not answered (${e.rcode}) — cannot be scored`); shapeOk = false; }
      if (!Array.isArray(e.records) || e.records.some((r) => typeof r !== "string")) { f.push(`${p} ${role} records malformed`); shapeOk = false; continue; }
      if (!Number.isInteger(e.answers) || e.answers < e.records.length) { f.push(`${p} ${role} answers count inconsistent`); shapeOk = false; }
      if (e.rcode === "NXDOMAIN" && e.answers !== 0) { f.push(`${p} ${role} NXDOMAIN with answers`); shapeOk = false; }
    }
    if (!shapeOk) continue;
    const want = derive(ev);
    for (const k of ["score", "grade", "dmarc", "spf", "mx"])
      if (d[k] !== want[k]) f.push(`${p} published ${k}=${JSON.stringify(d[k])} but evidence yields ${JSON.stringify(want[k])}`);
    if (typeof d.prevScore === "number" && d.delta !== d.score - d.prevScore) f.push(`${p} delta inconsistent with prevScore`);
  }
  return f;
}

/* ---------------- publication consistency (latest.json <-> history/) ---------------- */
// observe.js renames history -> catalog -> latest, so latest.json is the commit
// point. This check makes every intermediate (interrupted) state detectable:
// latest without its snapshot, a snapshot that disagrees with latest, or a
// snapshot newer than latest (history renamed, latest not).
function auditPublication(rec, snap, historyDates) {
  const f = [];
  if (!snap) return [`history/${rec.measuredDate}.json missing for latest.json`];
  if (snap.measuredDate !== rec.measuredDate || snap.generated !== rec.generated) f.push("history snapshot is from a different run than latest.json");
  if (JSON.stringify(snap.counts) !== JSON.stringify(rec.counts)) f.push("history snapshot counts differ from latest.json");
  const sc = snap.scores || {};
  if (Object.keys(sc).length !== rec.domains.length) f.push("history snapshot domain count differs from latest.json");
  for (const d of rec.domains) {
    const s = sc[d.domain];
    if (!s || s.score !== d.score || s.grade !== d.grade || s.dmarc !== d.dmarc) f.push(`history snapshot differs from latest.json for ${d.domain}`);
  }
  for (const h of historyDates) if (h > rec.measuredDate) f.push(`history/${h}.json is newer than latest.json (${rec.measuredDate})`);
  return f;
}

module.exports = {
  EVIDENCE_REQUIRED_AFTER, auditPublication,
  RESOLVER, RCODE, ANSWERED, MeasurementError,
  httpsTransport, classify, query, measure, derive, grade, auditRecord,
  txtStrings, isSpf, isDmarc, mxHost,
};
