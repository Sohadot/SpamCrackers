#!/usr/bin/env node
/*
 * SpamCrackers — publication policy (trusted check, Issue #44).
 *
 * Decides whether a pull request is an automated Observatory publication and,
 * if so, whether it changes ONLY the approved measurement artifacts:
 *
 *   observatory/latest.json               modified
 *   observatory/history/<D>.json          added (never modified/removed)
 *   observatory/evidence/<D>.json         added
 *   catalog.json                          optional; only `generated` and the
 *                                         observatory dataset `version` may
 *                                         change, both to <D>
 *
 * Anything else (scripts, tests, workflows, HTML, methodology, the domain
 * cohort, deletions, renames) fails the check. Human PRs are not restricted
 * here; they go through normal review and the `verify` check.
 *
 * Trust model: this file runs from the BASE branch via
 * .github/workflows/publication-policy.yml (`pull_request_target`, read-only
 * token). PR content is only ever read as data through the REST API, never
 * checked out or executed, so an automated PR cannot weaken the policy that
 * evaluates it. Because scripts/ is not an approved path, it also guarantees
 * that the `verify` check of an automated PR runs main's own validation code.
 *
 * evaluate() is pure and deterministic; the CLI below only gathers its inputs.
 */
"use strict";

const BRANCH_RE = /^observatory\/(\d{4}-\d{2}-\d{2})-(\d+)$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const OBSERVE_WORKFLOW = ".github/workflows/observe.yml";

/**
 * pr:    { headRef, headRepo, baseRepo, authorLogin, authorType }
 * files: [{ filename, status, previous_filename? }]  (compare merge-base...head)
 * read:  { base(path) -> string|null, head(path) -> string|null }
 * run:   workflow run cited by the branch name: { path, event, status, head_branch } | null
 * opts:  { botLogin, defaultBranch }
 * -> { automated, ok, violations[], date }
 */
function evaluate(pr, files, read, run, opts = {}) {
  const v = [];
  const automated = String(pr.headRef || "").startsWith("observatory/") ||
    pr.authorType === "Bot" || (!!opts.botLogin && pr.authorLogin === opts.botLogin);
  if (!automated) return { automated: false, ok: true, violations: [], date: null };

  if (pr.headRepo !== pr.baseRepo) v.push(`automated publication must come from ${pr.baseRepo}, not ${pr.headRepo}`);
  const m = BRANCH_RE.exec(pr.headRef || "");
  if (!m) v.push(`branch "${pr.headRef}" is not observatory/<YYYY-MM-DD>-<run id>`);
  const D = m ? m[1] : null;

  // provenance: the branch must cite a live run of the measurement workflow
  if (m) {
    if (!run) v.push(`workflow run ${m[2]} not found`);
    else {
      if (run.path !== OBSERVE_WORKFLOW) v.push(`run ${m[2]} is ${run.path}, not ${OBSERVE_WORKFLOW}`);
      if (!["schedule", "workflow_dispatch"].includes(run.event)) v.push(`run ${m[2]} was triggered by ${run.event}`);
      if (run.status === "completed") v.push(`run ${m[2]} has already completed`);
      if (run.head_branch !== (opts.defaultBranch || "main")) v.push(`run ${m[2]} ran on ${run.head_branch}, not ${opts.defaultBranch || "main"}`);
    }
  }

  // exact file allowlist
  const allowed = D ? {
    "observatory/latest.json": ["modified"],
    [`observatory/history/${D}.json`]: ["added"],
    [`observatory/evidence/${D}.json`]: ["added"],
    "catalog.json": ["modified"],
  } : {};
  const required = D ? ["observatory/latest.json", `observatory/history/${D}.json`, `observatory/evidence/${D}.json`] : [];
  const seen = new Set();
  for (const f of files) {
    seen.add(f.filename);
    if (f.previous_filename) v.push(`renames are not allowed (${f.previous_filename} -> ${f.filename})`);
    const ok = allowed[f.filename];
    if (!ok) v.push(`${f.filename} (${f.status}) is not an approved measurement artifact`);
    else if (!ok.includes(f.status)) v.push(`${f.filename} must be ${ok.join("/")}, was ${f.status}`);
  }
  for (const r of required) if (!seen.has(r)) v.push(`${r} is missing from the publication`);

  // content: dates must be consistent and moving forward
  const parse = (side, p) => {
    const s = read[side](p);
    if (s == null) return null;
    try { return JSON.parse(s); } catch { v.push(`${side} ${p} is not valid JSON`); return null; }
  };
  if (D && v.length === 0) {
    const headLatest = parse("head", "observatory/latest.json");
    const baseLatest = parse("base", "observatory/latest.json");
    if (!headLatest || headLatest.measuredDate !== D) v.push(`latest.json measuredDate must be ${D}`);
    if (baseLatest && DATE_RE.test(String(baseLatest.measuredDate)) && !(D > baseLatest.measuredDate))
      v.push(`${D} does not advance the published record (${baseLatest.measuredDate})`);
    for (const p of [`observatory/history/${D}.json`, `observatory/evidence/${D}.json`]) {
      const j = parse("head", p);
      if (!j || j.measuredDate !== D) v.push(`${p} measuredDate must be ${D}`);
    }
    if (seen.has("catalog.json")) {
      const hb = parse("base", "catalog.json"), hh = parse("head", "catalog.json");
      if (!hb || !hh) v.push("catalog.json could not be compared");
      else {
        const strip = (c) => { const x = JSON.parse(JSON.stringify(c)); delete x.generated;
          for (const d of x.datasets || []) if (d.id === "observatory") delete d.version; return JSON.stringify(x); };
        if (strip(hb) !== strip(hh)) v.push("catalog.json changes fields other than generated / observatory version");
        const obs = (hh.datasets || []).find((d) => d.id === "observatory");
        if (hh.generated !== D || !obs || obs.version !== D) v.push(`catalog.json generated and observatory version must both be ${D}`);
      }
    }
  }
  return { automated: true, ok: v.length === 0, violations: v, date: D };
}

/* ---------------- CLI (GitHub Actions, base-branch code only) ---------------- */
function cli() {
  const { execFileSync } = require("child_process");
  const env = process.env;
  const repo = env.REPO, number = env.PR_NUMBER;
  const gh = (args, raw) => execFileSync("gh", ["api", ...(raw ? ["-H", "Accept: application/vnd.github.raw"] : []), ...args],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
  const pull = JSON.parse(gh([`repos/${repo}/pulls/${number}`]));
  const headSha = pull.head.sha;
  // files changed between the merge base and this exact head SHA
  let mergeBase = null;
  const files = [];
  for (let page = 1; ; page++) {
    const p = JSON.parse(gh([`repos/${repo}/compare/${pull.base.sha}...${headSha}?per_page=100&page=${page}`]));
    mergeBase = mergeBase || p.merge_base_commit.sha;
    for (const f of p.files || []) files.push({ filename: f.filename, status: f.status, previous_filename: f.previous_filename });
    if (!p.files || p.files.length < 100) break;
  }
  const at = (ref) => (p) => { try { return gh([`repos/${repo}/contents/${p}?ref=${ref}`], true); } catch { return null; } };
  const m = BRANCH_RE.exec(pull.head.ref);
  let run = null;
  if (m) { try { run = JSON.parse(gh([`repos/${repo}/actions/runs/${m[2]}`])); } catch { run = null; } }
  const res = evaluate(
    { headRef: pull.head.ref, headRepo: pull.head.repo ? pull.head.repo.full_name : null, baseRepo: pull.base.repo.full_name,
      authorLogin: pull.user.login, authorType: pull.user.type },
    files, { base: at(mergeBase), head: at(headSha) }, run,
    { botLogin: env.BOT_LOGIN || "", defaultBranch: pull.base.repo.default_branch });

  const state = res.ok ? "success" : "failure";
  const desc = !res.automated ? "Not an automated publication: normal review applies."
    : res.ok ? `Automated publication ${res.date}: only approved measurement artifacts.`
    : `Rejected: ${res.violations[0]}`.slice(0, 139);
  console.log(`PR #${number} head ${headSha} automated=${res.automated} -> ${state}`);
  for (const x of res.violations) console.log("  ✗ " + x);
  execFileSync("gh", ["api", "-X", "POST", `repos/${repo}/statuses/${headSha}`, "-f", `state=${state}`,
    "-f", "context=publication-policy", "-f", `description=${desc}`, "-f", `target_url=${env.RUN_URL || ""}`], { stdio: "inherit" });
  if (!res.ok) process.exit(1);
}

module.exports = { evaluate, BRANCH_RE, OBSERVE_WORKFLOW };
if (require.main === module) cli();
