/*
 * Offline tests for PR-based publication (Issue #44):
 *  - scripts/publication-policy.js : the trusted allowlist check
 *  - .github/workflows/*.yml        : trust-boundary structure
 *  - scripts/publish-measurement.js : the publication driver, against a fake
 *                                     GitHub API (no network, no real git)
 *
 * Usage:  node --test scripts/test/publication.test.js
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const https = require("https");
const http = require("http");

const blocked = () => { throw new Error("network access is forbidden in offline tests"); };
https.get = https.request = http.get = http.request = blocked;

const { evaluate } = require("../publication-policy");
const { publish } = require("../publish-measurement");
const ROOT = path.resolve(__dirname, "../..");
const rd = (p) => fs.readFileSync(path.join(ROOT, p), "utf8");

// =========================================================================
// 1. publication policy: a genuine automated publication
// =========================================================================
const D = "2026-11-09", BASE_D = "2026-11-02", REPO = "Sohadot/SpamCrackers";
const baseCatalog = JSON.parse(rd("catalog.json"));
function headCatalog(mut) {
  const c = JSON.parse(JSON.stringify(baseCatalog));
  c.generated = D; c.datasets.find((d) => d.id === "observatory").version = D;
  if (mut) mut(c);
  return JSON.stringify(c, null, 2);
}
function scenario(over = {}) {
  const head = {
    "observatory/latest.json": JSON.stringify({ measuredDate: D, domains: [] }),
    [`observatory/history/${D}.json`]: JSON.stringify({ measuredDate: D }),
    [`observatory/evidence/${D}.json`]: JSON.stringify({ measuredDate: D }),
    "catalog.json": headCatalog(),
    ...(over.head || {}),
  };
  const base = { "observatory/latest.json": JSON.stringify({ measuredDate: BASE_D }), "catalog.json": JSON.stringify(baseCatalog), ...(over.base || {}) };
  const files = over.files || [
    { filename: "observatory/latest.json", status: "modified" },
    { filename: `observatory/history/${D}.json`, status: "added" },
    { filename: `observatory/evidence/${D}.json`, status: "added" },
    { filename: "catalog.json", status: "modified" },
  ];
  const pr = { headRef: `observatory/${D}-4242`, headRepo: REPO, baseRepo: REPO,
    authorLogin: "spamcrackers-observatory[bot]", authorType: "Bot", ...(over.pr || {}) };
  const run = over.run === null ? null : { path: ".github/workflows/observe.yml", event: "schedule", status: "in_progress", head_branch: "main", ...(over.run || {}) };
  return evaluate(pr, files, { base: (p) => base[p] ?? null, head: (p) => head[p] ?? null }, run,
    { botLogin: "spamcrackers-observatory[bot]", defaultBranch: "main", ...(over.enumeration ? { enumeration: over.enumeration } : {}) });
}
const plus = (...extra) => [
  { filename: "observatory/latest.json", status: "modified" },
  { filename: `observatory/history/${D}.json`, status: "added" },
  { filename: `observatory/evidence/${D}.json`, status: "added" },
  ...extra,
];

test("policy: genuine automated measurement PR passes", () => {
  const r = scenario();
  assert.deepEqual(r, { automated: true, ok: true, violations: [], date: D });
});

test("policy: catalog.json is optional", () => {
  assert.equal(scenario({ files: plus() }).ok, true);
});

// =========================================================================
// 2. policy negatives: an App-authored PR cannot weaken its own validation
// =========================================================================
const rejects = [
  ["edits scripts/verify.js (the verify gate)", { files: plus({ filename: "scripts/verify.js", status: "modified" }) }, /scripts\/verify\.js .* not an approved/],
  ["edits scripts/publication-policy.js (this policy)", { files: plus({ filename: "scripts/publication-policy.js", status: "modified" }) }, /publication-policy\.js/],
  ["edits scripts/observatory-core.js (scoring/audits)", { files: plus({ filename: "scripts/observatory-core.js", status: "modified" }) }, /observatory-core\.js/],
  ["edits scripts/publish-measurement.js", { files: plus({ filename: "scripts/publish-measurement.js", status: "modified" }) }, /publish-measurement\.js/],
  ["edits the tests", { files: plus({ filename: "scripts/test/observatory.test.js", status: "modified" }) }, /observatory\.test\.js/],
  ["adds a test file", { files: plus({ filename: "scripts/test/zz.test.js", status: "added" }) }, /zz\.test\.js/],
  ["edits verify.yml", { files: plus({ filename: ".github/workflows/verify.yml", status: "modified" }) }, /verify\.yml/],
  ["edits publication-policy.yml", { files: plus({ filename: ".github/workflows/publication-policy.yml", status: "modified" }) }, /publication-policy\.yml/],
  ["adds a workflow", { files: plus({ filename: ".github/workflows/x.yml", status: "added" }) }, /x\.yml/],
  ["changes the domain cohort", { files: plus({ filename: "observatory/domains.json", status: "modified" }) }, /domains\.json/],
  ["edits the Observatory page", { files: plus({ filename: "observatory/index.html", status: "modified" }) }, /observatory\/index\.html/],
  ["edits the methodology", { files: plus({ filename: "methodology/index.html", status: "modified" }) }, /methodology/],
  ["edits an unrelated file", { files: plus({ filename: "README.md", status: "modified" }) }, /README\.md/],
  ["rewrites an existing history snapshot", { files: plus({ filename: `observatory/history/${BASE_D}.json`, status: "modified" }) }, /history\/2026-11-02\.json/],
  ["deletes a history snapshot", { files: plus({ filename: "observatory/history/2026-07-16.json", status: "removed" }) }, /2026-07-16\.json \(removed\)/],
  ["modifies (not adds) the new snapshot", { files: [{ filename: "observatory/latest.json", status: "modified" },
    { filename: `observatory/history/${D}.json`, status: "modified" }, { filename: `observatory/evidence/${D}.json`, status: "added" }] }, /must be added, was modified/],
  ["renames into an allowed path", { files: [{ filename: "observatory/latest.json", status: "modified" },
    { filename: `observatory/history/${D}.json`, status: "renamed", previous_filename: "observatory/history/2026-07-16.json" },
    { filename: `observatory/evidence/${D}.json`, status: "added" }] }, /renames are not allowed/],
  ["omits the evidence sidecar", { files: [{ filename: "observatory/latest.json", status: "modified" }, { filename: `observatory/history/${D}.json`, status: "added" }] }, /evidence\/2026-11-09\.json is missing/],
  ["changes another catalog field", { head: { "catalog.json": headCatalog((c) => { c.datasets[0].name = "x"; }) } }, /catalog\.json changes fields other than/],
  ["sets a catalog version other than the date", { head: { "catalog.json": headCatalog((c) => { c.generated = "2027-01-01"; }) } }, /must both be 2026-11-09/],
  ["latest.json date differs from the branch date", { head: { "observatory/latest.json": JSON.stringify({ measuredDate: "2026-11-10" }) } }, /latest\.json measuredDate must be 2026-11-09/],
  ["backdates the record", { base: { "observatory/latest.json": JSON.stringify({ measuredDate: "2026-11-16" }) } }, /does not advance/],
  ["sidecar date differs", { head: { [`observatory/evidence/${D}.json`]: JSON.stringify({ measuredDate: "2026-11-02" }) } }, /evidence\/2026-11-09\.json measuredDate/],
  ["malformed JSON", { head: { "observatory/latest.json": "{not json" } }, /not valid JSON/],
  ["comes from a fork", { pr: { headRepo: "evil/SpamCrackers" } }, /must come from Sohadot\/SpamCrackers/],
  ["uses a non-conforming branch name", { pr: { headRef: "observatory/latest" } }, /is not observatory\/<YYYY-MM-DD>-<run id>/],
  ["cites a run that does not exist", { run: null }, /run 4242 not found/],
  ["cites a run of another workflow", { run: { path: ".github/workflows/verify.yml" } }, /not \.github\/workflows\/observe\.yml/],
  ["cites a run triggered by a PR", { run: { event: "pull_request" } }, /triggered by pull_request/],
  ["cites a run that already completed", { run: { status: "completed" } }, /already completed/],
  ["cites a run on another branch", { run: { head_branch: "evil" } }, /ran on evil/],
  ["is Bot-authored on a non-observatory branch with code changes", { pr: { headRef: "feature/x" },
    files: [{ filename: "scripts/verify.js", status: "modified" }] }, /is not observatory\//],
  ["is human-authored but uses the reserved observatory/ namespace", { pr: { authorLogin: "someone", authorType: "User" },
    files: plus({ filename: "scripts/verify.js", status: "modified" }) }, /scripts\/verify\.js/],
];
for (const [label, over, re] of rejects) {
  test(`policy rejects an automated PR that ${label}`, () => {
    const r = scenario(over);
    assert.equal(r.automated, true); assert.equal(r.ok, false);
    assert.ok(r.violations.some((m) => re.test(m)), JSON.stringify(r.violations));
  });
}

test("policy: human development PR changing code passes the policy (normal review + verify apply)", () => {
  const r = evaluate({ headRef: "ccr-feature", headRepo: REPO, baseRepo: REPO, authorLogin: "Sohadot", authorType: "User" },
    [{ filename: "scripts/verify.js", status: "modified" }, { filename: ".github/workflows/verify.yml", status: "modified" }],
    { base: () => null, head: () => null }, null, { botLogin: "spamcrackers-observatory[bot]" });
  assert.deepEqual(r, { automated: false, ok: true, violations: [], date: null });
});

test("policy: the configured App login is automated even without type Bot", () => {
  const r = scenario({ pr: { authorType: "User", headRef: "feature/x" }, files: [{ filename: "scripts/verify.js", status: "modified" }] });
  assert.equal(r.automated, true); assert.equal(r.ok, false);
});

// =========================================================================
// 3. trust boundary: workflow structure
// =========================================================================
const wf = (n) => rd(`.github/workflows/${n}`);
const code = (y) => y.split("\n").filter((l) => !/^\s*#/.test(l)).map((l) => l.replace(/\s+#.*$/, "")).join("\n"); // YAML without comments
const topPermissions = (y) => { const m = y.match(/^permissions:\n((?:  .+\n)+)/m); return m ? m[1].trim().split("\n").map((l) => l.trim()) : null; };

test("trust: publication-policy runs from the default branch via pull_request_target", () => {
  const y = wf("publication-policy.yml");
  assert.match(y, /^on:\n  pull_request_target:/m);
  assert.doesNotMatch(y, /^\s+pull_request:/m, "must not also run on pull_request (that would execute PR-head workflow code)");
  assert.match(y, /run: node scripts\/publication-policy\.js\s*$/m);
});

test("trust: publication-policy never checks out, references or executes the PR head", () => {
  const y = code(wf("publication-policy.yml"));
  assert.doesNotMatch(y, /github\.event\.pull_request\.head/, "no PR-head ref/sha/branch may be used");
  assert.doesNotMatch(y, /^\s+ref:/m, "checkout must use the default branch, never a ref override");
  assert.match(y, /persist-credentials: false/);
  assert.doesNotMatch(y, /npm |npx |yarn |pnpm |actions\/cache|upload-artifact|secrets\./);
  // only PR number / repository identifiers reach the step, through env
  for (const m of y.matchAll(/\$\{\{\s*([^}]+)\}\}/g))
    assert.ok(/^(github\.(token|repository|server_url|run_id|event\.pull_request\.number)|vars\.OBSERVATORY_APP_BOT_LOGIN)\s*$/.test(m[1].trim()), "unexpected expression " + m[1]);
});

test("trust: publication-policy token is read-only except commit statuses", () => {
  assert.deepEqual(topPermissions(wf("publication-policy.yml")).sort(),
    ["actions: read", "contents: read", "pull-requests: read", "statuses: write"]);
});

test("trust: every third-party action in the privileged policy workflow is pinned to a commit SHA", () => {
  const uses = [...code(wf("publication-policy.yml")).matchAll(/^\s*(?:- )?uses: (\S+)/gm)].map((m) => m[1]);
  assert.equal(uses.length, 2);
  for (const u of uses) assert.match(u, /@[0-9a-f]{40}$/, u);
});

test("trust: workflows that execute PR-head code hold a read-only token (cannot forge statuses or checks)", () => {
  for (const n of fs.readdirSync(path.join(ROOT, ".github/workflows"))) {
    const y = wf(n);
    if (!/^\s+pull_request:/m.test(y)) continue;
    assert.deepEqual(topPermissions(y), ["contents: read"], `${n} runs on pull_request and must be contents: read only`);
    assert.doesNotMatch(y, /^\s+permissions:/m, `${n} must not widen permissions per job`);
  }
});

// ---- dormant migration: production publication is unchanged until the owner opts in ----
const LEGACY_STEP_SHA256 = "483b08cef4da1eb276df614e40266266d05767dd0e92c0e6047e1712aa1806eb"; // main 605bdd0, run block
const stepBlock = (y, name) => {
  const lines = y.split("\n"), at = lines.findIndex((l) => l === `      - name: ${name}`);
  assert.ok(at >= 0, `step "${name}" not found`);
  const out = [];
  for (let i = at + 1; i < lines.length && !/^      - /.test(lines[i]); i++) out.push(lines[i]);
  return out;
};

test("migration: PR mode is selected only by a canary dispatch or OBSERVATORY_PUBLISHER=pr", () => {
  assert.match(wf("observe.yml"), /^    env:\n      PR_MODE: \$\{\{ inputs\.base == 'observatory-canary' \|\| vars\.OBSERVATORY_PUBLISHER == 'pr' \}\}$/m);
});

test("migration: the legacy publisher is the original step, byte for byte, and runs only outside PR mode", () => {
  const b = stepBlock(wf("observe.yml"), "Commit the refreshed record");
  assert.equal(b[0], "        if: env.PR_MODE != 'true'");
  const body = b.slice(1).filter((l) => l !== "").join("\n") + "\n";
  assert.equal(crypto.createHash("sha256").update(body).digest("hex"), LEGACY_STEP_SHA256,
    "the legacy production publisher must stay identical to main's until the cutover");
});

test("migration: every App/PR-mode step runs only in PR mode; checkout falls back to GITHUB_TOKEN", () => {
  const y = wf("observe.yml");
  for (const n of ["Require the publication App credentials", "Mint a short-lived App installation token for this repository only", "Publish through a verified pull request"])
    assert.equal(stepBlock(y, n)[0], "        if: env.PR_MODE == 'true'", n);
  assert.match(y, /token: \$\{\{ steps\.app\.outputs\.token \|\| github\.token \}\}/);
});

test("migration: the PR-mode publisher never pushes to the base branch and uses only the App token", () => {
  const b = stepBlock(wf("observe.yml"), "Publish through a verified pull request").join("\n");
  assert.doesNotMatch(b, /git push|git commit/);
  assert.match(b, /run: node scripts\/publish-measurement\.js/);
  assert.match(b, /GH_TOKEN: \$\{\{ steps\.app\.outputs\.token \}\}/);
  const y = wf("observe.yml");
  assert.match(y, /options: \[main, observatory-canary\]/);
  assert.match(y, /repositories: \$\{\{ github\.event\.repository\.name \}\}/, "App token must be scoped to this repository");
});

test("migration: GITHUB_TOKEN keeps contents: write only because the legacy publisher needs it", () => {
  assert.deepEqual(topPermissions(wf("observe.yml")), ["contents: write # legacy publisher only (see header); PR mode uses the App token"]);
});

test("trust: required check names stay stable (ruleset matches by name)", () => {
  assert.match(wf("verify.yml"), /^jobs:\n  verify:/m);
  assert.match(rd("scripts/publication-policy.js"), /context=publication-policy/);
});

// =========================================================================
// 4. publication driver against a fake GitHub
// =========================================================================
const LATEST = Buffer.from(JSON.stringify({ measuredDate: D, generated: "2026-11-09T12:00:00.000Z" }, null, 2) + "\n");
function fakeWorld(o = {}) {
  const w = {
    calls: [], gitCalls: [], heads: ["h1"], merged: null, t: 0, closed: false, comments: [], checkReads: {}, compares: [],
    checks: o.checks || (() => ({ verify: [["completed", "success"], ["completed", "success"]], policy: "success" })),
    mergeable: o.mergeable || (() => "clean"),
    mergeImpl: o.merge || ((sha) => ({ merged: true, sha: "m1", _sha: sha })),
    pages: o.pages || ((n) => ({ commit: "m1", status: n < 2 ? "building" : "built" })),
    live: o.live || (() => LATEST),
    expected: o.expected || LATEST,
  };
  let pagesN = 0, liveN = 0;
  const route = (args, opt) => {
    const a = args.filter((x) => !/^-[XfH]$/.test(x));
    const method = args.includes("-X") ? args[args.indexOf("-X") + 1] : "GET";
    const p = a.find((x) => x.startsWith("repos/"));
    const f = Object.fromEntries(args.map((x, i) => args[i - 1] === "-f" ? x.split(/=(.*)/s).slice(0, 2) : null).filter(Boolean));
    w.calls.push(`${method} ${p.replace(`repos/${REPO}/`, "")}`);
    const head = () => w.heads[w.heads.length - 1];
    if (method === "POST" && /\/pulls$/.test(p)) { w.pr = f; return JSON.stringify({ number: 7 }); }
    let m;
    if ((m = p.match(/commits\/([^/]+)\/check-runs/))) {
      w.checkReads[m[1]] = (w.checkReads[m[1]] || 0) + 1;
      const c = w.checks(m[1], w.t, w.checkReads[m[1]]);
      return JSON.stringify({ check_runs: c.verify.map(([status, conclusion, app, sha]) => ({ name: "verify", status, conclusion,
        app: { slug: app || "github-actions" }, head_sha: sha || m[1] })).concat([{ name: "evaluate", status: "completed", conclusion: "success", app: { slug: "github-actions" }, head_sha: m[1] }]) });
    }
    if ((m = p.match(/commits\/([^/]+)\/statuses/))) {
      const c = w.checks(m[1], w.t, w.checkReads[m[1]] || 0);
      const list = c.statuses || (c.policy ? [{ context: "publication-policy", state: c.policy, description: "x", creator: { login: c.policyCreator || "github-actions[bot]" } }] : []);
      return JSON.stringify(list);
    }
    if (method === "GET" && /\/pulls\/7$/.test(p)) {
      const r = w.mergeable(head(), w.t);
      const st = typeof r === "string" ? r : r.state;
      const mergeable = typeof r === "object" && "mergeable" in r ? r.mergeable : st === "unknown" ? null : ["clean", "has_hooks", "unstable"].includes(st);
      return JSON.stringify({ state: (typeof r === "object" && r.prState) || "open", draft: typeof r === "object" && !!r.draft,
        head: { sha: head() }, mergeable_state: st, mergeable });
    }
    if ((m = p.match(/compare\/([^.]+)\.\.\.(.+)$/))) {
      w.compares.push(p);
      return JSON.stringify({ status: "ahead", behind_by: 0, ...(o.compare ? o.compare(m[2], w.t) : {}) });
    }
    if (method === "PUT" && /update-branch$/.test(p)) { w.heads.push(`h${w.heads.length + 1}`); return "{}"; }
    if (method === "PUT" && /\/merge$/.test(p)) { const r = w.mergeImpl(f.sha); w.merged = { ...f }; if (r instanceof Error) throw r; return JSON.stringify(r); }
    if (method === "POST" && /comments$/.test(p)) { if (o.commentFails) throw new Error("HTTP 403"); w.comments.push(f.body); return "{}"; }
    if (method === "PATCH" && /\/pulls\/7$/.test(p)) { w.closed = f.state === "closed"; return "{}"; }
    if (/contents\/observatory\/latest\.json\?ref=/.test(p)) { assert.equal(opt && opt.raw, true); return w.expected; }
    if (/pages\/builds\/latest$/.test(p)) return JSON.stringify(w.pages(pagesN++));
    throw new Error("unexpected gh call " + method + " " + p);
  };
  w.deps = {
    gh: (args, opt) => route(args, opt),
    git: (args) => {
      w.gitCalls.push(args.join(" "));
      if (args[0] === "status") return o.noChange ? "" : " M observatory/latest.json\n";
      if (args[0] === "rev-parse") return "h1\n";
      return "";
    },
    fetchBytes: async () => w.live(liveN++),
    sleep: async (ms) => { w.t += ms; },
    log: () => {},
    readFile: (p) => p === "CNAME" ? "spamcrackers.com\n" : LATEST.toString(),
    now: () => w.t,
  };
  return w;
}
const ENV = { GITHUB_REPOSITORY: REPO, GITHUB_RUN_ID: "4242", DEFAULT_BRANCH: "main", RUN_URL: "https://example.invalid/run" };
const LIM = { interval: 1000, checksTimeout: 60000, readyTimeout: 20000, pagesTimeout: 30000, liveTimeout: 30000 };

test("publish: happy path -> PR, both checks, merge pinned to the verified head, deployed bytes match", async () => {
  const w = fakeWorld();
  const r = await publish(ENV, w.deps, LIM);
  assert.equal(r.published, true); assert.equal(r.mergeSha, "m1");
  assert.equal(r.sha256, crypto.createHash("sha256").update(LATEST).digest("hex"));
  assert.deepEqual(w.merged, { sha: "h1", merge_method: "squash", commit_title: `Observatory: weekly measurement ${D} (#7)` });
  assert.deepEqual({ head: w.pr.head, base: w.pr.base }, { head: `observatory/${D}-4242`, base: "main" });
  assert.ok(w.calls.indexOf("PUT pulls/7/merge") > w.calls.indexOf("GET commits/h1/statuses?per_page=100"), "merge only after checks");
  assert.equal(w.closed, false);
});

test("publish: only ever pushes the observatory/ branch, never the base branch", async () => {
  const w = fakeWorld();
  await publish(ENV, w.deps, LIM);
  const pushes = w.gitCalls.filter((c) => c.startsWith("push"));
  assert.deepEqual(pushes, [`push origin HEAD:refs/heads/observatory/${D}-4242`]);
});

test("publish: no change -> no branch, no PR, no merge", async () => {
  const w = fakeWorld({ noChange: true });
  const r = await publish(ENV, w.deps, LIM);
  assert.equal(r.published, false); assert.deepEqual(w.calls, []);
  assert.ok(!w.gitCalls.some((c) => /^(push|commit|checkout)/.test(c)));
});

const preMergeFailures = [
  ["verify fails", { checks: () => ({ verify: [["completed", "failure"]], policy: "success" }) }, /verify check concluded "failure"/],
  ["one of two verify runs fails", { checks: () => ({ verify: [["completed", "success"], ["completed", "cancelled"]], policy: "success" }) }, /"cancelled"/],
  ["publication-policy fails", { checks: () => ({ verify: [["completed", "success"]], policy: "failure" }) }, /publication-policy is failure/],
  ["checks never complete", { checks: () => ({ verify: [["in_progress", null]], policy: "pending" }) }, /timed out waiting for verify \+ publication-policy/],
  ["policy status never appears", { checks: () => ({ verify: [["completed", "success"]], policy: null }) }, /timed out/],
  ["no verify run ever appears", { checks: () => ({ verify: [], policy: "success" }) }, /timed out/],
  ["PR conflicts with base", { mergeable: () => "dirty" }, /conflicts/],
  ["base keeps moving", { mergeable: () => "behind" }, /gave up after 3 updates/],
  ["merge refused by the ruleset", { merge: () => new Error("HTTP 405: Required status check is expected") }, /405/],
  ["merge returns merged:false", { merge: () => ({ merged: false, message: "Base branch was modified" }) }, /merge refused/],
];
for (const [label, o, re] of preMergeFailures) {
  test(`publish: ${label} -> NOT published, PR closed, nonzero`, async () => {
    const w = fakeWorld(o);
    await assert.rejects(publish(ENV, w.deps, LIM), (e) => /^NOT published: /.test(e.message) && re.test(e.message));
    assert.equal(w.closed, true); assert.match(w.comments[0], /nothing was merged/);
    if (!/merge/.test(label)) assert.equal(w.merged, null, "must not attempt the merge");
    assert.ok(!w.calls.some((c) => /pages/.test(c)));
  });
}

test("publish: aborted PR is closed even if the explanatory comment cannot be posted", async () => {
  const w = fakeWorld({ commentFails: true, checks: () => ({ verify: [["completed", "failure"]], policy: "success" }) });
  await assert.rejects(publish(ENV, w.deps, LIM), /NOT published: verify check concluded "failure"/);
  assert.equal(w.closed, true); assert.equal(w.merged, null);
});

test("publish: behind -> update branch -> re-verify the NEW head -> merge pinned to the new head", async () => {
  const w = fakeWorld({
    mergeable: (h) => h === "h1" ? "behind" : "clean",
    checks: (sha) => ({ verify: [["completed", "success"]], policy: "success", _sha: sha }),
  });
  const r = await publish(ENV, w.deps, LIM);
  assert.equal(r.published, true); assert.equal(r.head, "h2");
  assert.equal(w.merged.sha, "h2");
  assert.ok(w.calls.includes("GET commits/h2/check-runs?per_page=100") && w.calls.includes("GET commits/h2/statuses?per_page=100"));
  assert.ok(w.calls.indexOf("GET commits/h2/statuses?per_page=100") < w.calls.indexOf("PUT pulls/7/merge"));
});

test("publish: updated head that fails policy is never merged", async () => {
  const w = fakeWorld({
    mergeable: (h) => h === "h1" ? "behind" : "clean",
    checks: (sha) => ({ verify: [["completed", "success"]], policy: sha === "h1" ? "success" : "failure" }),
  });
  await assert.rejects(publish(ENV, w.deps, LIM), /NOT published: publication-policy is failure on h2/);
  assert.equal(w.merged, null); assert.equal(w.closed, true);
});

test("publish: PR head moved by someone else -> NOT published", async () => {
  const w = fakeWorld();
  w.heads.push("intruder");
  await assert.rejects(publish(ENV, w.deps, LIM), /NOT published: .*head moved/);
  assert.equal(w.merged, null);
});

test("publish: Pages build errored -> merged but deployment NOT confirmed (nonzero)", async () => {
  const w = fakeWorld({ pages: () => ({ commit: "m1", status: "errored" }) });
  await assert.rejects(publish(ENV, w.deps, LIM), /merged as m1 but the Pages build errored; deployment NOT confirmed/);
  assert.equal(w.closed, false);
});

test("publish: no Pages build for the merge commit -> nonzero", async () => {
  const w = fakeWorld({ pages: () => ({ commit: "older", status: "built" }) });
  await assert.rejects(publish(ENV, w.deps, LIM), /no completed Pages build for it/);
});

test("publish: deployed latest.json differs by ONE byte (same dates) -> nonzero", async () => {
  const tampered = Buffer.from(LATEST); tampered[tampered.length - 2] ^= 1; // same measuredDate/generated text, different bytes
  assert.equal(JSON.parse(LATEST).generated, JSON.parse(LATEST.toString()).generated);
  const w = fakeWorld({ live: () => tampered });
  await assert.rejects(publish(ENV, w.deps, LIM), /deployed latest\.json sha256 [0-9a-f]{64} != [0-9a-f]{64}; deployment NOT confirmed/);
});

test("publish: stale CDN copy first, then the new bytes -> succeeds after retry", async () => {
  const old = Buffer.from(JSON.stringify({ measuredDate: "2026-11-02" }));
  const w = fakeWorld({ live: (n) => (n < 3 ? old : LATEST) });
  const r = await publish(ENV, w.deps, LIM);
  assert.equal(r.published, true);
});

test("publish: live fetch errors until timeout -> nonzero", async () => {
  const w = fakeWorld({ live: () => { throw new Error("HTTP 503"); } });
  await assert.rejects(publish(ENV, w.deps, LIM), /sha256 error: HTTP 503/);
});

test("publish: canary base -> merged into observatory-canary, Pages not touched", async () => {
  const w = fakeWorld();
  const r = await publish({ ...ENV, PUBLISH_BASE: "observatory-canary" }, w.deps, LIM);
  assert.equal(r.published, "canary"); assert.equal(w.pr.base, "observatory-canary");
  assert.ok(!w.calls.some((c) => /pages|contents/.test(c)));
});

// =========================================================================
// 5. policy CLI end to end (the code publication-policy.yml runs), stub gh
// =========================================================================
const { spawnSync } = require("child_process");
const os = require("os");
function runPolicyCli(fixture) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "policy-cli-"));
  fs.mkdirSync(path.join(dir, "bin"));
  fs.writeFileSync(path.join(dir, "fixture.json"), JSON.stringify(fixture));
  // stub gh: answers only the read endpoints the policy is allowed to use, logs every call
  fs.writeFileSync(path.join(dir, "bin/gh"), `#!${process.execPath}
const fs = require("fs"), dir = ${JSON.stringify(dir)};
const args = process.argv.slice(2); fs.appendFileSync(dir + "/calls", JSON.stringify(args) + "\\n");
const fx = JSON.parse(fs.readFileSync(dir + "/fixture.json", "utf8"));
const p = args.find((a) => a.startsWith("repos/")) || "";
const out = (o) => process.stdout.write(typeof o === "string" ? o : JSON.stringify(o));
let m;
if (args.includes("-X")) { process.exit(0); }                       // the status POST
if (/\\/pulls\\/7$/.test(p)) out(fx.pull);
else if (/\\/compare\\//.test(p)) out({ merge_base_commit: { sha: "mb" }, files: fx.files });
else if ((m = p.match(/\\/contents\\/(.+)\\?ref=(.+)$/))) { const c = (fx.contents[m[2]] || {})[m[1]]; if (c == null) process.exit(1); out(c); }
else if (/\\/actions\\/runs\\//.test(p)) out(fx.run);
else { process.stderr.write("forbidden call " + p); process.exit(2); }
`);
  fs.chmodSync(path.join(dir, "bin/gh"), 0o755);
  const r = spawnSync(process.execPath, [path.join(ROOT, "scripts/publication-policy.js")], { encoding: "utf8",
    env: { ...process.env, PATH: path.join(dir, "bin") + path.delimiter + process.env.PATH, REPO, PR_NUMBER: "7",
      BOT_LOGIN: "spamcrackers-observatory[bot]", RUN_URL: "https://example.invalid/r" } });
  const calls = fs.readFileSync(path.join(dir, "calls"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  fs.rmSync(dir, { recursive: true });
  return { status: r.status, out: r.stdout + r.stderr, calls };
}
const genuineFixture = (files, extraHead = {}) => ({
  pull: { head: { sha: "hs", ref: `observatory/${D}-4242`, repo: { full_name: REPO } }, base: { sha: "bs", repo: { full_name: REPO, default_branch: "main" } },
    user: { login: "spamcrackers-observatory[bot]", type: "Bot" }, changed_files: files.length },
  files,
  contents: {
    mb: { "observatory/latest.json": JSON.stringify({ measuredDate: BASE_D }), "catalog.json": JSON.stringify(baseCatalog) },
    hs: { "observatory/latest.json": JSON.stringify({ measuredDate: D }), [`observatory/history/${D}.json`]: JSON.stringify({ measuredDate: D }),
      [`observatory/evidence/${D}.json`]: JSON.stringify({ measuredDate: D }), "catalog.json": headCatalog(), ...extraHead },
  },
  run: { path: ".github/workflows/observe.yml", event: "schedule", status: "in_progress", head_branch: "main" },
});
const statusPost = (calls) => calls.find((c) => c.includes("-X"));
const field = (call, k) => (call.find((x) => x.startsWith(k + "=")) || "").slice(k.length + 1);

test("policy CLI: genuine publication -> posts success on the exact head SHA", () => {
  const r = runPolicyCli(genuineFixture(plus({ filename: "catalog.json", status: "modified" })));
  assert.equal(r.status, 0, r.out);
  const post = statusPost(r.calls);
  assert.ok(post.includes(`repos/${REPO}/statuses/hs`));
  assert.equal(field(post, "state"), "success"); assert.equal(field(post, "context"), "publication-policy");
});

test("policy CLI: App PR replacing the policy with an always-pass version is still evaluated by the BASE policy -> failure", () => {
  const evil = "#!/usr/bin/env node\nprocess.exit(0); // always pass\n";
  const r = runPolicyCli(genuineFixture(plus({ filename: "scripts/publication-policy.js", status: "modified" }),
    { "scripts/publication-policy.js": evil }));
  assert.equal(r.status, 1, r.out);
  const post = statusPost(r.calls);
  assert.ok(post.includes(`repos/${REPO}/statuses/hs`));
  assert.equal(field(post, "state"), "failure");
  assert.match(field(post, "description"), /scripts\/publication-policy\.js .* not an approved measurement artifact/);
  // the PR-head version of any script is never even fetched, let alone executed
  assert.ok(!r.calls.some((c) => c.some((a) => /contents\/scripts\//.test(a))), JSON.stringify(r.calls));
});

test("policy CLI: App PR weakening verify.js -> failure status, so the required check blocks the merge", () => {
  const r = runPolicyCli(genuineFixture(plus({ filename: "scripts/verify.js", status: "modified" }),
    { "scripts/verify.js": "process.exit(0)" }));
  assert.equal(r.status, 1);
  assert.equal(field(statusPost(r.calls), "state"), "failure");
});

test("policy CLI: only read endpoints plus one status POST are used", () => {
  const r = runPolicyCli(genuineFixture(plus()));
  const writes = r.calls.filter((c) => c.includes("-X"));
  assert.equal(writes.length, 1);
  assert.deepEqual(writes[0].slice(0, 4), ["api", "-X", "POST", `repos/${REPO}/statuses/hs`]);
  for (const c of r.calls.filter((c) => !c.includes("-X")))
    assert.match(c.find((a) => a.startsWith("repos/")), /\/(pulls\/7|compare\/bs\.\.\.hs\?|contents\/observatory\/|contents\/catalog\.json|actions\/runs\/4242)/);
});


// =========================================================================
// 6. merge readiness: transient/blocked states, up-to-date proof, check provenance
// =========================================================================
const noMerge = (w) => { assert.equal(w.merged, null, "must not attempt the merge"); assert.equal(w.closed, true); };

test("ready: 'unknown' while GitHub computes mergeability, then clean -> merges", async () => {
  const w = fakeWorld({ mergeable: (h, t) => (t < 3000 ? "unknown" : "clean") });
  const r = await publish(ENV, w.deps, LIM);
  assert.equal(r.published, true); assert.equal(w.merged.sha, "h1");
});

test("ready: 'unknown' forever -> bounded, NOT published", async () => {
  const w = fakeWorld({ mergeable: () => "unknown" });
  await assert.rejects(publish(ENV, w.deps, LIM), /NOT published: PR stayed "unknown" for 20s/);
  noMerge(w);
});

test("ready: 'blocked' briefly after checks pass (ruleset catching up), then clean -> merges", async () => {
  const w = fakeWorld({ mergeable: (h, t) => (t < 2000 ? "blocked" : "clean") });
  assert.equal((await publish(ENV, w.deps, LIM)).published, true);
});

test("ready: 'blocked' persistently despite green checks -> NOT published", async () => {
  const w = fakeWorld({ mergeable: () => "blocked" });
  await assert.rejects(publish(ENV, w.deps, LIM), /PR stayed "blocked"/);
  noMerge(w);
});

test("ready: 'clean' but mergeable still null -> waits, then merges when computed", async () => {
  const w = fakeWorld({ mergeable: (h, t) => ({ state: "clean", mergeable: t < 2000 ? null : true }) });
  assert.equal((await publish(ENV, w.deps, LIM)).published, true);
});

for (const [label, state, re] of [
  ["unstable (a non-required check failing)", "unstable", /mergeable_state unstable/],
  ["an unrecognised state", "weird", /unexpected mergeable_state "weird"/],
  ["'clean' with mergeable=false", { state: "clean", mergeable: false }, /unexpected mergeable_state "clean" \(mergeable=false\)/],
  ["a draft PR", { state: "clean", draft: true }, /PR is a draft/],
  ["a PR closed by someone else", { state: "clean", prState: "closed" }, /PR is closed, not open/],
]) {
  test(`ready: ${label} -> fail closed, NOT published`, async () => {
    const w = fakeWorld({ mergeable: () => state });
    await assert.rejects(publish(ENV, w.deps, LIM), re);
    noMerge(w);
  });
}

test("ready: mergeable_state says clean but compare shows the base moved -> update, re-verify, merge NEW head", async () => {
  const w = fakeWorld({ compare: (sha) => ({ behind_by: sha === "h1" ? 1 : 0 }) });
  const r = await publish(ENV, w.deps, LIM);
  assert.equal(r.head, "h2"); assert.equal(w.merged.sha, "h2");
  assert.ok(w.calls.includes("PUT pulls/7/update-branch"));
  assert.ok(w.calls.lastIndexOf("GET commits/h2/statuses?per_page=100") < w.calls.indexOf("PUT pulls/7/merge"));
});

test("ready: the merge is only attempted after a compare proves behind_by == 0 for the exact head", async () => {
  const w = fakeWorld();
  await publish(ENV, w.deps, LIM);
  assert.deepEqual(w.compares, [`repos/${REPO}/compare/main...h1`]);
  assert.ok(w.calls.indexOf("GET compare/main...h1") < w.calls.indexOf("PUT pulls/7/merge"));
});

test("ready: compare reports a diverged/identical branch -> NOT published", async () => {
  const w = fakeWorld({ compare: () => ({ status: "diverged", behind_by: 0 }) });
  await assert.rejects(publish(ENV, w.deps, LIM), /unexpected comparison with main: diverged/);
  noMerge(w);
});

test("checks: a 'verify' check from another app counts as tampering -> NOT published", async () => {
  const w = fakeWorld({ checks: () => ({ verify: [["completed", "success", "evil-ci"]], policy: "success" }) });
  await assert.rejects(publish(ENV, w.deps, LIM), /not produced by GitHub Actions for that SHA/);
  noMerge(w);
});

test("checks: a stale 'verify' result for a different SHA -> NOT published", async () => {
  const w = fakeWorld({ checks: () => ({ verify: [["completed", "success", "github-actions", "old-head"]], policy: "success" }) });
  await assert.rejects(publish(ENV, w.deps, LIM), /not produced by GitHub Actions for that SHA/);
  noMerge(w);
});

test("checks: publication-policy status posted by a non-Actions identity -> NOT published", async () => {
  const w = fakeWorld({ checks: () => ({ verify: [["completed", "success"]], policy: "success", policyCreator: "spamcrackers-observatory[bot]" }) });
  await assert.rejects(publish(ENV, w.deps, LIM), /publication-policy status .* not posted by GitHub Actions/);
  noMerge(w);
});

test("checks: only the NEWEST publication-policy status counts (older success, newer failure)", async () => {
  const w = fakeWorld({ checks: () => ({ verify: [["completed", "success"]], statuses: [
    { context: "publication-policy", state: "failure", description: "rejected", creator: { login: "github-actions[bot]" } },
    { context: "publication-policy", state: "success", description: "old", creator: { login: "github-actions[bot]" } }] }) });
  await assert.rejects(publish(ENV, w.deps, LIM), /publication-policy is failure/);
  noMerge(w);
});

test("checks: a re-run that fails after readiness is caught by the re-confirmation right before merging", async () => {
  // read #1 (wait for checks) succeeds; read #2 is the pre-merge re-confirmation and sees a failed re-run
  const w = fakeWorld({ checks: (sha, t, n) => ({ verify: [["completed", n >= 2 ? "failure" : "success"]], policy: "success" }) });
  await assert.rejects(publish(ENV, w.deps, LIM), /NOT published: verify check concluded "failure"/);
  noMerge(w);
});

// =========================================================================
// 7. policy: file enumeration must be provably complete (fail closed)
// =========================================================================
test("policy: automated PR with a truncated file enumeration -> rejected", () => {
  const r = scenario({ enumeration: { complete: false, expected: 4 } });
  assert.equal(r.ok, false); assert.ok(r.violations.some((m) => /enumeration truncated/.test(m)));
});

test("policy: automated PR whose enumerated count differs from the PR's changed_files -> rejected", () => {
  const r = scenario({ enumeration: { complete: true, expected: 5 } });
  assert.equal(r.ok, false); assert.ok(r.violations.some((m) => /4 enumerated, PR reports 5/.test(m)));
});

test("policy: complete enumeration with a matching count is accepted", () => {
  assert.equal(scenario({ enumeration: { complete: true, expected: 4 } }).ok, true);
});

test("policy CLI: compare response without a file list -> failure status (fail closed)", () => {
  const fx = genuineFixture(plus({ filename: "catalog.json", status: "modified" }));
  fx.files = null; fx.pull.changed_files = 4;
  const r = runPolicyCli(fx);
  assert.equal(r.status, 1);
  assert.equal(field(statusPost(r.calls), "state"), "failure");
  assert.match(field(statusPost(r.calls), "description"), /incomplete/);
});

test("policy CLI: PR reports more changed files than the compare enumerated -> failure status", () => {
  const fx = genuineFixture(plus({ filename: "catalog.json", status: "modified" }));
  fx.pull.changed_files = 9;
  const r = runPolicyCli(fx);
  assert.equal(r.status, 1);
  assert.equal(field(statusPost(r.calls), "state"), "failure");
});

// =========================================================================
// 8. platform prerequisites captured in the repository
// =========================================================================
test("platform: publication-policy.yml is the ONLY workflow using pull_request_target", () => {
  const users = fs.readdirSync(path.join(ROOT, ".github/workflows")).filter((n) => /pull_request_target/.test(code(wf(n))));
  assert.deepEqual(users, ["publication-policy.yml"]);
});

test("platform: every action in the publication workflows is pinned to a full commit SHA; App token = verified v3.3.0", () => {
  for (const n of ["observe.yml", "publication-policy.yml"])
    for (const m of code(wf(n)).matchAll(/^\s*(?:- )?uses: (\S+)/gm)) assert.match(m[1], /@[0-9a-f]{40}$/, `${n}: ${m[1]}`);
  assert.match(wf("observe.yml"), /uses: actions\/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510/);
});

test("platform: the App token is down-scoped to exactly the permissions the publisher uses", () => {
  const y = code(wf("observe.yml"));
  const perms = [...y.matchAll(/^\s+permission-([a-z-]+): (\w+)$/gm)].map((m) => `${m[1]}:${m[2]}`).sort();
  assert.deepEqual(perms, ["checks:read", "contents:write", "pages:read", "pull-requests:write", "statuses:read"]);
  assert.match(y, /client-id: \$\{\{ vars\.OBSERVATORY_APP_CLIENT_ID \}\}/);
});
