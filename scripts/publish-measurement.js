#!/usr/bin/env node
/*
 * SpamCrackers Observatory — PR-based publication (Issue #44).
 *
 * Runs in the scheduled `observatory` job after observe.js and verify.js have
 * passed, with a GitHub App installation token (GH_TOKEN). It never pushes to
 * the base branch. Instead it:
 *
 *  1. commits the measurement to observatory/<date>-<run id> and opens a PR;
 *  2. waits until, on that exact head SHA, every "verify" check run succeeded
 *     and the trusted "publication-policy" status is success (if the branch is
 *     behind, it updates it once per attempt, max 3, and waits again);
 *  3. merges with a squash merge pinned to that verified head SHA (the ruleset
 *     on the base branch independently enforces the same requirements);
 *  4. for the production base branch, waits for the GitHub Pages build of the
 *     merge commit and requires the deployed latest.json to be byte-identical
 *     (SHA-256) to latest.json in the merge commit.
 *
 * Any failure before the merge closes the PR (nothing reaches the base branch)
 * and exits nonzero. A failure after the merge exits nonzero and states that
 * the record is merged but its deployment is unconfirmed. Success is reported
 * only after the deployed bytes match.
 *
 * All I/O goes through injectable deps so scripts/test/publication.test.js can
 * exercise every path offline and deterministically.
 */
"use strict";
const crypto = require("crypto");

const PATHS = ["observatory/latest.json", "observatory/history", "observatory/evidence", "catalog.json"];
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

class PublishError extends Error {}

async function publish(env, deps, limits = {}) {
  const L = { interval: 15000, checksTimeout: 20 * 60000, readyTimeout: 5 * 60000, pagesTimeout: 10 * 60000, liveTimeout: 10 * 60000, maxUpdates: 3, ...limits };
  const { gh, git, fetchBytes, sleep, log, readFile, now } = deps;
  const R = env.GITHUB_REPOSITORY;
  const base = env.PUBLISH_BASE || "main";
  const production = base === (env.DEFAULT_BRANCH || "main");
  const json = (args) => JSON.parse(gh(args));

  if (!git(["status", "--porcelain", "--", ...PATHS]).trim()) {
    log("No change in measurements — nothing to publish.");
    return { published: false, reason: "no-change" };
  }
  const D = JSON.parse(readFile("observatory/latest.json")).measuredDate;
  const branch = `observatory/${D}-${env.GITHUB_RUN_ID}`;
  const title = `Observatory: weekly measurement ${D}`;

  git(["checkout", "-b", branch]);
  git(["add", "--", ...PATHS]);
  git(["-c", `user.name=${env.BOT_NAME || "spamcrackers-observatory[bot]"}`, "-c", `user.email=${env.BOT_EMAIL || "observatory@spamcrackers.com"}`,
    "commit", "-m", title]);
  git(["push", "origin", `HEAD:refs/heads/${branch}`]);
  let head = git(["rev-parse", "HEAD"]).trim();
  const pr = json(["-X", "POST", `repos/${R}/pulls`, "-f", `title=${title}`, "-f", `head=${branch}`, "-f", `base=${base}`,
    "-f", `body=Automated Observatory publication from ${env.RUN_URL || "the observatory workflow"}.\n\nMerged only after \`verify\` and \`publication-policy\` pass on the exact head SHA.`]).number;
  log(`Opened PR #${pr} (${branch} -> ${base}) at ${head}`);

  // A result only counts if GitHub Actions produced it for this exact SHA. A
  // "verify" check from any other app, or a publication-policy status posted
  // by anyone but GitHub Actions, is treated as tampering: fail closed.
  const checksFor = (sha) => {
    const runs = json([`repos/${R}/commits/${sha}/check-runs?per_page=100`]).check_runs.filter((c) => c.name === "verify");
    const alien = runs.find((c) => !c.app || c.app.slug !== "github-actions" || c.head_sha !== sha);
    if (alien) throw new PublishError(`a "verify" check on ${sha} was not produced by GitHub Actions for that SHA`);
    const pol = json([`repos/${R}/commits/${sha}/statuses?per_page=100`]).filter((x) => x.context === "publication-policy")[0] || null; // newest first
    if (pol && (!pol.creator || pol.creator.login !== "github-actions[bot]"))
      throw new PublishError(`the latest publication-policy status on ${sha} was not posted by GitHub Actions`);
    const bad = runs.find((c) => c.status === "completed" && c.conclusion !== "success");
    if (bad) throw new PublishError(`verify check concluded "${bad.conclusion}" on ${sha}`);
    if (pol && (pol.state === "failure" || pol.state === "error")) throw new PublishError(`publication-policy is ${pol.state} on ${sha}: ${pol.description || ""}`);
    return runs.length > 0 && runs.every((c) => c.status === "completed") && !!pol && pol.state === "success";
  };
  const waitForChecks = async (sha) => {
    const deadline = now() + L.checksTimeout;
    while (!checksFor(sha)) {
      if (now() >= deadline) throw new PublishError(`timed out waiting for verify + publication-policy on ${sha}`);
      await sleep(L.interval);
    }
  };

  // Merge readiness. GitHub computes mergeability asynchronously, so "unknown"
  // and a briefly "blocked" PR are polled for a bounded time; every other
  // non-ready state fails closed. "ready" additionally requires the branch to
  // contain the base tip (behind_by 0): then the squash result is exactly the
  // head tree, so the head-SHA checks ARE the checks of what gets merged (not
  // a stale test-merge commit against an older base).
  const READY = new Set(["clean", "has_hooks"]);
  const TRANSIENT = new Set(["unknown", "blocked"]);
  const waitForMergeable = async (sha) => {
    const deadline = now() + L.readyTimeout;
    for (;;) {
      const pull = json([`repos/${R}/pulls/${pr}`]);
      const st = pull.mergeable_state;
      if (pull.state !== "open") throw new PublishError(`PR is ${pull.state}, not open`);
      if (pull.head.sha !== sha) throw new PublishError(`PR head moved from ${sha} to ${pull.head.sha} outside this job`);
      if (pull.draft) throw new PublishError("PR is a draft");
      if (st === "dirty") throw new PublishError("PR conflicts with the base branch");
      if (st === "behind") return "behind";
      if (st === "unstable") throw new PublishError("a non-required check is failing on the PR (mergeable_state unstable)");
      if (READY.has(st) && pull.mergeable === true) {
        const cmp = json([`repos/${R}/compare/${base}...${sha}`]);
        if (cmp.behind_by !== 0) return "behind";
        if (cmp.status !== "ahead") throw new PublishError(`unexpected comparison with ${base}: ${cmp.status}`);
        return "ready";
      }
      if (!TRANSIENT.has(st) && !(READY.has(st) && pull.mergeable === null))
        throw new PublishError(`unexpected mergeable_state "${st}" (mergeable=${pull.mergeable})`);
      if (now() >= deadline) throw new PublishError(`PR stayed "${st}" for ${L.readyTimeout / 1000}s after its checks passed`);
      await sleep(L.interval);
    }
  };

  let mergeSha;
  try {
    for (let updates = 0; ; ) {
      await waitForChecks(head);
      if ((await waitForMergeable(head)) === "ready") {
        if (!checksFor(head)) throw new PublishError(`checks on ${head} are no longer all successful`); // re-confirm right before merging
        break;
      }
      if (++updates > L.maxUpdates) throw new PublishError(`base branch kept moving; gave up after ${L.maxUpdates} updates`);
      log(`PR #${pr} is behind ${base}; updating the branch (attempt ${updates}) and re-verifying.`);
      gh(["-X", "PUT", `repos/${R}/pulls/${pr}/update-branch`, "-f", `expected_head_sha=${head}`]);
      const deadline = now() + L.checksTimeout;
      for (;;) {
        const h = json([`repos/${R}/pulls/${pr}`]).head.sha;
        if (h !== head) { head = h; break; }
        if (now() >= deadline) throw new PublishError("timed out waiting for the updated branch");
        await sleep(L.interval);
      }
    }
    const m = json(["-X", "PUT", `repos/${R}/pulls/${pr}/merge`, "-f", `sha=${head}`, "-f", "merge_method=squash",
      "-f", `commit_title=${title} (#${pr})`]);
    if (!m.merged || !m.sha) throw new PublishError(`merge refused: ${m.message || "unknown"}`);
    mergeSha = m.sha;
  } catch (e) {
    // close first; the explanatory comment is best-effort and independent
    try { gh(["-X", "PATCH", `repos/${R}/pulls/${pr}`, "-f", "state=closed"]); }
    catch (closeErr) { log(`warning: could not close PR #${pr}: ${closeErr.message}`); }
    try { gh(["-X", "POST", `repos/${R}/issues/${pr}/comments`, "-f", `body=Publication aborted, nothing was merged: ${e.message}`]); }
    catch (commentErr) { log(`warning: could not comment on PR #${pr}: ${commentErr.message}`); }
    throw new PublishError(`NOT published: ${e.message}`);
  }
  log(`Merged PR #${pr} at verified head ${head} -> ${mergeSha}`);

  if (!production) {
    log(`Canary base "${base}": merge verified; Pages deployment check skipped (Pages serves the default branch only).`);
    return { published: "canary", pr, head, mergeSha };
  }

  // the deployed record must be byte-identical to the merged one
  const expected = Buffer.from(gh([`repos/${R}/contents/observatory/latest.json?ref=${mergeSha}`], { raw: true }));
  const want = sha256(expected);
  let deadline = now() + L.pagesTimeout;
  for (;;) {
    const b = json([`repos/${R}/pages/builds/latest`]);
    if (b.commit === mergeSha && b.status === "built") break;
    if (b.commit === mergeSha && b.status === "errored") throw new PublishError(`merged as ${mergeSha} but the Pages build errored; deployment NOT confirmed`);
    if (now() >= deadline) throw new PublishError(`merged as ${mergeSha} but no completed Pages build for it; deployment NOT confirmed`);
    await sleep(L.interval);
  }
  const host = readFile("CNAME").trim();
  const url = `https://${host}/observatory/latest.json?v=${mergeSha}`;
  deadline = now() + L.liveTimeout;
  let got = null;
  for (;;) {
    try { got = sha256(await fetchBytes(url)); } catch (e) { got = `error: ${e.message}`; }
    if (got === want) break;
    if (now() >= deadline) throw new PublishError(`merged as ${mergeSha} but deployed latest.json sha256 ${got} != ${want}; deployment NOT confirmed`);
    await sleep(L.interval);
  }
  log(`Published: PR #${pr}, merge ${mergeSha}, deployed latest.json sha256 ${want} matches.`);
  return { published: true, pr, head, mergeSha, sha256: want };
}

/* ---------------- CLI (observatory workflow) ---------------- */
function realDeps() {
  const { execFileSync } = require("child_process");
  const fs = require("fs");
  const https = require("https");
  return {
    gh: (args, o = {}) => execFileSync("gh", ["api", ...(o.raw ? ["-H", "Accept: application/vnd.github.raw"] : []), ...args],
      { encoding: o.raw ? "buffer" : "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "inherit"] }),
    git: (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }),
    fetchBytes: (url) => new Promise((resolve, reject) => {
      https.get(url, { headers: { "cache-control": "no-cache", "user-agent": "spamcrackers-observatory-publisher" }, timeout: 15000 }, (r) => {
        if (r.statusCode !== 200) { r.resume(); return reject(new Error(`HTTP ${r.statusCode}`)); }
        const parts = []; r.on("data", (c) => parts.push(c)); r.on("end", () => resolve(Buffer.concat(parts))); r.on("error", reject);
      }).on("timeout", function () { this.destroy(new Error("timeout")); }).on("error", reject);
    }),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    log: (s) => console.log(s),
    readFile: (p) => fs.readFileSync(p, "utf8"),
    now: () => Date.now(),
  };
}

module.exports = { publish, PublishError, PATHS };
if (require.main === module) {
  publish(process.env, realDeps()).then((r) => {
    if (process.env.GITHUB_STEP_SUMMARY) require("fs").appendFileSync(process.env.GITHUB_STEP_SUMMARY, "```\n" + JSON.stringify(r, null, 2) + "\n```\n");
  }, (e) => { console.error(`::error::${e.message}`); process.exit(1); });
}
