// Tests for commit-identity-gate.mjs.
//
// The fixtures use INVENTED addresses ("dev@zorpco.example", "jane@example.com"), never the real
// ones. A test that spelled the leaked domain would republish it in the file that exists to keep
// it out — the same rule naming-gate.test.mjs follows for names.

import { test } from "node:test";
import assert from "node:assert/strict";

import { identityErrors, parseCommits, logArgs } from "./commit-identity-gate.mjs";

const commit = (sha, author, committer = author) => ({ sha, author, committer });

const NOREPLY = "1234567+octocat@users.noreply.github.com";

test("a GitHub no-reply identity passes on both fields", () => {
  assert.deepEqual(identityErrors([commit("a".repeat(40), NOREPLY)]), []);
});

test("GitHub's own committer is accepted, or the merge queue would fail its own merge commit", () => {
  // A squash, a web edit and a merge-queue entry all commit as this address.
  assert.deepEqual(identityErrors([commit("b".repeat(40), NOREPLY, "noreply@github.com")]), []);
});

test("a bot's no-reply address needs no special case", () => {
  const bots = [
    "49699333+dependabot[bot]@users.noreply.github.com",
    "41898282+github-actions[bot]@users.noreply.github.com",
  ];
  for (const bot of bots) {
    assert.deepEqual(identityErrors([commit("c".repeat(40), bot, "noreply@github.com")]), []);
  }
});

test("an employer domain fails, and the address never reaches the report", () => {
  const out = identityErrors([commit("d1e2f3a4" + "0".repeat(32), "dev@zorpco.example")]);
  assert.deepEqual(out, [
    "commit d1e2f3a4: author email is not a GitHub no-reply address",
    "commit d1e2f3a4: committer email is not a GitHub no-reply address",
  ]);
  // The whole point of the redaction: CI logs are public, so a rejected address — which is by
  // definition one this repository should not publish — must not survive into the failure.
  assert.doesNotMatch(out.join("\n"), /zorpco|@/);
});

test("author and committer are judged separately", () => {
  // The case a rebase produces: rewriting the committer leaves the original author in place.
  assert.deepEqual(identityErrors([commit("e".repeat(40), "jane@example.com", NOREPLY)]), [
    "commit eeeeeeee: author email is not a GitHub no-reply address",
  ]);
});

test("a personal address is not a pass just because it is not an employer's", () => {
  // The allowlist is the point: anything but a GitHub no-reply address is rejected, so the next
  // contributor's domain cannot leak the way this one did.
  assert.equal(identityErrors([commit("f".repeat(40), "someone@gmail.com")]).length, 2);
});

test("a lookalike domain does not satisfy the suffix", () => {
  const forged = [
    "dev@users.noreply.github.com.zorpco.example",
    "dev@notusers.noreply.github.com",
    "users.noreply.github.com@zorpco.example",
  ];
  for (const address of forged) {
    assert.equal(identityErrors([commit("1".repeat(40), address, NOREPLY)]).length, 1, address);
  }
});

test("case and surrounding whitespace do not change the verdict", () => {
  assert.deepEqual(identityErrors([commit("2".repeat(40), `  ${NOREPLY.toUpperCase()}  `)]), []);
});

test("an empty identity field fails rather than passing for want of a domain", () => {
  assert.equal(identityErrors([commit("3".repeat(40), "", NOREPLY)]).length, 1);
  assert.equal(identityErrors([{ sha: "4".repeat(40), author: NOREPLY }]).length, 1);
});

test("an empty range passes", () => {
  assert.deepEqual(identityErrors([]), []);
});

test("every commit in a range is reported, not just the first", () => {
  const out = identityErrors([
    commit("aaaaaaaa" + "0".repeat(32), "dev@zorpco.example", NOREPLY),
    commit("bbbbbbbb" + "0".repeat(32), NOREPLY),
    commit("cccccccc" + "0".repeat(32), NOREPLY, "dev@zorpco.example"),
  ]);
  assert.deepEqual(out, [
    "commit aaaaaaaa: author email is not a GitHub no-reply address",
    "commit cccccccc: committer email is not a GitHub no-reply address",
  ]);
});

test("git's record format round-trips, including the trailing separator", () => {
  const output = `${"a".repeat(40)}\x1f${NOREPLY}\x1fnoreply@github.com\x1e\n${"b".repeat(40)}\x1fdev@zorpco.example\x1fdev@zorpco.example\x1e`;
  assert.deepEqual(parseCommits(output), [
    { sha: "a".repeat(40), author: NOREPLY, committer: "noreply@github.com" },
    { sha: "b".repeat(40), author: "dev@zorpco.example", committer: "dev@zorpco.example" },
  ]);
});

test("merge commits are excluded, or every pull request fails on a commit nobody can fix", () => {
  // CI checks out refs/pull/N/merge, and GitHub authors that synthetic merge commit with the BASE
  // branch's identity — pre-existing by definition, and not the contributor's to rewrite. Dropping
  // this flag rejects every pull request, including the one that introduced the gate.
  assert.ok(logArgs("abc1234").includes("--no-merges"));
  assert.ok(logArgs("abc1234").includes("abc1234..HEAD"));
});

test("the range ends at the pull request head, never at the checked-out merge ref", () => {
  // base.sha is frozen when the pull request opens and does not follow the base branch. Ending
  // the range at the merge ref therefore sweeps in every commit the base gained since — squash
  // merges included, which are ordinary commits --no-merges does NOT drop — and fails the pull
  // request on published work by other authors who cannot rewrite it.
  assert.ok(logArgs("base1", "head1").includes("base1..head1"));
  assert.ok(!logArgs("base1", "head1").some((arg) => arg.includes("HEAD")));
});

test("the tip defaults to HEAD, so a local run needs only a base", () => {
  assert.ok(logArgs("base1").includes("base1..HEAD"));
});

test("an empty log yields no commits rather than one blank record", () => {
  assert.deepEqual(parseCommits(""), []);
  assert.deepEqual(parseCommits("\n"), []);
});
