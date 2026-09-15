// Tests for naming-gate.mjs.
//
// The fixtures use INVENTED terms ("zorpco", "quill", "vantage-core"), never the real ones. A
// test file that spelled the forbidden names would defeat the point of hashing them — and
// AGENTS.md binds test fixtures exactly like everything else.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

import { namingErrors, canonicalScanRoot, messageErrors, commitMessageBody } from "./naming-gate.mjs";

const digest = (value) => createHash("sha256").update(value.toLowerCase()).digest("hex");

const TERMS = [
  { term: "zorpco", modes: ["word"] },
  { term: "vantage-core", modes: ["slug"] },
  { term: "quill", modes: ["proper", "compound"] },
  { term: "pike", modes: ["proper"] },
  { term: "north star mutual", modes: ["phrase"] },
];

// A throwaway module root carrying the synthetic term list and nothing else.
function termsRoot() {
  const root = mkdtempSync(join(tmpdir(), "naming-gate-"));
  mkdirSync(join(root, "tools"), { recursive: true });
  writeFileSync(
    join(root, "tools", "naming-terms.json"),
    JSON.stringify({
      schema: "saas.naming.terms.v1",
      terms: TERMS.map(({ term, modes }) => ({ h: digest(term), modes, note: "fixture" })),
    }),
  );
  return root;
}

// Writes `files` (relative path -> contents) into such a root and runs the tree gate over it.
function run(files, { allowlist } = {}) {
  const root = termsRoot();
  if (allowlist) {
    writeFileSync(
      join(root, "tools", "naming-allowlist.json"),
      JSON.stringify({ schema: "saas.naming.allowlist.v1", paths: allowlist }),
    );
  }
  for (const [rel, contents] of Object.entries(files)) {
    const abs = join(root, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, contents);
  }
  try {
    return namingErrors(root, root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const joined = (files, opts) => run(files, opts).join("\n");

test("word mode matches case-insensitively, anywhere in a slug", () => {
  const out = joined({
    "a.md": "Deployed for ZorpCo last week.",
    "b.md": "See zorpco-platform for the details.",
    "c.ts": 'const host = "vault.zorpco.svc:8200";',
    "d.md": "Contact alice@zorpco.ai about it.",
  });
  for (const f of ["a.md:1", "b.md:1", "c.ts:1", "d.md:1"]) assert.match(out, new RegExp(f));
});

test("word mode does not match a longer word that merely contains the term", () => {
  // The real-tree analogue: `obIngressPolicy` must not trip a four-letter org name.
  assert.deepEqual(run({ "a.go": "func zorpcoreHandler() {}\nvar Zorpcology = 1\n" }), []);
});

test("slug mode matches the whole slug, never its generic parts", () => {
  const out = joined({ "a.md": "Tracked in vantage-core#12.\n" });
  assert.match(out, /a\.md:1: forbidden name \(vantage-core\)/);
  // "vantage" and "core" on their own are ordinary words and must stay legal.
  assert.deepEqual(run({ "b.md": "The vantage point of the core service.\n" }), []);
});

test("proper mode matches a capitalised proper noun only", () => {
  assert.match(joined({ "a.md": "Quill composes this module.\n" }), /a\.md:1/);
  // Ordinary English use of the same letters — the real-tree analogue is "changed my mind".
  assert.deepEqual(run({ "b.go": '// sharpened the quill before writing\n' }), []);
  // An all-caps constant is not a proper noun — the real-tree analogue is ROUND_ROBIN.
  assert.deepEqual(run({ "c.go": 'LBPolicy: "ROUND_PIKE"\nconst PIKE = 2\n' }), []);
});

test("compound mode matches inside a multi-part slug but not as a bare word", () => {
  const out = joined({ "a.go": 'writeFixture(t, "quill-control")\n' });
  assert.match(out, /a\.go:1: forbidden name \(quill\)/);
  assert.deepEqual(run({ "b.md": "a quill and some ink\n" }), []);
});

test("proper-only terms do not leak through compound slugs", () => {
  // `pike` is proper-only, so a lowercase slug part must not match — otherwise every
  // ROUND_ROBIN-shaped constant in the tree would fail the gate.
  assert.deepEqual(run({ "a.go": 'x := "round-pike-policy"\n' }), []);
});

test("a name fused into a camelCase or PascalCase identifier is caught", () => {
  // Splitting on separators alone saw none of these: a name reaches code as an identifier far
  // more often than as prose, so every one of them used to pass while the prose form failed.
  const out = joined({
    "a.go": "type ZorpcoClient struct{}\nfunc NewZorpcoHandler() {}\n",
    "b.ts": 'const zorpcoTimeout = 5;\nconst zorpcoAPIKey = "x";\n',
  });
  for (const at of ["a\\.go:1", "a\\.go:2", "b\\.ts:1", "b\\.ts:2"]) {
    assert.match(out, new RegExp(`${at}: forbidden name`));
  }
});

test("case splitting does not fire on identifiers that merely embed the letters", () => {
  // The real-tree analogues that make case splitting risky: `obIngressPolicy` must not trip a
  // four-letter org name, a longer word containing the term is still not the term, and an
  // all-caps constant is not a proper noun.
  assert.deepEqual(
    run({
      "a.go": "func obIngressPolicy() {}\nvar zorpcoreHandler = 1\ntype Zorpcology struct{}\n",
      "b.go": 'LBPolicy: "ROUND_PIKE"\nremindUser(ctx)\n',
    }),
    [],
  );
});

test("phrase mode matches a spaced multi-word name", () => {
  const out = joined({ "a.md": "Sold to North Star Mutual in March.\n" });
  assert.match(out, /a\.md:1: forbidden name \(North Star Mutual\)/);
});

test("filenames are checked, not just contents", () => {
  const out = joined({ "docs/zorpco-integration-plan.md": "Nothing to see here.\n" });
  assert.match(out, /docs\/zorpco-integration-plan\.md: forbidden name in path \(zorpco\)/);
});

test("the reported line number points at the violation", () => {
  const out = joined({ "a.md": "clean\nclean\nZorpCo\n" });
  assert.match(out, /a\.md:3: forbidden name \(ZorpCo\)/);
});

test("an allowlist entry with a reason and a ticket exempts the path", () => {
  const files = { "LICENSE": "Copyright (c) ZorpCo\n" };
  assert.equal(run(files).length, 1);
  assert.deepEqual(
    run(files, { allowlist: [{ path: "LICENSE", reason: "legal rights holder", ticket: "policy:AGENTS.md" }] }),
    [],
  );
});

test("an allowlist entry missing a reason or a ticket does not take effect", () => {
  const files = { "LICENSE": "Copyright (c) ZorpCo\n" };
  for (const entry of [
    { path: "LICENSE" },
    { path: "LICENSE", reason: "because" },
    { path: "LICENSE", ticket: "#1" },
    { path: "LICENSE", reason: "   ", ticket: "#1" },
  ]) {
    assert.equal(run(files, { allowlist: [entry] }).length, 1, JSON.stringify(entry));
  }
});

test("a malformed term entry is dropped rather than guessed at", () => {
  const root = mkdtempSync(join(tmpdir(), "naming-gate-"));
  mkdirSync(join(root, "tools"), { recursive: true });
  writeFileSync(
    join(root, "tools", "naming-terms.json"),
    JSON.stringify({ terms: [{ h: "not-a-digest", modes: ["word"] }, { modes: ["word"] }] }),
  );
  writeFileSync(join(root, "a.md"), "ZorpCo\n");
  try {
    assert.deepEqual(namingErrors(root, root), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a missing term list fails closed rather than passing silently", () => {
  const root = mkdtempSync(join(tmpdir(), "naming-gate-"));
  try {
    assert.equal(namingErrors(root, root).length, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("canonicalScanRoot widens to the repository root only in canonical", () => {
  const repo = mkdtempSync(join(tmpdir(), "naming-gate-"));
  const moduleRoot = join(repo, "module");
  mkdirSync(moduleRoot, { recursive: true });
  assert.equal(canonicalScanRoot(moduleRoot), moduleRoot, "no workspace marker: stay in the module");
  writeFileSync(join(repo, "workspace.codefly.yaml"), "name: test\n");
  assert.equal(canonicalScanRoot(moduleRoot), repo, "canonical: widen to the repository root");
  rmSync(repo, { recursive: true, force: true });

  const consumer = mkdtempSync(join(tmpdir(), "naming-gate-"));
  const composed = join(consumer, "modules", "saas-starter");
  mkdirSync(composed, { recursive: true });
  writeFileSync(join(consumer, "workspace.codefly.yaml"), "name: consumer\n");
  assert.equal(canonicalScanRoot(composed), composed, "consumer copy: stay in the module");
  rmSync(consumer, { recursive: true, force: true });
});

test("a file too large to scan is reported, never skipped silently", () => {
  const big = "clean line\n".repeat(60000); // comfortably over the 512 KiB cap
  assert.match(joined({ "big.md": big }), /big\.md: too large to scan/);
  // The allowlist is the escape hatch the message names, so it must actually silence it.
  assert.deepEqual(
    run({ "big.md": big }, { allowlist: [{ path: "big.md", reason: "generated", ticket: "#1" }] }),
    [],
  );
});

test("a directory carrying tracked content is not pruned", () => {
  const out = joined({ "test-results/.last-run.json": '{"failedTests":["ZorpCo"]}\n' });
  assert.match(out, /test-results\/\.last-run\.json:1: forbidden name \(ZorpCo\)/);
});

test("machine-generated skips apply in canonical, where paths carry a module/ prefix", () => {
  const repo = mkdtempSync(join(tmpdir(), "naming-gate-"));
  const moduleRoot = join(repo, "module");
  mkdirSync(join(moduleRoot, "tools"), { recursive: true });
  writeFileSync(
    join(moduleRoot, "tools", "naming-terms.json"),
    JSON.stringify({ terms: TERMS.map(({ term, modes }) => ({ h: digest(term), modes })) }),
  );
  // Matched as whole paths these skips never fired in canonical, so the manifest was scanned
  // and its recorded paths reported as violations in their own right.
  writeFileSync(join(moduleRoot, "tools", "base-manifest.json"), '{"zorpco/a.md":"deadbeef"}\n');
  try {
    assert.deepEqual(namingErrors(moduleRoot, repo), []);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

// Records — a pull request title or body, a commit message — scanned in a throwaway root.
function messages(entries, options) {
  const root = termsRoot();
  try {
    return messageErrors(entries, root, options);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("a record is reported by mode, never by the matched term or its line", () => {
  const out = messages([{ label: "pull request title", text: "Wire up the ZorpCo tenant" }]);
  assert.deepEqual(out, ["pull request title: forbidden name (mode: word)"]);
  assert.doesNotMatch(out.join("\n"), /zorpco/i);
  // The line is withheld for the same reason the term is: this log is public, and so is the body
  // a line number points into, so naming the line narrows the term to that line's few words.
  assert.doesNotMatch(out.join("\n"), /:\d/);
});

test("the hook path reports the line, because its output never leaves the machine", () => {
  const body = "Closes #12.\n\n## Summary\n\n- rolled out for ZorpCo\n";
  assert.deepEqual(messages([{ label: "commit message", text: body }], { lines: true }), [
    "commit message:5: forbidden name (mode: word)",
  ]);
});

test("every mode names itself in a record", () => {
  const byMode = (text) => messages([{ label: "r", text }]).join("\n");
  assert.match(byMode("Tracked in vantage-core#12"), /\(mode: slug\)/);
  assert.match(byMode("Quill composes this module"), /\(mode: proper\)/);
  assert.match(byMode('writeFixture(t, "quill-control")'), /\(mode: compound\)/);
  assert.match(byMode("Sold to North Star Mutual"), /\(mode: phrase\)/);
});

test("a phrase broken by a line wrap is still caught", () => {
  // Not an exotic shape — it is the convention. Commit bodies wrap at 72 columns and pull request
  // bodies are hand-wrapped prose, and phrase mode carries the tier with no single distinctive
  // word (a customer, a real person). A per-line n-gram never saw any of these.
  for (const wrapped of [
    "Rolled out the pilot for North Star\nMutual last week.",
    "Rolled out for North Star\n  Mutual last week.",
    "Delivered to North\nStar\nMutual.",
  ]) {
    assert.deepEqual(messages([{ label: "r", text: wrapped }]), ["r: forbidden name (mode: phrase)"], wrapped);
  }
});

test("a phrase broken by a line wrap is caught in the tree too", () => {
  const out = joined({ "a.md": "Sold to North Star\nMutual in March.\n" });
  assert.match(out, /a\.md:1: forbidden name \(North Star Mutual\)/);
});

test("a clean record passes, and each entry is reported under its own label", () => {
  assert.deepEqual(
    messages([
      { label: "pull request title", text: "fix: gate records as well as files (#1)" },
      { label: "commit abc1234 message", text: "fix: gate records\n\nFor a consuming solution.\n" },
    ]),
    [],
  );
  assert.deepEqual(
    messages([
      { label: "pull request title", text: "ZorpCo" },
      { label: "commit abc1234 message", text: "Quill" },
    ]),
    [
      "pull request title: forbidden name (mode: word)",
      "commit abc1234 message: forbidden name (mode: proper)",
    ],
  );
});

test("a record reports each mode once, however many times it matches", () => {
  assert.deepEqual(messages([{ label: "r", text: "ZorpCo and zorpco\nand ZorpCo again" }]), [
    "r: forbidden name (mode: word)",
  ]);
});

test("a commit message keeps its comment lines, which git does not always strip", () => {
  // `git commit -m` and `-F` use cleanup=whitespace, which keeps `#` lines, so a line like
  // "#707 rolled out for <name>" reaches the stored message verbatim. Blanking it here hid
  // exactly the text the gate exists to read.
  const kept = commitMessageBody("feat: x\n\n#707 rolled out for ZorpCo.");
  assert.match(kept, /#707 rolled out for ZorpCo\./);
  assert.deepEqual(messages([{ label: "commit message", text: kept }]), [
    "commit message: forbidden name (mode: word)",
  ]);
});

test("the verbose diff below the scissors line is not the message", () => {
  const raw = [
    "fix: a clean subject",
    "",
    "For a consuming solution.",
    "# ------------------------ >8 ------------------------",
    "diff --git a/a.md b/a.md",
    "+ZorpCo",
  ].join("\n");
  // Tree content, which the `check` scan already owns.
  assert.deepEqual(messages([{ label: "commit message", text: commitMessageBody(raw) }]), []);
  // Blanked rather than dropped, so a reported line still matches the editor.
  assert.equal(commitMessageBody(raw).split("\n").length, raw.split("\n").length);
});

test("a record scan with a missing term list fails closed rather than passing silently", () => {
  const root = mkdtempSync(join(tmpdir(), "naming-gate-"));
  try {
    assert.equal(messageErrors([{ label: "r", text: "ZorpCo" }], root).length, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// End to end over the CLI. The exported functions cannot cover this: a change that stopped
// calling process.exit — a refactor, a `--warn` flag — would leave every unit test above green
// while the gate passed everything forever.
//
// These also pin the main-module guard. The temp root sits under the system temp directory, which
// is reached through a symlink on macOS, so an argv[1]-versus-realpath mismatch shows up here as
// a command that exits 0 having printed nothing — the same silence that `modules/saas-starter`,
// a symlink to `module/`, would produce in the real tree.
function cliRoot() {
  const root = termsRoot();
  copyFileSync(new URL("./naming-gate.mjs", import.meta.url), join(root, "tools", "naming-gate.mjs"));
  return root;
}

const git = (root, args) =>
  execFileSync("git", ["-c", "user.name=T", "-c", "user.email=t@example.com", ...args], {
    cwd: root,
    encoding: "utf8",
  });

const cli = (root, args, env = {}) =>
  spawnSync(process.execPath, [join(root, "tools", "naming-gate.mjs"), ...args], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });

function withRepo(run) {
  const root = cliRoot();
  try {
    git(root, ["init", "-q", "."]);
    git(root, ["commit", "-q", "--allow-empty", "-m", "chore: base"]);
    return run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("records exits non-zero on a forbidden name, printing neither the term nor a line", () => {
  withRepo((root) => {
    git(root, ["commit", "-q", "--allow-empty", "-m", "feat: roll out\n\nRequested by ZorpCo."]);
    const bad = cli(root, ["records", "HEAD~1"]);
    assert.equal(bad.status, 1, bad.stdout + bad.stderr);
    assert.doesNotMatch(bad.stderr, /zorpco/i);
    assert.doesNotMatch(bad.stderr, /message:\d/);

    const clean = cli(root, ["records", "HEAD"], { NAMING_PR_TITLE: "fix: a clean title" });
    assert.equal(clean.status, 0, clean.stdout + clean.stderr);
  });
});

test("a record separator inside a commit message cannot truncate the scan", () => {
  // A literal \x1e used to terminate the record early: everything after it went unscanned while
  // the run still reported a clean count. NUL is the only byte a commit message cannot contain.
  withRepo((root) => {
    git(root, ["commit", "-q", "--allow-empty", "-m", "feat: x\n\nRequested by ZorpCo."]);
    const out = cli(root, ["records", "HEAD~1"]);
    assert.equal(out.status, 1, out.stdout + out.stderr);
  });
});

test("a run that scanned nothing fails instead of reporting success", () => {
  withRepo((root) => {
    const out = cli(root, ["records", "HEAD"]);
    assert.equal(out.status, 1, out.stdout + out.stderr);
    assert.match(out.stderr, /nothing to scan/);
  });
});

test("message exits non-zero and does report the line, for local use", () => {
  withRepo((root) => {
    writeFileSync(join(root, "msg.txt"), "feat: x\n\nRolled out for ZorpCo.\n");
    const out = cli(root, ["message", join(root, "msg.txt")]);
    assert.equal(out.status, 1, out.stdout + out.stderr);
    assert.match(out.stderr, /commit message:3: forbidden name \(mode: word\)/);
  });
});

test("the shipped tree is clean", () => {
  const errors = namingErrors();
  assert.deepEqual(
    errors,
    [],
    `${errors.length} forbidden name(s) in the tree:\n${errors.slice(0, 40).join("\n")}`,
  );
});
