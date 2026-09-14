// Tests for naming-gate.mjs.
//
// The fixtures use INVENTED terms ("zorpco", "quill", "vantage-core"), never the real ones. A
// test file that spelled the forbidden names would defeat the point of hashing them — and
// AGENTS.md binds test fixtures exactly like everything else.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
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
function messages(entries) {
  const root = termsRoot();
  try {
    return messageErrors(entries, root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("a record is reported by mode, never by the matched term", () => {
  const out = messages([{ label: "pull request title", text: "Wire up the ZorpCo tenant" }]);
  assert.deepEqual(out, ["pull request title:1: forbidden name (mode: word)"]);
  // The whole point of the redaction: CI logs are public, so the term must not survive the report.
  assert.doesNotMatch(out.join("\n"), /zorpco/i);
});

test("every mode names itself in a record", () => {
  const byMode = (text) => messages([{ label: "r", text }]).join("\n");
  assert.match(byMode("Tracked in vantage-core#12"), /\(mode: slug\)/);
  assert.match(byMode("Quill composes this module"), /\(mode: proper\)/);
  assert.match(byMode('writeFixture(t, "quill-control")'), /\(mode: compound\)/);
  assert.match(byMode("Sold to North Star Mutual"), /\(mode: phrase\)/);
});

test("a record line number points at the offending line of a body", () => {
  const body = "Closes #12.\n\n## Summary\n\n- rolled out for ZorpCo\n";
  assert.deepEqual(messages([{ label: "pull request body", text: body }]), [
    "pull request body:5: forbidden name (mode: word)",
  ]);
});

test("a clean record passes, and each entry is reported under its own label", () => {
  assert.deepEqual(
    messages([
      { label: "pull request title", text: "fix: gate records as well as files (#1)" },
      { label: "commit abc1234 message", text: "fix: gate records\n\nFor a consuming solution.\n" },
    ]),
    [],
  );
  const out = messages([
    { label: "pull request title", text: "ZorpCo" },
    { label: "commit abc1234 message", text: "Quill" },
  ]);
  assert.deepEqual(out, [
    "pull request title:1: forbidden name (mode: word)",
    "commit abc1234 message:1: forbidden name (mode: proper)",
  ]);
});

test("one line reports a mode once, however many times it matches", () => {
  assert.deepEqual(messages([{ label: "r", text: "ZorpCo and zorpco and ZorpCo again" }]), [
    "r:1: forbidden name (mode: word)",
  ]);
});

test("a commit message is the author's text, not git's comments or the verbose diff", () => {
  const raw = [
    "fix: a clean subject",
    "",
    "Rolled out for ZorpCo.",
    "# Please enter the commit message for your changes.",
    "# On branch quill-control",
    "# ------------------------ >8 ------------------------",
    "diff --git a/a.md b/a.md",
    "+ZorpCo",
  ].join("\n");
  // Only line 3 is the author's; the comment block and everything below the scissors line are
  // git's own prose and tree content the `check` scan already owns. Line 3 must still read 3.
  assert.deepEqual(messages([{ label: "commit message", text: commitMessageBody(raw) }]), [
    "commit message:3: forbidden name (mode: word)",
  ]);
});

test("a record scan with a missing term list fails closed rather than passing silently", () => {
  const root = mkdtempSync(join(tmpdir(), "naming-gate-"));
  try {
    assert.equal(messageErrors([{ label: "r", text: "ZorpCo" }], root).length, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the shipped tree is clean", () => {
  const errors = namingErrors();
  assert.deepEqual(
    errors,
    [],
    `${errors.length} forbidden name(s) in the tree:\n${errors.slice(0, 40).join("\n")}`,
  );
});
