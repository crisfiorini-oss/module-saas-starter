#!/usr/bin/env node
// naming-gate — enforce AGENTS.md §"Naming and confidentiality" mechanically.
//
// The rule has existed since the repo was created: everything here — docs, specs, code,
// comments, tests, fixtures — must use only generic placeholder names, and must never name a
// real customer, partner, employer, or downstream consumer of this module. The reason is
// architectural, not merely legal: this module sits BELOW its consumers in the dependency
// graph, so it must carry no build-time or documentation-level knowledge of who composes it.
//
// Nothing checked it, so it eroded. By the time this gate was written the tree carried ~380
// violating lines across 68 files: two consumer-premised design docs (one of them shipping to
// every consumer, its own filename naming a private product), a consumer's domain baked into a
// wire-format constant emitted into every generated manifest, real internal hostnames in test
// fixtures, and named private products scattered through prose that had been copy-edited past
// the rule dozens of times. This repository is public. Zero-tolerance.
//
//   node tools/naming-gate.mjs check          # fail on any real name in content or filenames
//   node tools/naming-gate.mjs records <base> # ... in the pull request and in <base>..HEAD
//   node tools/naming-gate.mjs message <file> # ... in one commit message (the commit-msg hook)
//   node tools/naming-gate.mjs hash <term>    # compute the digest for a new naming-terms entry
//
// AGENTS.md binds the rule to "issues, PRs, ... commit messages" too, and those are the copies
// that cannot be taken back: GitHub retains prior revisions of an edited body and serves them
// through its API, and a commit message cannot be edited at all without rewriting history. So the
// record checks run BEFORE publication, and they report only the mode that matched — printing the
// term into a public CI log would republish precisely what the gate exists to keep out of it.
//
// The forbidden terms are stored as SHA-256 digests, never literals. A guard that spelled the
// names would itself be the worst violation in the tree: one public file enumerating every
// private product and the consumer org. AGENTS.md line 35 ("holds for public and private files
// alike") binds this gate too.
//
// Be honest about what that buys: digests of short, guessable words are dictionary-attackable.
// This is not secrecy. It raises the bar from "read one file" to "mount an offline attack",
// which is proportionate, because the goal is to avoid STATING the relationship, not to defend
// a secret. Do not describe naming-terms.json as if it were confidential.
//
// The module root is the parent of tools/, so this works identically in canonical's `module/`
// and a consumer's `modules/<name>/`.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync, lstatSync, existsSync } from "node:fs";
import { join, relative, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const MODULE_ROOT = join(dirname(SCRIPT_PATH), "..");

// Mirrors base-integrity's prune set: build output, dependencies, VCS. `test-results` is
// deliberately NOT pruned even though base-integrity prunes it: it holds a tracked file here,
// and pruning a directory that carries tracked content is a silent hole in the scan.
const PRUNE_DIRS = new Set([
  "node_modules", ".next", ".turbo", "dist", "build", "coverage",
  ".git", "vendor", "__pycache__", ".codefly", ".cache", ".nix-cache", "playwright-report",
]);

// Generated output is deliberately NOT skipped — a checked-in generated Go file carried a
// product name that only a scan of generated code would have caught. Only content it cannot
// read usefully is
// skipped: binaries, and machine-generated files with no prose (a lockfile's dependency names
// and the base manifest's digests produce noise, never a real violation).
// Matched on the suffix, not the whole path: `rel` is relative to the scan root, which is the
// repository root in canonical (`module/tools/...`) and the module root in a consumer copy
// (`tools/...`).
//
// `.binpb` needs its reason stated, because skipping it looks unsafe and nearly was. A compiled
// descriptor embeds the leading comments of the protos it was built from, so a forbidden name in
// a proto reaches the binary verbatim — this scrub renamed a proto comment and left the shipped
// descriptor still carrying the old name. Nothing here reads it. What closes that is not this
// gate but the pair around it: the protos themselves are scanned as text, and
// `codefly generate contracts --check` fails the build unless the descriptor matches them. A
// clean proto plus an in-sync descriptor is a clean descriptor; drop either half and this skip
// becomes a hole.
const SKIP_FILE = (rel) =>
  /(?:^|\/)tools\/base-manifest\.json$/.test(rel) ||
  /(?:^|\/)tools\/naming-terms\.json$/.test(rel) || // digests only, by construction
  /(?:^|\/)package-lock\.json$/.test(rel) ||
  /\.(?:png|jpe?g|gif|webp|avif|ico|icns|pdf|zip|gz|tgz|bz2|xz|woff2?|ttf|otf|eot|mp4|webm|wasm|so|dylib|dll|exe|bin|binpb|node)$/i.test(rel) ||
  rel.endsWith(".tsbuildinfo") ||
  rel.endsWith(".DS_Store");

const MAX_BYTES = 512 * 1024;

// A slug is an identifier-ish run: a hyphenated repository name, a dotted hostname, an email
// address, an UPPER_SNAKE constant, a camelCase identifier. Splitting it on separators yields
// the parts a term can match; keeping the part count lets `compound` distinguish a name embedded
// in an identifier from the same letters used as an ordinary English word.
const SLUG_RE = /[A-Za-z0-9][A-Za-z0-9._@-]*[A-Za-z0-9]|[A-Za-z0-9]+/g;
const WORD_RE = /[A-Za-z]+/g;

const digest = (value) => createHash("sha256").update(value).digest("hex");

// Modes, and why each exists:
//   slug     — the whole normalized slug. For names whose individual words are far too generic
//              to forbid on their own, where only the hyphenated whole is distinctive.
//   word     — any constituent word, case-insensitively. The default, for distinctive names.
//   proper   — a constituent word written as a proper noun, /^[A-Z][a-z]+$/. For names that
//              collide with ordinary English, so that the product spelled as a proper noun
//              fails while the ordinary word, and an UPPER_SNAKE constant, do not.
//   compound — a constituent word, but only inside a multi-part slug. The other half of the
//              English-collision problem: a real name embedded in an identifier is signal, the
//              bare word is not. Pair it with `proper`; never use it for a name whose letters
//              appear in a common constant, or every such constant fails the gate.
//   phrase   — a lowercased 2- or 3-word n-gram. For human and company names written with
//              spaces, where no single word is distinctive enough to forbid.
const MODES = new Set(["slug", "word", "proper", "compound", "phrase"]);

function loadTerms(root = MODULE_ROOT) {
  const path = join(root, "tools", "naming-terms.json");
  if (!existsSync(path)) return null;
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
  const index = { slug: new Set(), word: new Set(), proper: new Set(), compound: new Set(), phrase: new Set() };
  for (const entry of Array.isArray(parsed?.terms) ? parsed.terms : []) {
    // A malformed entry is dropped rather than guessed at, so a typo weakens the gate
    // visibly (the tree stops failing on a name) instead of silently matching nothing.
    if (typeof entry?.h !== "string" || !/^[0-9a-f]{64}$/.test(entry.h)) continue;
    const modes = Array.isArray(entry.modes) ? entry.modes : [entry.mode ?? "word"];
    for (const mode of modes) if (MODES.has(mode)) index[mode].add(entry.h);
  }
  return index;
}

function loadAllowlist(root = MODULE_ROOT) {
  const path = join(root, "tools", "naming-allowlist.json");
  if (!existsSync(path)) return new Set();
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return new Set();
  }
  const allowed = new Set();
  for (const entry of Array.isArray(parsed?.paths) ? parsed.paths : []) {
    // Same contract as authz-coverage-allowlist.json: an exemption without a reason and a
    // ticket is not a reviewable decision, so it does not take effect.
    if (typeof entry?.path !== "string") continue;
    if (typeof entry?.reason !== "string" || !entry.reason.trim()) continue;
    if (typeof entry?.ticket !== "string" || !entry.ticket.trim()) continue;
    allowed.add(entry.path);
  }
  return allowed;
}

// Case-boundary units of one separator part: `ZorpcoClient` -> Zorpco, Client;
// `obIngressPolicy` -> ob, Ingress, Policy; `zorpcoAPIKey` -> zorpco, API, Key. The
// acronym branch is ordered first and guarded so `APIKey` yields API + Key, not APIK + ey.
const CASE_UNIT_RE = /[A-Z]+(?![a-z])|[A-Z][a-z]*|[a-z]+|[0-9]+/g;

// Every match a single slug occurrence produces, each carrying the mode that caught it. The tree
// scan reports the text; the record checks report only the mode.
function slugMatches(raw, terms) {
  const hits = [];
  const lower = raw.toLowerCase();
  if (terms.slug.has(digest(lower))) hits.push({ text: raw, mode: "slug" });

  // Each separator part contributes itself AND, when it is a camelCase/PascalCase identifier,
  // its case units. Splitting on separators alone never saw a name fused into an identifier —
  // `ZorpcoClient` and `zorpcoTimeout` passed while the prose form failed — which is the
  // commonest way a name reaches code. The whole part is still tested, so a term that itself
  // spans a case boundary (`ZorpCo`) keeps matching.
  const parts = raw.split(/[._@-]+/).filter(Boolean);
  const units = [];
  for (const part of parts) {
    units.push(part);
    const cased = part.match(CASE_UNIT_RE) ?? [];
    if (cased.length > 1) units.push(...cased);
  }
  // A name fused into an identifier is as compound as one joined by a hyphen.
  const compound = units.length > 1;
  for (const part of units) {
    const h = digest(part.toLowerCase());
    if (terms.word.has(h)) hits.push({ text: part, mode: "word" });
    else if (compound && terms.compound.has(h)) hits.push({ text: part, mode: "compound" });
    else if (terms.proper.has(h) && /^[A-Z][a-z]+$/.test(part)) hits.push({ text: part, mode: "proper" });
  }
  return hits;
}

function phraseMatches(line, terms) {
  if (!terms.phrase.size) return [];
  const words = line.match(WORD_RE);
  if (!words) return [];
  const hits = [];
  for (let i = 0; i < words.length; i += 1) {
    for (let n = 2; n <= 3 && i + n <= words.length; n += 1) {
      const gram = words.slice(i, i + n);
      if (terms.phrase.has(digest(gram.join(" ").toLowerCase()))) {
        hits.push({ text: gram.join(" "), mode: "phrase" });
      }
    }
  }
  return hits;
}

const lineMatches = (line, terms) => [
  ...(line.match(SLUG_RE) ?? []).flatMap((slug) => slugMatches(slug, terms)),
  ...phraseMatches(line, terms),
];

function walk(dir, out, base) {
  for (const name of readdirSync(dir)) {
    if (PRUNE_DIRS.has(name)) continue;
    const abs = join(dir, name);
    // lstat, not stat: `modules/<name>` is a symlink to `module/` (the workspace-composed view
    // Codefly expects). Following it walks the whole module tree a second time and reports every
    // violation twice, under a path that does not exist on disk.
    const st = lstatSync(abs);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) walk(abs, out, base);
    else if (st.isFile()) out.push(relative(base, abs));
  }
  return out;
}

// Widen to the repository root when running against canonical, so root *.md and .github/ are
// covered; stay inside the module when running in a consumer copy. Same test base-integrity
// uses for its public-claim scan.
export function canonicalScanRoot(moduleRoot = MODULE_ROOT) {
  const repositoryRoot = dirname(moduleRoot);
  if (
    resolve(join(repositoryRoot, "module")) === resolve(moduleRoot) &&
    existsSync(join(repositoryRoot, "workspace.codefly.yaml"))
  ) {
    return repositoryRoot;
  }
  return moduleRoot;
}

export function namingErrors(moduleRoot = MODULE_ROOT, scanRoot = canonicalScanRoot(moduleRoot)) {
  const terms = loadTerms(moduleRoot);
  if (!terms) return ["tools/naming-terms.json is missing or not valid JSON"];

  const allowed = loadAllowlist(moduleRoot);
  const errors = [];

  for (const rel of walk(scanRoot, [], scanRoot).sort()) {
    if (SKIP_FILE(rel) || allowed.has(rel)) continue;

    // A content-only scan misses a file that names a product in its own filename — which is
    // how the worst offender in the tree shipped to every consumer.
    for (const hit of new Set(rel.split("/").flatMap((seg) => slugMatches(seg, terms).map((m) => m.text)))) {
      errors.push(`${rel}: forbidden name in path (${hit})`);
    }

    const abs = join(scanRoot, rel);
    // Reported, never skipped silently: coverage must not shrink just because a file grew past
    // the cap. Binaries are already excluded by extension, so whatever reaches this is text the
    // gate is declining to read, and a reader of a green run has to be able to see that.
    if (statSync(abs).size > MAX_BYTES) {
      errors.push(
        `${rel}: too large to scan (over ${MAX_BYTES} bytes) — split it, or allowlist it in ` +
          "tools/naming-allowlist.json with a reason and a ticket",
      );
      continue;
    }
    let source;
    try {
      source = readFileSync(abs, "utf8");
    } catch {
      continue;
    }
    if (source.includes("\0")) continue; // binary that slipped the extension list

    source.split("\n").forEach((line, i) => {
      const hits = new Set(lineMatches(line, terms).map((m) => m.text));
      for (const hit of hits) errors.push(`${rel}:${i + 1}: forbidden name (${hit})`);
    });
  }
  return errors.sort();
}

// Records — a pull request title or body, a commit message — scanned with the same terms and the
// same matcher as the tree, reported WITHOUT the matched text. Only the mode and the line survive,
// which is enough to find the word in your own draft and not enough to republish it.
export function messageErrors(entries, moduleRoot = MODULE_ROOT) {
  const terms = loadTerms(moduleRoot);
  if (!terms) return ["tools/naming-terms.json is missing or not valid JSON"];

  const errors = [];
  for (const { label, text } of entries) {
    (text ?? "").split("\n").forEach((line, i) => {
      const modes = new Set(lineMatches(line, terms).map((m) => m.mode));
      for (const mode of [...modes].sort()) {
        errors.push(`${label}:${i + 1}: forbidden name (mode: ${mode})`);
      }
    });
  }
  return errors;
}

// git hands the commit-msg hook the whole buffer: the author's message, git's own `#` comment
// block, and under `commit.verbose` the entire diff below a scissors line. Only the message is the
// author's text — the diff is tree content the `check` scan already owns. Comments are blanked
// rather than dropped so a reported line number still points at the line in the editor.
const SCISSORS_RE = /^#\s*-+\s*>8\s*-+/;
export function commitMessageBody(raw) {
  let cut = false;
  return raw
    .split("\n")
    .map((line) => {
      if (SCISSORS_RE.test(line)) cut = true;
      return cut || line.startsWith("#") ? "" : line;
    })
    .join("\n");
}

// %x1f separates the sha from the message and %x1e terminates each record: a commit message
// contains newlines, so no line-oriented format can delimit one.
function commitEntries(base) {
  let out;
  try {
    out = execFileSync("git", ["log", "--format=%H%x1f%B%x1e", `${base}..HEAD`], {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "inherit"],
    });
  } catch {
    console.error(`naming-gate: cannot read commits in ${base}..HEAD`);
    process.exit(1);
  }
  return out
    .split("\x1e")
    .filter((record) => record.includes("\x1f"))
    .map((record) => {
      const [sha, ...rest] = record.replace(/^\n/, "").split("\x1f");
      return { label: `commit ${sha.slice(0, 8)} message`, text: rest.join("\x1f") };
    });
}

function reportRecords(errors, scanned) {
  if (errors.length) {
    console.error("naming-gate: a real customer, product, or consumer name in a record that cannot be retracted:");
    errors.forEach((error) => console.error(`    ${error}`));
    console.error(
      `\nFAIL: ${errors.length} forbidden name(s). The term is deliberately not printed — this log ` +
        `is public. Rewrite it with a generic placeholder — "a consuming solution", "the ` +
        `downstream product", "Acme", "Jane Doe", "user@example.com" — and amend or rebase the ` +
        `commit rather than adding one on top: a published message cannot be edited afterwards. ` +
        `See AGENTS.md §"Naming and confidentiality".`,
    );
    process.exit(1);
  }
  console.log(`✓ no real customer, product, or consumer names in ${scanned} record(s).`);
}

// The pull request's own text arrives through the environment, never interpolated into a shell
// command: it is attacker-controlled. It is absent on a merge-queue entry, where only the commits
// remain to check.
function records(base) {
  const entries = [];
  for (const [label, text] of [
    ["pull request title", process.env.NAMING_PR_TITLE],
    ["pull request body", process.env.NAMING_PR_BODY],
  ]) {
    if (text) entries.push({ label, text });
  }
  entries.push(...commitEntries(base));
  reportRecords(messageErrors(entries), entries.length);
}

function message(path) {
  const entries = [{ label: "commit message", text: commitMessageBody(readFileSync(path, "utf8")) }];
  reportRecords(messageErrors(entries), entries.length);
}

function check() {
  const errors = namingErrors();
  if (errors.length) {
    console.error("naming-gate: real customer, product, or consumer names in a repository that forbids them:");
    errors.forEach((error) => console.error(`    ${error}`));
    console.error(
      `\nFAIL: ${errors.length} forbidden name(s). Use generic placeholders — "a consuming ` +
        `solution", "the downstream product", "Acme", "Jane Doe", "user@example.com". See ` +
        `AGENTS.md §"Naming and confidentiality". A genuine exception (a copyright holder, a ` +
        `CODEOWNERS handle) goes in tools/naming-allowlist.json with a reason and a ticket.`,
    );
    process.exit(1);
  }
  console.log("✓ no real customer, product, or consumer names in tracked content or filenames.");
}

if (resolve(process.argv[1] ?? "") === resolve(SCRIPT_PATH)) {
  const cmd = process.argv[2];
  if (cmd === "check") check();
  else if (cmd === "records" || cmd === "message") {
    const argument = process.argv[3];
    if (!argument) {
      console.error(`usage: naming-gate.mjs ${cmd} <${cmd === "records" ? "base-ref" : "message-file"}>`);
      process.exit(2);
    }
    if (cmd === "records") records(argument);
    else message(argument);
  } else if (cmd === "hash") {
    const term = process.argv[3];
    if (!term) {
      console.error("usage: naming-gate.mjs hash <term>");
      process.exit(2);
    }
    console.log(digest(term.toLowerCase()));
  } else {
    console.error("usage: naming-gate.mjs <check|records|message|hash>");
    process.exit(2);
  }
}
