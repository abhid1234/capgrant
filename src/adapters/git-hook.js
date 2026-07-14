// capgrant — git pre-commit hook adapter (the dogfood surface).
//
// This is what makes capgrant actually enforce a least-privilege boundary in a
// live agent setup: a pre-commit hook that treats a commit as a batch of
// `fs.write` actions — one per staged path — and `check`s each against the
// committing agent's grants. A path the agent has no `fs.write` grant for is an
// out-of-scope write. The git plumbing lives here; the authorization decision is
// delegated to the shared `check` core, so this adapter adds a new *surface*,
// not a second notion of "authorized".
//
// Design, matching the roadmap's advisory-first principle: the hook WARNS by
// default (prints out-of-scope writes, exits 0, never blocks a commit). Set
// `CAPGRANT_ENFORCE=1` in the hook's environment to make an out-of-scope write
// fatal (exit 1), aborting the commit. The committing agent is read from
// `CAPGRANT_AGENT`.
//
// Zero runtime dependencies: `git` is invoked via `child_process`, everything
// else reuses this package's own modules.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync } from "node:fs";
import { dirname, join, isAbsolute } from "node:path";
import { loadRegistry, defaultRegistryPath } from "../registry.js";
import { check } from "../check.js";

// Markers delimiting capgrant's managed region inside `.git/hooks/pre-commit`.
// Install rewrites only the text *between* (and including) these lines, so any
// pre-existing hook body a user or another tool wrote is preserved verbatim.
const START = "# >>> capgrant >>>";
const END = "# <<< capgrant <<<";

// --- staged-write check ----------------------------------------------------

// stagedPaths({ cwd }) → the repo-relative paths staged for the pending commit.
//
// These are the files the commit is about to write. A staged path is already a
// concrete path, and every concrete path is a valid degenerate glob, so it feeds
// straight into `check` as the resource of an `fs.write` action —
// `check("fs.write", "src/auth/x.ts", …)` is covered by a grant of `fs.write`
// on `src/**`. A non-git directory (or any git failure) yields [] — the caller
// then treats the commit as clear, since an advisory hook must never wedge a
// commit.
export function stagedPaths(opts = {}) {
  const { cwd = process.cwd() } = opts;
  const r = spawnSync("git", ["diff", "--cached", "--name-only"], {
    cwd,
    encoding: "utf8",
  });
  if (r.status !== 0 || typeof r.stdout !== "string") return [];
  return r.stdout
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
}

// checkStagedWrites(paths, { registry, subject, now }) → { clear, violations, notes }
//
// The core the hook runs: load the registry once and `check("fs.write", path)`
// for each staged path as the committing `subject`. Empty input short-circuits
// to clear (an empty or docs-only staged set can never be out of scope). Each
// out-of-scope write becomes `{ path, reason }`. `notes` carries loadRegistry's
// skipped/tampered/expired warnings so the caller can surface them.
export function checkStagedWrites(paths, opts = {}) {
  const { registry = null, subject = null, now = Date.now() } = opts;
  if (!paths || paths.length === 0) {
    return { clear: true, violations: [], notes: [] };
  }
  const path = registry || defaultRegistryPath();
  const { grants, notes } = loadRegistry(path, { now });

  const violations = [];
  for (const p of paths) {
    const result = check("fs.write", p, grants, { subject, now });
    if (!result.allowed) violations.push({ path: p, reason: result.reason });
  }
  return { clear: violations.length === 0, violations, notes };
}

// --- hook install ----------------------------------------------------------

// gitPath(cwd, rel) → the absolute path of a file inside the git dir, or null if
// cwd is not a git repo. Uses `git rev-parse --git-path` so it resolves
// correctly for worktrees (where hooks live in the shared common dir) — the
// exact setup capgrant targets, since fleets run in parallel worktrees.
function gitPath(cwd, rel) {
  const r = spawnSync("git", ["rev-parse", "--git-path", rel], {
    cwd,
    encoding: "utf8",
  });
  if (r.status !== 0 || typeof r.stdout !== "string") return null;
  const p = r.stdout.trim();
  if (!p) return null;
  return isAbsolute(p) ? p : join(cwd, p);
}

// hookPath(cwd) → absolute path of this repo's pre-commit hook, or null if cwd
// is not a git repository.
export function hookPath(cwd = process.cwd()) {
  return gitPath(cwd, "hooks/pre-commit");
}

// renderHookBlock() → the marker-delimited shell block install writes.
//
// The block delegates to `capgrant hook run`, guarded by `command -v` so a clone
// where `capgrant` isn't on PATH degrades gracefully (no hook error, consistent
// with advisory-first). The warn/enforce policy is NOT baked into the block — it
// is read from the `CAPGRANT_ENFORCE` env var at run time — so one installed hook
// serves both modes and the decision lives in one place (`hook run`).
export function renderHookBlock() {
  return [
    START,
    "# Managed by `capgrant hook install` — checks staged writes against your grants.",
    "# Advisory by default (warns, never blocks). Set CAPGRANT_ENFORCE=1 to block",
    "# out-of-scope writes; set CAPGRANT_AGENT to the committing agent's id.",
    "if command -v capgrant >/dev/null 2>&1; then",
    "  capgrant hook run",
    "fi",
    END,
  ].join("\n");
}

// installHook({ cwd }) → { path, action }
//
// Idempotent, existing-hook-preserving install:
//   - no pre-commit hook yet     → create one (shebang + block)  ["created"]
//   - a hook with our markers     → replace only the marked block ["updated"]
//   - a hook without our markers   → append the block after it     ["appended"]
// Re-running install therefore converges to a single managed block and never
// duplicates it or clobbers a hand-written hook. The file is chmod +x so git
// will execute it.
export function installHook(opts = {}) {
  const { cwd = process.cwd() } = opts;
  const path = hookPath(cwd);
  if (!path) {
    throw new Error("not a git repository (run `git init` first)");
  }

  const block = renderHookBlock();
  let content;
  let action;

  if (!existsSync(path)) {
    content = `#!/bin/sh\n${block}\n`;
    action = "created";
  } else {
    const existing = readFileSync(path, "utf8");
    const s = existing.indexOf(START);
    const e = existing.indexOf(END);
    if (s !== -1 && e !== -1 && e > s) {
      content = existing.slice(0, s) + block + existing.slice(e + END.length);
      action = "updated";
    } else {
      const sep = existing.endsWith("\n") ? "" : "\n";
      content = `${existing}${sep}\n${block}\n`;
      action = "appended";
    }
  }

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
  chmodSync(path, 0o755);
  return { path, action };
}
