import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  writeFileSync,
  readFileSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import {
  stagedPaths,
  checkStagedWrites,
  hookPath,
  renderHookBlock,
  installHook,
} from "../src/adapters/git-hook.js";
import { makeGrant } from "../src/grant.js";
import { appendRecord } from "../src/registry.js";

const CREATED = "2026-07-11T12:00:00Z"; // ttl 3600 → expires 13:00
const NOW = Date.parse("2026-07-11T12:10:00Z");

// A throwaway git repo with a configured identity so commits/hooks work.
function initRepo() {
  const dir = mkdtempSync(join(tmpdir(), "capgrant-hook-"));
  const git = (...a) => spawnSync("git", a, { cwd: dir, encoding: "utf8" });
  git("init", "-q");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "Tester");
  git("config", "commit.gpgsign", "false");
  return { dir, git };
}

// Write a registry with one grant for `subject` over `resource`, return the path.
function writeRegistry(dir, { subject = "me", resource = "src/**" } = {}) {
  const p = join(dir, ".capgrant", "registry.jsonl");
  const g = makeGrant([{ action: "fs.write", resource }], {
    issuer: "alice",
    subject,
    ttl_seconds: 3600,
    created: CREATED,
  });
  appendRecord(p, g);
  return p;
}

// --- checkStagedWrites -----------------------------------------------------

test("checkStagedWrites: no staged paths → clear", () => {
  assert.deepEqual(checkStagedWrites([], {}), { clear: true, violations: [], notes: [] });
});

test("checkStagedWrites: a covered staged write is clear", () => {
  const { dir } = initRepo();
  const reg = writeRegistry(dir, { subject: "me", resource: "src/**" });
  const out = checkStagedWrites(["src/auth/login.ts"], { registry: reg, subject: "me", now: NOW });
  assert.equal(out.clear, true);
  assert.equal(out.violations.length, 0);
  rmSync(dir, { recursive: true, force: true });
});

test("checkStagedWrites: an out-of-scope staged write is a violation", () => {
  const { dir } = initRepo();
  const reg = writeRegistry(dir, { subject: "me", resource: "src/**" });
  const out = checkStagedWrites(["lib/x.js"], { registry: reg, subject: "me", now: NOW });
  assert.equal(out.clear, false);
  assert.equal(out.violations.length, 1);
  assert.equal(out.violations[0].path, "lib/x.js");
  assert.match(out.violations[0].reason, /outside the scope|no grant/);
  rmSync(dir, { recursive: true, force: true });
});

test("checkStagedWrites: mixed staged set flags only the out-of-scope path", () => {
  const { dir } = initRepo();
  const reg = writeRegistry(dir, { subject: "me", resource: "src/**" });
  const out = checkStagedWrites(["src/a.js", "docs/readme.md"], { registry: reg, subject: "me", now: NOW });
  assert.equal(out.clear, false);
  assert.deepEqual(out.violations.map((v) => v.path), ["docs/readme.md"]);
  rmSync(dir, { recursive: true, force: true });
});

test("checkStagedWrites: surfaces loadRegistry notes for a dropped line", () => {
  const { dir } = initRepo();
  const reg = writeRegistry(dir, { subject: "me", resource: "src/**" });
  writeFileSync(reg, readFileSync(reg, "utf8") + "not json\n");
  const out = checkStagedWrites(["src/a.js"], { registry: reg, subject: "me", now: NOW });
  assert.ok(out.notes.some((n) => /skipped|unparseable/i.test(n)));
  rmSync(dir, { recursive: true, force: true });
});

// --- stagedPaths -----------------------------------------------------------

test("stagedPaths: lists the staged files", () => {
  const { dir, git } = initRepo();
  writeFileSync(join(dir, "a.txt"), "hi");
  writeFileSync(join(dir, "b.txt"), "yo");
  git("add", "a.txt");
  assert.deepEqual(stagedPaths({ cwd: dir }).sort(), ["a.txt"]);
  rmSync(dir, { recursive: true, force: true });
});

test("stagedPaths: non-git directory → [] (never throws)", () => {
  const dir = mkdtempSync(join(tmpdir(), "capgrant-nogit-"));
  assert.deepEqual(stagedPaths({ cwd: dir }), []);
  rmSync(dir, { recursive: true, force: true });
});

// --- hookPath / renderHookBlock --------------------------------------------

test("hookPath: resolves inside a repo, null outside one", () => {
  const { dir } = initRepo();
  const p = hookPath(dir);
  assert.ok(p && p.endsWith(join("hooks", "pre-commit")));
  rmSync(dir, { recursive: true, force: true });

  const nogit = mkdtempSync(join(tmpdir(), "capgrant-nogit2-"));
  assert.equal(hookPath(nogit), null);
  rmSync(nogit, { recursive: true, force: true });
});

test("renderHookBlock: contains the managed-block markers and delegates to `hook run`", () => {
  const block = renderHookBlock();
  assert.match(block, /# >>> capgrant >>>/);
  assert.match(block, /# <<< capgrant <<</);
  assert.match(block, /capgrant hook run/);
});

// --- installHook -----------------------------------------------------------

test("installHook: creates an executable hook when none exists", () => {
  const { dir } = initRepo();
  const res = installHook({ cwd: dir });
  assert.equal(res.action, "created");
  assert.equal(existsSync(res.path), true);
  const body = readFileSync(res.path, "utf8");
  assert.match(body, /^#!\/bin\/sh/);
  assert.match(body, /capgrant hook run/);
  assert.ok(statSync(res.path).mode & 0o100, "owner-executable bit set");
  rmSync(dir, { recursive: true, force: true });
});

test("installHook: idempotent — re-install updates the one block, no dupes", () => {
  const { dir } = initRepo();
  installHook({ cwd: dir });
  const res = installHook({ cwd: dir });
  assert.equal(res.action, "updated");
  const body = readFileSync(res.path, "utf8");
  assert.equal(body.match(/# >>> capgrant >>>/g).length, 1);
  assert.equal(body.match(/# <<< capgrant <<</g).length, 1);
  rmSync(dir, { recursive: true, force: true });
});

test("installHook: preserves an existing hook by appending the block", () => {
  const { dir } = initRepo();
  const hookFile = join(dir, ".git", "hooks", "pre-commit");
  mkdirSync(dirname(hookFile), { recursive: true });
  writeFileSync(hookFile, "#!/bin/sh\necho custom-check\n");
  const res = installHook({ cwd: dir });
  assert.equal(res.action, "appended");
  const body = readFileSync(res.path, "utf8");
  assert.match(body, /echo custom-check/); // existing content preserved
  assert.match(body, /capgrant hook run/); // block added
  assert.equal(body.match(/# >>> capgrant >>>/g).length, 1);
  rmSync(dir, { recursive: true, force: true });
});

test("installHook: outside a git repo → throws", () => {
  const dir = mkdtempSync(join(tmpdir(), "capgrant-nogit3-"));
  assert.throws(() => installHook({ cwd: dir }), /not a git repository/);
  rmSync(dir, { recursive: true, force: true });
});
