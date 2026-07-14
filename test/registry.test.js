import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  canonicalize,
  computeRecordId,
  resolveRecords,
  loadRegistry,
  appendRecord,
  defaultRegistryPath,
  listActive,
  formatRelative,
  shortId,
} from "../src/registry.js";
import { makeGrant, revoke } from "../src/grant.js";

// A fixed clock so expiry is deterministic. Created 12:00, ttl 1800 → expires 12:30.
const CREATED = "2026-07-11T12:00:00Z";
const NOW = Date.parse("2026-07-11T12:10:00Z"); // inside the lease → active

// A self-consistent grant record (id = its own content hash).
function grant(overrides = {}) {
  const {
    caps = [{ action: "fs.write", resource: "src/**" }],
    issuer = "alice",
    subject = "agent-A",
    ttl_seconds = 1800,
    created = CREATED,
    delegable = false,
    parent,
  } = overrides;
  const meta = { issuer, subject, ttl_seconds, created, delegable };
  if (parent !== undefined) meta.parent = parent;
  return makeGrant(caps, meta);
}

// --- canonicalize / computeRecordId ---------------------------------------

test("computeRecordId is deterministic and key-order-independent", () => {
  const a = { type: "grant", issuer: "alice", subject: "a1" };
  const b = { subject: "a1", issuer: "alice", type: "grant" };
  assert.equal(computeRecordId(a), computeRecordId(b));
  assert.match(computeRecordId(a), /^[0-9a-f]{64}$/);
});

test("canonicalize excludes the id field", () => {
  const base = { type: "grant", issuer: "alice", subject: "a1" };
  assert.equal(canonicalize({ ...base, id: "anything" }), canonicalize(base));
});

test("canonicalize recurses so nested key order can't perturb the digest", () => {
  const a = { x: { p: 1, q: [{ m: 1, n: 2 }] } };
  const b = { x: { q: [{ n: 2, m: 1 }], p: 1 } };
  assert.equal(computeRecordId(a), computeRecordId(b));
});

test("changing any content field changes the id", () => {
  const base = computeRecordId({ issuer: "alice", subject: "a1" });
  assert.notEqual(computeRecordId({ issuer: "bob", subject: "a1" }), base);
  assert.notEqual(computeRecordId({ issuer: "alice", subject: "a2" }), base);
});

test("shortId is the first 8 hex chars", () => {
  assert.equal(shortId("0123456789abcdef"), "01234567");
});

test("formatRelative renders seconds/minutes/hours and expired", () => {
  const now = Date.parse("2026-07-11T20:00:00Z");
  assert.equal(formatRelative("2026-07-11T20:00:40Z", now), "in 40s");
  assert.equal(formatRelative("2026-07-11T20:12:00Z", now), "in 12m");
  assert.equal(formatRelative("2026-07-11T22:00:00Z", now), "in 2h");
  assert.equal(formatRelative("2026-07-11T19:59:00Z", now), "expired");
  assert.equal(formatRelative("not-a-date", now), "unknown");
});

// --- resolveRecords: basics ------------------------------------------------

test("single active grant (now before expires) → one active grant", () => {
  const { grants, notes } = resolveRecords([grant()], { now: NOW });
  assert.equal(grants.length, 1);
  assert.equal(grants[0].status, "active");
  assert.equal(notes.length, 0);
  assert.equal(listActive(grants).length, 1);
});

test("a duplicate grant record resolves to a single grant (idempotent)", () => {
  const g = grant();
  const { grants } = resolveRecords([g, { ...g }], { now: NOW });
  assert.equal(grants.length, 1);
});

test("two distinct grants both present, sorted by expires ascending", () => {
  const soon = grant({ caps: [{ action: "fs.write", resource: "a/**" }], ttl_seconds: 300 });
  const late = grant({ caps: [{ action: "fs.write", resource: "b/**" }], ttl_seconds: 1500 });
  const { grants } = resolveRecords([late, soon], { now: NOW });
  assert.deepEqual(
    grants.map((g) => g.capabilities[0].resource),
    ["a/**", "b/**"]
  );
});

test("resolveRecords never throws on malformed records", () => {
  assert.doesNotThrow(() => resolveRecords([null, 42, "str", {}, { id: "x" }], { now: NOW }));
});

test("a record whose id doesn't match its content is skipped with a note", () => {
  const good = grant({ caps: [{ action: "fs.write", resource: "good/**" }] });
  const tampered = { ...grant({ caps: [{ action: "fs.write", resource: "bad/**" }] }), subject: "mutated" };
  const { grants, notes } = resolveRecords([good, tampered], { now: NOW });
  assert.equal(grants.length, 1);
  assert.equal(grants[0].capabilities[0].resource, "good/**");
  assert.ok(notes.some((n) => /id\/content mismatch/.test(n)));
});

test("a record with an unknown type is skipped with a note", () => {
  const weird = { type: "frobnicate", data: 1 };
  weird.id = computeRecordId(weird);
  const { grants, notes } = resolveRecords([weird], { now: NOW });
  assert.equal(grants.length, 0);
  assert.ok(notes.some((n) => /unknown type/.test(n)));
});

// --- resolveRecords: revocation + cascade ----------------------------------

test("a matching revocation moves the grant to revoked", () => {
  const g = grant();
  const rev = revoke(g.id, { issuer: "alice", reason: "leaked", at: "2026-07-11T12:05:00Z" });
  const { grants } = resolveRecords([g, rev], { now: NOW });
  assert.equal(grants.length, 1);
  assert.equal(grants[0].status, "revoked");
  assert.equal(grants[0].revoked_by, "alice");
  assert.equal(grants[0].revoked_reason, "leaked");
  assert.equal(listActive(grants).length, 0);
});

test("a revocation for an unknown grant_id is ignored with a note", () => {
  const rev = revoke("no-such-grant", { issuer: "alice", reason: "x", at: CREATED });
  const { grants, notes } = resolveRecords([rev], { now: NOW });
  assert.equal(grants.length, 0);
  assert.ok(notes.some((n) => /unknown grant_id/.test(n)));
});

test("revoking a parent CASCADES to a delegated child", () => {
  const parent = grant({ delegable: true });
  const child = grant({
    subject: "agent-B",
    caps: [{ action: "fs.write", resource: "src/auth/**" }],
    parent: parent.id,
  });
  const rev = revoke(parent.id, { issuer: "alice", reason: "leaked", at: "2026-07-11T12:05:00Z" });
  const { grants, notes } = resolveRecords([parent, child, rev], { now: NOW });
  const byId = Object.fromEntries(grants.map((g) => [g.id, g]));
  assert.equal(byId[parent.id].status, "revoked");
  assert.equal(byId[child.id].status, "revoked");
  assert.match(byId[child.id].revoked_reason, /cascade/);
  assert.ok(notes.some((n) => /cascade/.test(n)));
});

test("cascade propagates down a multi-level delegation chain", () => {
  const parent = grant({ delegable: true });
  const child = grant({
    subject: "agent-B",
    caps: [{ action: "fs.write", resource: "src/auth/**" }],
    parent: parent.id,
  });
  const grandchild = grant({
    subject: "agent-C",
    caps: [{ action: "fs.write", resource: "src/auth/login.ts" }],
    parent: child.id,
  });
  const rev = revoke(parent.id, { issuer: "alice", reason: "leaked", at: "2026-07-11T12:05:00Z" });
  const { grants } = resolveRecords([parent, child, grandchild, rev], { now: NOW });
  for (const g of grants) assert.equal(g.status, "revoked", `${shortId(g.id)} should cascade`);
});

// --- resolveRecords: TTL expiry --------------------------------------------

test("an active grant past its TTL is derived to expired (expire default) + a note", () => {
  // created 11:00, ttl 1800 → expires 11:30, before NOW (12:10).
  const g = grant({ created: "2026-07-11T11:00:00Z" });
  const { grants, notes } = resolveRecords([g], { now: NOW });
  assert.equal(grants[0].status, "expired");
  assert.ok(notes.some((n) => /expired/.test(n)));
  // Input record unchanged.
  assert.equal(g.status, "active");
});

test("expire:false preserves the stored active state (no TTL decay)", () => {
  const g = grant({ created: "2026-07-11T11:00:00Z" });
  const { grants } = resolveRecords([g], { now: NOW, expire: false });
  assert.equal(grants[0].status, "active");
});

test("a grant exactly at expires === now counts as expired", () => {
  const g = grant({ created: "2026-07-11T11:40:00Z" }); // expires 12:10 == NOW
  const { grants } = resolveRecords([g], { now: NOW });
  assert.equal(grants[0].status, "expired");
});

test("revocation dominates expiry (a revoked, past-TTL grant stays revoked)", () => {
  const g = grant({ created: "2026-07-11T11:00:00Z" });
  const rev = revoke(g.id, { issuer: "alice", reason: "x", at: "2026-07-11T11:05:00Z" });
  const { grants } = resolveRecords([g, rev], { now: NOW });
  assert.equal(grants[0].status, "revoked");
});

// --- appendRecord / loadRegistry ------------------------------------------

let dir;
test.before(() => {
  dir = mkdtempSync(join(tmpdir(), "capgrant-reg-"));
});
test.after(() => {
  rmSync(dir, { recursive: true, force: true });
});

test("loadRegistry on a missing file → empty, no throw", () => {
  const res = loadRegistry(join(dir, "nope.jsonl"), { now: NOW });
  assert.deepEqual(res, { grants: [], requests: [], notes: [] });
});

test("appendRecord assigns a content-hash id and returns the stored record", () => {
  const p = join(dir, "append-id.jsonl");
  const stored = appendRecord(p, { type: "revocation", grant_id: "abc", issuer: "a", reason: "r", at: "t" });
  assert.equal(stored.id, computeRecordId({ type: "revocation", grant_id: "abc", issuer: "a", reason: "r", at: "t" }));
});

test("appendRecord round-trips through loadRegistry", () => {
  const p = join(dir, "roundtrip.jsonl");
  const g = grant();
  appendRecord(p, g);
  const { grants } = loadRegistry(p, { now: NOW });
  assert.equal(grants.length, 1);
  assert.equal(grants[0].id, g.id);
  assert.equal(grants[0].status, "active");
});

test("two appends both survive; append-only (first line byte-identical); trailing newline", () => {
  const p = join(dir, "two-appends.jsonl");
  const a = appendRecord(p, grant({ caps: [{ action: "fs.write", resource: "a/**" }] }));
  const firstBefore = readFileSync(p, "utf8").split("\n")[0];
  const b = appendRecord(p, grant({ caps: [{ action: "fs.write", resource: "b/**" }] }));

  const raw = readFileSync(p, "utf8");
  const lines = raw.split("\n");
  assert.equal(lines[0], firstBefore, "first line unchanged");
  assert.equal(lines[2], "", "trailing newline");
  assert.equal(raw.trim().split("\n").length, 2);

  const { grants } = loadRegistry(p, { now: NOW });
  assert.deepEqual(new Set(grants.map((g) => g.id)), new Set([a.id, b.id]));
});

test("a duplicate append is idempotent on read", () => {
  const p = join(dir, "dupe.jsonl");
  const g = grant();
  appendRecord(p, g);
  appendRecord(p, g);
  const { grants } = loadRegistry(p, { now: NOW });
  assert.equal(grants.length, 1);
});

test("an unparseable line is skipped with a note; other lines still resolve", () => {
  const p = join(dir, "garbage.jsonl");
  appendRecord(p, grant({ caps: [{ action: "fs.write", resource: "good/**" }] }));
  writeFileSync(p, readFileSync(p, "utf8") + "{ not json\n");
  const { grants, notes } = loadRegistry(p, { now: NOW });
  assert.equal(grants.length, 1);
  assert.ok(notes.some((n) => /unparseable line/.test(n)));
});

test("appendRecord creates the parent directory when absent", () => {
  const p = join(dir, "nested", "deep", "registry.jsonl");
  appendRecord(p, grant());
  assert.equal(existsSync(p), true);
});

test("defaultRegistryPath honors CAPGRANT_REGISTRY, else .capgrant/registry.jsonl", () => {
  const saved = process.env.CAPGRANT_REGISTRY;
  try {
    process.env.CAPGRANT_REGISTRY = "/tmp/custom.jsonl";
    assert.equal(defaultRegistryPath(), "/tmp/custom.jsonl");
    delete process.env.CAPGRANT_REGISTRY;
    assert.equal(defaultRegistryPath("/repo"), join("/repo", ".capgrant", "registry.jsonl"));
  } finally {
    if (saved === undefined) delete process.env.CAPGRANT_REGISTRY;
    else process.env.CAPGRANT_REGISTRY = saved;
  }
});
