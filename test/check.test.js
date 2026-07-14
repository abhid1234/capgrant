import { test } from "node:test";
import assert from "node:assert/strict";
import { check } from "../src/check.js";

// Fixed clock so wall-clock expiry is deterministic.
const NOW = Date.parse("2026-01-01T00:00:00Z");
const FUTURE = "2026-01-01T01:00:00Z"; // after NOW
const PAST = "2025-12-31T23:00:00Z"; // before NOW

// A resolved-style grant object (as resolveRecords would hand to check).
function grant(overrides = {}) {
  return {
    id: "0123456789abcdef",
    type: "grant",
    issuer: "alice",
    subject: "agent-A",
    capabilities: [{ action: "fs.write", resource: "src/**" }],
    expires: FUTURE,
    status: "active",
    ...overrides,
  };
}

// --- allow paths -----------------------------------------------------------

test("a covering active grant authorizes the action", () => {
  const g = grant();
  const res = check("fs.write", "src/auth/login.ts", [g], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, true);
  assert.equal(res.matched_grant, g);
  assert.match(res.reason, /authorized by grant/);
});

test("action hierarchy: a grant of `fs` authorizes `fs.write`", () => {
  const g = grant({ capabilities: [{ action: "fs", resource: "src/**" }] });
  const res = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, true);
});

test("a wildcard action + wildcard resource grant authorizes anything", () => {
  const g = grant({ capabilities: [{ action: "*", resource: "*" }] });
  assert.equal(check("proc.exec", "rm -rf /", [g], { subject: "agent-A", now: NOW }).allowed, true);
  assert.equal(check("net.fetch", "api.github.com", [g], { subject: "agent-A", now: NOW }).allowed, true);
});

test("no subject filter → any grant may authorize", () => {
  const g = grant({ subject: "someone" });
  assert.equal(check("fs.write", "src/a.js", [g], { now: NOW }).allowed, true);
});

test("first covering grant is the matched grant", () => {
  const g1 = grant({ id: "aaaa1111", capabilities: [{ action: "fs.write", resource: "src/**" }] });
  const g2 = grant({ id: "bbbb2222", capabilities: [{ action: "fs.write", resource: "src/**" }] });
  const res = check("fs.write", "src/a.js", [g1, g2], { subject: "agent-A", now: NOW });
  assert.equal(res.matched_grant, g1);
});

// --- deny paths ------------------------------------------------------------

test("empty registry → denied, specific reason", () => {
  const res = check("fs.write", "src/a.js", [], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
  assert.equal(res.matched_grant, null);
  assert.match(res.reason, /no grants in the registry/);
});

test("no grant for the subject → denied with 'no grant for' reason", () => {
  const g = grant({ subject: "other" });
  const res = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
  assert.match(res.reason, /no grant for subject "agent-A"/);
});

test("out-of-scope action → denied with 'outside the scope' reason", () => {
  const g = grant({ capabilities: [{ action: "fs.write", resource: "src/**" }] });
  const res = check("proc.exec", "src/a.js", [g], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
  assert.match(res.reason, /outside the scope/);
});

test("out-of-scope resource → denied", () => {
  const g = grant({ capabilities: [{ action: "fs.write", resource: "src/**" }] });
  const res = check("fs.write", "lib/x.js", [g], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
  assert.match(res.reason, /outside the scope/);
});

test("a narrower grant does not authorize a broader action request", () => {
  const g = grant({ capabilities: [{ action: "fs.write", resource: "src/**" }] });
  const res = check("fs", "src/a.js", [g], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
});

test("expired-by-status grant → denied with 'expired' reason", () => {
  const g = grant({ status: "expired" });
  const res = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
  assert.match(res.reason, /have expired/);
});

test("expired-by-wall-clock grant (expires <= now) → denied with 'expired' reason", () => {
  const g = grant({ status: "active", expires: PAST });
  const res = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
  assert.match(res.reason, /have expired/);
});

test("a grant exactly at expires === now is treated as expired", () => {
  const g = grant({ status: "active", expires: "2026-01-01T00:00:00Z" });
  const res = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
  assert.match(res.reason, /have expired/);
});

test("revoked grant → denied with 'revoked' reason", () => {
  const g = grant({ status: "revoked" });
  const res = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
  assert.match(res.reason, /were revoked/);
});

test("out-of-scope takes precedence over expired/revoked in the reason", () => {
  // A live in-scope-miss grant plus a revoked one → the specific 'outside scope'
  // reason wins, so the caller learns 'you were never granted this'.
  const active = grant({ id: "act", capabilities: [{ action: "fs.write", resource: "src/**" }] });
  const revoked = grant({ id: "rev", status: "revoked" });
  const res = check("net.fetch", "api.x.com", [active, revoked], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
  assert.match(res.reason, /outside the scope/);
});

test("a subject only matches its own grants (isolation)", () => {
  const mine = grant({ id: "mine", subject: "agent-A", capabilities: [{ action: "fs.write", resource: "src/**" }] });
  const theirs = grant({ id: "theirs", subject: "agent-B", capabilities: [{ action: "*", resource: "*" }] });
  // agent-A can't ride agent-B's broad grant.
  assert.equal(check("proc.exec", "x", [mine, theirs], { subject: "agent-A", now: NOW }).allowed, false);
  // agent-B can.
  assert.equal(check("proc.exec", "x", [mine, theirs], { subject: "agent-B", now: NOW }).allowed, true);
});
