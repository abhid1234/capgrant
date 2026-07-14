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

// --- capability constraints ------------------------------------------------

test("constraint satisfied → ALLOW (max_bytes under cap)", () => {
  const g = grant({ capabilities: [{ action: "fs.write", resource: "src/**", constraints: { max_bytes: 4096 } }] });
  const res = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW, bytes: 1000 });
  assert.equal(res.allowed, true);
  assert.match(res.reason, /authorized by grant/);
});

test("constraint violated → DENY with the specific constraint reason (max_bytes)", () => {
  const g = grant({ capabilities: [{ action: "fs.write", resource: "src/**", constraints: { max_bytes: 4096 } }] });
  const res = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW, bytes: 5000 });
  assert.equal(res.allowed, false);
  assert.equal(res.matched_grant, null);
  assert.match(res.reason, /within scope/);
  assert.match(res.reason, /violates constraint max_bytes: 5000 > 4096/);
});

test("request context may be passed inline OR under opts.request", () => {
  const g = grant({ capabilities: [{ action: "fs.write", resource: "src/**", constraints: { max_bytes: 4096 } }] });
  const inline = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW, bytes: 5000 });
  const nested = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW, request: { bytes: 5000 } });
  assert.equal(inline.allowed, false);
  assert.equal(nested.allowed, false);
  assert.equal(inline.reason, nested.reason);
});

test("max_calls constraint: within budget ALLOW, over budget DENY", () => {
  const g = grant({ capabilities: [{ action: "net.fetch", resource: "api.github.com", constraints: { max_calls: 10 } }] });
  assert.equal(check("net.fetch", "api.github.com", [g], { subject: "agent-A", now: NOW, calls: 5 }).allowed, true);
  const denied = check("net.fetch", "api.github.com", [g], { subject: "agent-A", now: NOW, calls: 50 });
  assert.equal(denied.allowed, false);
  assert.match(denied.reason, /violates constraint max_calls: 50 > 10/);
});

test("rate constraint: within budget ALLOW, over budget DENY", () => {
  const g = grant({ capabilities: [{ action: "net.fetch", resource: "api.github.com", constraints: { rate: 5 } }] });
  assert.equal(check("net.fetch", "api.github.com", [g], { subject: "agent-A", now: NOW, rate: 3 }).allowed, true);
  const denied = check("net.fetch", "api.github.com", [g], { subject: "agent-A", now: NOW, rate: 20 });
  assert.equal(denied.allowed, false);
  assert.match(denied.reason, /violates constraint rate: 20 > 5/);
});

test("methods constraint: allowed method ALLOW, disallowed method DENY", () => {
  const g = grant({ capabilities: [{ action: "net.fetch", resource: "api.github.com", constraints: { methods: ["GET", "HEAD"] } }] });
  assert.equal(check("net.fetch", "api.github.com", [g], { subject: "agent-A", now: NOW, method: "GET" }).allowed, true);
  const denied = check("net.fetch", "api.github.com", [g], { subject: "agent-A", now: NOW, method: "DELETE" });
  assert.equal(denied.allowed, false);
  assert.match(denied.reason, /violates constraint methods: "DELETE" not in \{GET, HEAD\}/);
});

test("path_depth constraint: shallow resource ALLOW, deep resource DENY", () => {
  const g = grant({ capabilities: [{ action: "fs.write", resource: "src/**", constraints: { path_depth: 2 } }] });
  // depth 2 — within cap, and no request context needed
  assert.equal(check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW }).allowed, true);
  // depth 3 — exceeds cap
  const denied = check("fs.write", "src/auth/login.ts", [g], { subject: "agent-A", now: NOW });
  assert.equal(denied.allowed, false);
  assert.match(denied.reason, /violates constraint path_depth: 3 > 2/);
});

test("backward-compat: a constrained grant with no request context still ALLOWS", () => {
  // max_bytes only bites when the request declares bytes; a context-free check works.
  const g = grant({ capabilities: [{ action: "fs.write", resource: "src/**", constraints: { max_bytes: 4096 } }] });
  assert.equal(check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW }).allowed, true);
});

test("backward-compat: a capability with no constraints behaves exactly as v0.1", () => {
  const g = grant({ capabilities: [{ action: "fs.write", resource: "src/**" }] });
  // extra request context is simply ignored when the cap declares no constraints
  assert.equal(check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW, bytes: 999999 }).allowed, true);
});

test("a second, unconstrained covering cap rescues a constraint-blocked request", () => {
  // first cap is in scope but over the byte cap; a broader unconstrained cap covers it.
  const g = grant({
    capabilities: [
      { action: "fs.write", resource: "src/**", constraints: { max_bytes: 10 } },
      { action: "fs.write", resource: "src/**" },
    ],
  });
  const res = check("fs.write", "src/a.js", [g], { subject: "agent-A", now: NOW, bytes: 5000 });
  assert.equal(res.allowed, true);
});

test("constraint-miss reason names the offending grant and beats generic out-of-scope", () => {
  const constrained = grant({ id: "cccc3333", capabilities: [{ action: "fs.write", resource: "src/**", constraints: { max_bytes: 10 } }] });
  const unrelated = grant({ id: "dddd4444", capabilities: [{ action: "proc.exec", resource: "other" }] });
  const res = check("fs.write", "src/a.js", [constrained, unrelated], { subject: "agent-A", now: NOW, bytes: 5000 });
  assert.equal(res.allowed, false);
  assert.match(res.reason, /within scope of grant cccc3333/);
  assert.match(res.reason, /violates constraint max_bytes/);
});
