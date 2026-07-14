import { test } from "node:test";
import assert from "node:assert/strict";
import { audit } from "../src/audit.js";

const NOW = Date.parse("2026-01-01T00:00:00Z");
const FUTURE = "2026-01-01T01:00:00Z";

function grant(overrides = {}) {
  return {
    id: "g1",
    type: "grant",
    issuer: "alice",
    subject: "agent-A",
    capabilities: [{ action: "fs.write", resource: "src/**" }],
    expires: FUTURE,
    status: "active",
    ...overrides,
  };
}

test("score is 1.0 for an empty action set (vacuously in scope)", () => {
  const res = audit([], [grant()], { now: NOW });
  assert.deepEqual(res, { score: 1, total: 0, allowed: 0, violations: [] });
});

test("non-array actions are treated as empty", () => {
  assert.equal(audit(null, [grant()], { now: NOW }).score, 1);
  assert.equal(audit(undefined, [grant()], { now: NOW }).total, 0);
});

test("full score when every action is covered", () => {
  const actions = [
    { action: "fs.write", resource: "src/a.js", subject: "agent-A" },
    { action: "fs.write", resource: "src/b.js", subject: "agent-A" },
  ];
  const res = audit(actions, [grant()], { now: NOW });
  assert.equal(res.total, 2);
  assert.equal(res.allowed, 2);
  assert.equal(res.score, 1);
  assert.deepEqual(res.violations, []);
});

test("partial score with a violation carrying the denial reason", () => {
  const actions = [
    { action: "fs.write", resource: "src/a.js", subject: "agent-A" }, // ok
    { action: "fs.write", resource: "lib/x.js", subject: "agent-A" }, // out of scope
  ];
  const res = audit(actions, [grant()], { now: NOW });
  assert.equal(res.total, 2);
  assert.equal(res.allowed, 1);
  assert.equal(res.score, 0.5);
  assert.equal(res.violations.length, 1);
  const v = res.violations[0];
  assert.equal(v.action, "fs.write");
  assert.equal(v.resource, "lib/x.js");
  assert.equal(v.subject, "agent-A");
  assert.match(v.reason, /outside the scope/);
});

test("zero score when nothing is covered", () => {
  const actions = [{ action: "proc.exec", resource: "x", subject: "agent-A" }];
  const res = audit(actions, [grant()], { now: NOW });
  assert.equal(res.score, 0);
  assert.equal(res.allowed, 0);
  assert.equal(res.violations.length, 1);
});

test("per-action `at` is used as `now`: an action that ran before expiry counts", () => {
  // Grant lives 12:00–12:30. The registry is passed WITHOUT wall-clock decay
  // (as `audit` loading with expire:false would), still carrying status active.
  const g = grant({ expires: "2026-01-01T00:30:00Z" });
  const actions = [
    // Ran at 12:15, while the grant was live — allowed even though `opts.now`
    // (default) is far in the future here.
    { action: "fs.write", resource: "src/a.js", subject: "agent-A", at: "2026-01-01T00:15:00Z" },
  ];
  const res = audit(actions, [g], { now: Date.parse("2030-01-01T00:00:00Z") });
  assert.equal(res.allowed, 1);
  assert.equal(res.score, 1);
});

test("an action `at` after expiry is a violation", () => {
  const g = grant({ expires: "2026-01-01T00:30:00Z" });
  const actions = [
    { action: "fs.write", resource: "src/a.js", subject: "agent-A", at: "2026-01-01T01:00:00Z" },
  ];
  const res = audit(actions, [g], { now: NOW });
  assert.equal(res.allowed, 0);
  assert.match(res.violations[0].reason, /expired/);
});

test("an action with no `at` falls back to opts.now", () => {
  const g = grant({ expires: "2026-01-01T00:30:00Z" });
  const actions = [{ action: "fs.write", resource: "src/a.js", subject: "agent-A" }];
  // opts.now before expiry → allowed.
  assert.equal(audit(actions, [g], { now: Date.parse("2026-01-01T00:15:00Z") }).allowed, 1);
  // opts.now after expiry → violation.
  assert.equal(audit(actions, [g], { now: Date.parse("2026-01-01T02:00:00Z") }).allowed, 0);
});

test("per-action subject isolation: another agent's action is a violation", () => {
  const actions = [{ action: "fs.write", resource: "src/a.js", subject: "agent-B" }];
  const res = audit(actions, [grant()], { now: NOW });
  assert.equal(res.allowed, 0);
  assert.match(res.violations[0].reason, /no grant for subject "agent-B"/);
});
