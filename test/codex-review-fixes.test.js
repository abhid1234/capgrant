// Regression tests for the Codex (Sol) review findings. Each fails against the
// pre-fix code and passes after. capgrant is an authorization library, so the
// delegation-containment cases are the load-bearing ones.
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeGrant, delegate, parseTtl } from "../src/grant.js";
import { globContains } from "../src/glob.js";
import { capabilityContains } from "../src/capability.js";
import { resolveRecords, computeRecordId } from "../src/registry.js";
import { validateDecision, validateCapability } from "../src/schema.js";

const T0 = "2026-01-01T00:00:00Z";
const parentGrant = (resource, over = {}) =>
  makeGrant([{ action: "fs", resource }], { issuer: "root", subject: "alice", ttl_seconds: 3600, created: T0, delegable: true, ...over });
const childMeta = (over = {}) => ({ issuer: "alice", subject: "bob", ttl_seconds: 1800, created: T0, ...over });

// --- HIGH [0]: delegation requires CONTAINMENT, not overlap ------------------
test("globContains is directional (child ⊆ parent)", () => {
  assert.equal(globContains("src/**", "src/auth/**"), true);
  assert.equal(globContains("src/**", "src/x.js"), true);
  assert.equal(globContains("**", "anything/at/all"), true);
  assert.equal(globContains("src/*.js", "src/**"), false); // overlaps, but NOT contained
  assert.equal(globContains("src/auth/**", "src/**"), false);
  assert.equal(globContains("src/*.js", "src/a/b.py"), false);
});

test("delegate rejects a child resource broader than the parent (no escalation)", () => {
  const narrow = parentGrant("src/*.js");
  // child `src/**` overlaps `src/*.js` but also matches src/a/b.py → must be rejected
  assert.throws(
    () => delegate(narrow, [{ action: "fs", resource: "src/**" }], childMeta()),
    /exceeds the parent grant's authority/,
  );
  // a genuinely narrower child is allowed
  const broad = parentGrant("src/**");
  assert.doesNotThrow(() => delegate(broad, [{ action: "fs.write", resource: "src/auth/login.js" }], childMeta()));
});

test("capabilityContains needs action implication AND resource containment", () => {
  assert.equal(capabilityContains({ action: "fs", resource: "src/**" }, { action: "fs.write", resource: "src/a.js" }), true);
  assert.equal(capabilityContains({ action: "fs.write", resource: "src/**" }, { action: "fs", resource: "src/a.js" }), false); // broader action
  assert.equal(capabilityContains({ action: "fs", resource: "src/*.js" }, { action: "fs", resource: "src/**" }), false); // broader resource
});

// --- HIGH [2]: delegate validates the parent grant --------------------------
test("delegate rejects a non-active, mis-issued, or out-of-window parent", () => {
  const p = parentGrant("src/**");
  // issuer must be the parent's subject
  assert.throws(() => delegate(p, [{ action: "fs", resource: "src/a.js" }], childMeta({ issuer: "mallory" })), /must be the parent grant's subject/);
  // a revoked/expired parent cannot delegate
  assert.throws(() => delegate({ ...p, status: "revoked" }, [{ action: "fs", resource: "src/a.js" }], childMeta()), /not active/);
  // delegation time must be within the parent's live window
  assert.throws(() => delegate(p, [{ action: "fs", resource: "src/a.js" }], childMeta({ created: "2030-01-01T00:00:00Z" })), /outside the parent grant's live window/);
});

// --- HIGH [1]: malformed records are skipped in resolveRecords --------------
test("resolveRecords skips a hash-valid but schema-invalid grant", () => {
  const bad = { type: "grant", issuer: "r", subject: "s", capabilities: [{ action: "fs", resource: "x" }], ttl_seconds: 60, created: T0, delegable: false, status: "active" }; // no expires
  bad.id = computeRecordId(bad);
  const { grants, notes } = resolveRecords([bad], { expire: false });
  assert.equal(grants.length, 0);
  assert.ok(notes.some((n) => n.includes("skipped grant")));
});

// --- MEDIUM [4]: decision cross-field rules ---------------------------------
test("validateDecision enforces grant_ttl_seconds for approve / forbids for deny", () => {
  const base = { id: "x", type: "decision", request_id: "r", approver: "a", at: T0 };
  assert.equal(validateDecision({ ...base, decision: "approve" }).valid, false); // missing ttl
  assert.equal(validateDecision({ ...base, decision: "approve", grant_ttl_seconds: 60 }).valid, true);
  assert.equal(validateDecision({ ...base, decision: "deny", grant_ttl_seconds: 60 }).valid, false); // ttl forbidden
  assert.equal(validateDecision({ ...base, decision: "deny" }).valid, true);
});

// --- MEDIUM [5]: capability constraint validation ---------------------------
test("validateCapability rejects nonsensical constraints", () => {
  const cap = (constraints) => validateCapability({ action: "fs", resource: "x", constraints });
  assert.equal(cap({ max_bytes: -1 }).valid, false);
  assert.equal(cap({ rate: Infinity }).valid, false);
  assert.equal(cap({ methods: ["GET", 5] }).valid, false);
  assert.equal(cap({ max_bytes: 4096, methods: ["GET", "POST"], unknown_future: 1 }).valid, true);
});

// --- MEDIUM [6] / LOW [7]: strict UTC + safe-integer TTL --------------------
test("makeGrant rejects a non-UTC timestamp; parseTtl rejects unsafe integers", () => {
  assert.throws(() => makeGrant([{ action: "fs", resource: "x" }], { issuer: "i", subject: "s", ttl_seconds: 60, created: "2026-01-01T00:00:00+05:00" }), /ISO-8601-UTC/);
  assert.equal(parseTtl("999999999999999999999"), null);
  assert.equal(parseTtl("9999999999999d"), null);
  assert.equal(parseTtl("30m"), 1800);
});
