import { test } from "node:test";
import assert from "node:assert/strict";
import { makeGrant, delegate, revoke, parseTtl } from "../src/grant.js";
import { validateGrant, validateRevocation } from "../src/schema.js";
import { computeRecordId } from "../src/registry.js";

const CREATED = "2026-07-11T12:00:00Z";
const CAP = [{ action: "fs.write", resource: "src/**" }];
const META = { issuer: "alice", subject: "agent-A", ttl_seconds: 1800, created: CREATED };

// --- makeGrant -------------------------------------------------------------

test("makeGrant builds a fully-valid grant record", () => {
  const g = makeGrant(CAP, META);
  assert.equal(validateGrant(g).valid, true);
  assert.equal(g.type, "grant");
  assert.equal(g.issuer, "alice");
  assert.equal(g.subject, "agent-A");
  assert.equal(g.status, "active");
  assert.equal(g.delegable, false);
  assert.deepEqual(g.capabilities, CAP);
});

test("makeGrant field order is canonical, with no parent key on a root grant", () => {
  const g = makeGrant(CAP, META);
  assert.deepEqual(Object.keys(g), [
    "id",
    "type",
    "issuer",
    "subject",
    "capabilities",
    "ttl_seconds",
    "created",
    "expires",
    "delegable",
    "status",
  ]);
  assert.ok(!("parent" in g));
});

test("makeGrant computes expires = created + ttl_seconds", () => {
  const g = makeGrant(CAP, META);
  assert.equal(Date.parse(g.expires), Date.parse(CREATED) + 1800 * 1000);
});

test("makeGrant id is the deterministic content hash of the record", () => {
  const g = makeGrant(CAP, META);
  assert.match(g.id, /^[0-9a-f]{64}$/);
  const { id, ...rest } = g;
  assert.equal(id, computeRecordId(rest));
  // Same inputs → same id (deterministic, clock-injected).
  assert.equal(makeGrant(CAP, META).id, g.id);
});

test("makeGrant with delegable + parent stamps both, in order", () => {
  const g = makeGrant(CAP, { ...META, delegable: true, parent: "parent-hash" });
  assert.equal(g.delegable, true);
  assert.equal(g.parent, "parent-hash");
  assert.deepEqual(Object.keys(g), [
    "id",
    "type",
    "issuer",
    "subject",
    "capabilities",
    "ttl_seconds",
    "created",
    "expires",
    "delegable",
    "parent",
    "status",
  ]);
});

test("makeGrant throws on empty issuer / subject", () => {
  assert.throws(() => makeGrant(CAP, { ...META, issuer: "" }), /issuer/);
  assert.throws(() => makeGrant(CAP, { ...META, issuer: undefined }), /issuer/);
  assert.throws(() => makeGrant(CAP, { ...META, subject: "  " }), /subject/);
});

test("makeGrant throws on non-positive-int ttl", () => {
  for (const t of [0, -1, 1.5, "1800", null]) {
    assert.throws(() => makeGrant(CAP, { ...META, ttl_seconds: t }), /ttl_seconds/, `ttl=${t}`);
  }
});

test("makeGrant throws on an unparseable created", () => {
  assert.throws(() => makeGrant(CAP, { ...META, created: "not-a-date" }), /created/);
  assert.throws(() => makeGrant(CAP, { ...META, created: undefined }), /created/);
});

test("makeGrant throws on empty / invalid capabilities", () => {
  assert.throws(() => makeGrant([], META), /capabilities/);
  assert.throws(() => makeGrant("fs", META), /capabilities/);
  assert.throws(() => makeGrant([{ action: "NOPE", resource: "x" }], META), /action/);
  assert.throws(() => makeGrant([{ action: "fs.write" }], META), /resource/);
});

test("makeGrant throws on non-boolean delegable", () => {
  assert.throws(() => makeGrant(CAP, { ...META, delegable: "yes" }), /delegable/);
  assert.throws(() => makeGrant(CAP, { ...META, delegable: 1 }), /delegable/);
});

test("makeGrant throws on an empty parent when one is passed", () => {
  assert.throws(() => makeGrant(CAP, { ...META, parent: "" }), /parent/);
});

// --- delegate --------------------------------------------------------------

function delegableParent(overrides = {}) {
  return makeGrant([{ action: "fs.write", resource: "src/**" }], {
    issuer: "alice",
    subject: "agent-A",
    ttl_seconds: 1800,
    created: CREATED,
    delegable: true,
    ...overrides,
  });
}

const SUB_META = { issuer: "agent-A", subject: "agent-B", ttl_seconds: 600, created: CREATED };

test("delegate mints a narrower sub-grant stamped with the parent id", () => {
  const parent = delegableParent();
  const sub = delegate(parent, [{ action: "fs.write", resource: "src/auth/**" }], SUB_META);
  assert.equal(sub.parent, parent.id);
  assert.equal(sub.subject, "agent-B");
  assert.equal(validateGrant(sub).valid, true);
  // Sub expires no later than the parent.
  assert.ok(Date.parse(sub.expires) <= Date.parse(parent.expires));
});

test("delegate allows a same-scope subset (equal capability)", () => {
  const parent = delegableParent();
  const sub = delegate(parent, [{ action: "fs.write", resource: "src/**" }], SUB_META);
  assert.equal(sub.parent, parent.id);
});

test("delegate throws when the parent is not delegable", () => {
  const parent = makeGrant(CAP, { ...META, delegable: false });
  assert.throws(
    () => delegate(parent, [{ action: "fs.write", resource: "src/auth/**" }], SUB_META),
    /not delegable/
  );
});

test("delegate throws on privilege escalation (action broader than parent)", () => {
  const parent = delegableParent();
  assert.throws(
    () => delegate(parent, [{ action: "fs", resource: "src/**" }], SUB_META),
    /exceeds/
  );
});

test("delegate throws on privilege escalation (resource outside parent)", () => {
  const parent = delegableParent();
  assert.throws(
    () => delegate(parent, [{ action: "fs.write", resource: "lib/**" }], SUB_META),
    /exceeds/
  );
});

test("delegate throws when the sub-grant would outlive the parent", () => {
  const parent = delegableParent({ ttl_seconds: 600 }); // expires at +10m
  assert.throws(
    () =>
      delegate(parent, [{ action: "fs.write", resource: "src/auth/**" }], {
        ...SUB_META,
        ttl_seconds: 1200, // +20m > parent's +10m
      }),
    /after the parent/
  );
});

test("delegate throws on a non-object parent", () => {
  assert.throws(() => delegate(null, CAP, SUB_META), /parent grant/);
  assert.throws(() => delegate(42, CAP, SUB_META), /parent grant/);
});

test("delegate can chain (grandchild covered by child)", () => {
  const parent = delegableParent();
  const child = delegate(parent, [{ action: "fs.write", resource: "src/auth/**" }], {
    ...SUB_META,
    delegable: true,
  });
  // The child must itself be delegable to delegate further.
  const delegableChild = makeGrant([{ action: "fs.write", resource: "src/auth/**" }], {
    issuer: "agent-A",
    subject: "agent-B",
    ttl_seconds: 600,
    created: CREATED,
    delegable: true,
    parent: parent.id,
  });
  const grandchild = delegate(
    delegableChild,
    [{ action: "fs.write", resource: "src/auth/login.ts" }],
    { issuer: "agent-B", subject: "agent-C", ttl_seconds: 300, created: CREATED }
  );
  assert.equal(grandchild.parent, delegableChild.id);
  assert.equal(validateGrant(grandchild).valid, true);
});

// --- revoke ----------------------------------------------------------------

test("revoke builds a valid revocation record", () => {
  const rec = revoke("grant-hash", { issuer: "alice", reason: "leaked", at: CREATED });
  assert.equal(validateRevocation(rec).valid, true);
  assert.equal(rec.type, "revocation");
  assert.equal(rec.grant_id, "grant-hash");
  assert.equal(rec.issuer, "alice");
  assert.equal(rec.reason, "leaked");
  assert.equal(rec.at, CREATED);
  assert.match(rec.id, /^[0-9a-f]{64}$/);
  const { id, ...rest } = rec;
  assert.equal(id, computeRecordId(rest));
});

test("revoke field order is canonical", () => {
  const rec = revoke("g", { issuer: "alice", reason: "why", at: CREATED });
  assert.deepEqual(Object.keys(rec), ["id", "type", "grant_id", "issuer", "reason", "at"]);
});

test("revoke throws on missing / empty fields", () => {
  assert.throws(() => revoke("", { issuer: "a", reason: "r", at: CREATED }), /grantId/);
  assert.throws(() => revoke("g", { issuer: "", reason: "r", at: CREATED }), /issuer/);
  assert.throws(() => revoke("g", { issuer: "a", reason: "", at: CREATED }), /reason/);
  assert.throws(() => revoke("g", { issuer: "a", reason: "r", at: "nope" }), /at/);
  assert.throws(() => revoke("g", {}), /issuer/);
});

// --- parseTtl --------------------------------------------------------------

test("parseTtl parses s/m/h/d units", () => {
  assert.equal(parseTtl("30s"), 30);
  assert.equal(parseTtl("20m"), 1200);
  assert.equal(parseTtl("2h"), 7200);
  assert.equal(parseTtl("1d"), 86400);
});

test("parseTtl accepts bare seconds (string or number)", () => {
  assert.equal(parseTtl("1800"), 1800);
  assert.equal(parseTtl(1800), 1800);
  assert.equal(parseTtl("1"), 1);
});

test("parseTtl returns null on invalid input (never throws)", () => {
  for (const bad of ["0", "-5", "0m", "5x", "m", "1.5h", "1 h", "", "  ", "abc", 0, -5, 1.5, null, undefined, {}]) {
    assert.equal(parseTtl(bad), null, JSON.stringify(bad));
  }
});
