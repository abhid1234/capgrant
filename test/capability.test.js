import { test } from "node:test";
import assert from "node:assert/strict";
import {
  actionImplies,
  resourceMatches,
  capabilityCovers,
  capabilityCoverage,
  constraintViolation,
  constraintsSubsume,
  resourceDepth,
  CONSTRAINT_KEYS,
} from "../src/capability.js";
import { globsOverlap } from "../src/glob.js";

// --- actionImplies ---------------------------------------------------------

test("* implies any action", () => {
  for (const req of ["fs", "fs.write", "net.fetch", "proc.exec.sub", "*"]) {
    assert.equal(actionImplies("*", req), true, `* ⊇ ${req}`);
  }
});

test("an action implies itself (equality)", () => {
  for (const a of ["fs", "fs.write", "net.fetch"]) {
    assert.equal(actionImplies(a, a), true, a);
  }
});

test("a broader (prefix) action implies its descendants", () => {
  assert.equal(actionImplies("fs", "fs.write"), true);
  assert.equal(actionImplies("fs", "fs.write.foo"), true);
  assert.equal(actionImplies("fs.write", "fs.write.foo"), true);
  assert.equal(actionImplies("net", "net.fetch"), true);
});

test("a narrower action does NOT imply a broader one", () => {
  assert.equal(actionImplies("fs.write", "fs"), false);
  assert.equal(actionImplies("fs.write.foo", "fs.write"), false);
  assert.equal(actionImplies("net.fetch", "net"), false);
  // granting a concrete action never implies the wildcard request.
  assert.equal(actionImplies("fs", "*"), false);
});

test("unrelated namespaces never imply each other", () => {
  assert.equal(actionImplies("fs", "net"), false);
  assert.equal(actionImplies("fs.write", "fs.read"), false);
  assert.equal(actionImplies("net.fetch", "fs.write"), false);
  // a shared prefix segment that isn't a real ancestor (fs vs fsx) must not match.
  assert.equal(actionImplies("fs", "fsx"), false);
});

test("actionImplies is false for non-string operands (unless granted is *)", () => {
  assert.equal(actionImplies("fs", 42), false);
  assert.equal(actionImplies(42, "fs"), false);
  assert.equal(actionImplies(null, "fs"), false);
});

// --- resourceMatches -------------------------------------------------------

test("* matches any resource", () => {
  for (const r of ["src/a.js", "api.github.com", "anything", "*"]) {
    assert.equal(resourceMatches("*", r), true, r);
  }
});

test("glob patterns defer to globsOverlap", () => {
  assert.equal(resourceMatches("src/**", "src/a.js"), true);
  assert.equal(resourceMatches("src/**", "src/auth/login.ts"), true);
  assert.equal(resourceMatches("src/**", "lib/a.js"), false);
  assert.equal(resourceMatches("src/*", "src/a.js"), true);
  assert.equal(resourceMatches("src/*", "src/auth/login.ts"), false); // * doesn't cross /
  // A pattern-vs-pattern overlap resolves through the same engine.
  assert.equal(
    resourceMatches("src/**", "src/*"),
    globsOverlap("src/**", "src/*")
  );
});

test("opaque tokens (hosts/ids) use exact case-sensitive equality", () => {
  assert.equal(resourceMatches("api.github.com", "api.github.com"), true);
  assert.equal(resourceMatches("api.github.com", "api.gitlab.com"), false);
  assert.equal(resourceMatches("api.github.com", "API.github.com"), false);
  assert.equal(resourceMatches("db-primary", "db-primary"), true);
  assert.equal(resourceMatches("db-primary", "db-replica"), false);
});

test("path-vs-path resources overlap only when they can name a common file", () => {
  assert.equal(resourceMatches("src/a.js", "src/a.js"), true);
  assert.equal(resourceMatches("src/a.js", "src/b.js"), false);
});

test("resourceMatches is false for non-string operands (unless pattern is *)", () => {
  assert.equal(resourceMatches(42, "x"), false);
  assert.equal(resourceMatches("x", 42), false);
});

// --- capabilityCovers ------------------------------------------------------

test("capabilityCovers requires BOTH axes to line up", () => {
  const cap = { action: "fs", resource: "src/**" };
  assert.equal(capabilityCovers(cap, "fs.write", "src/a.js"), true);
  // action out of scope
  assert.equal(capabilityCovers(cap, "net.fetch", "src/a.js"), false);
  // resource out of scope
  assert.equal(capabilityCovers(cap, "fs.write", "lib/a.js"), false);
});

test("a wildcard capability covers everything", () => {
  const cap = { action: "*", resource: "*" };
  assert.equal(capabilityCovers(cap, "proc.exec", "anything"), true);
  assert.equal(capabilityCovers(cap, "net.fetch", "api.github.com"), true);
});

test("a narrow capability does not cover a broader action request", () => {
  const cap = { action: "fs.write", resource: "src/**" };
  assert.equal(capabilityCovers(cap, "fs", "src/a.js"), false);
  assert.equal(capabilityCovers(cap, "fs.write", "src/a.js"), true);
});

test("host-scoped network capability", () => {
  const cap = { action: "net.fetch", resource: "api.github.com" };
  assert.equal(capabilityCovers(cap, "net.fetch", "api.github.com"), true);
  assert.equal(capabilityCovers(cap, "net.fetch", "evil.example.com"), false);
});

test("capabilityCovers is false for a non-object capability", () => {
  assert.equal(capabilityCovers(null, "fs", "x"), false);
  assert.equal(capabilityCovers(42, "fs", "x"), false);
  assert.equal(capabilityCovers("cap", "fs", "x"), false);
});

// --- resourceDepth ---------------------------------------------------------

test("resourceDepth counts non-empty /-separated segments", () => {
  assert.equal(resourceDepth("src/auth/login.ts"), 3);
  assert.equal(resourceDepth("src"), 1);
  assert.equal(resourceDepth("a/b/c/d"), 4);
  assert.equal(resourceDepth("*"), 1);
  // leading/trailing/duplicate slashes don't inflate the depth
  assert.equal(resourceDepth("/src/auth/"), 2);
  assert.equal(resourceDepth("src//auth"), 2);
  assert.equal(resourceDepth(42), 0);
});

// --- constraintViolation ---------------------------------------------------

test("no constraints (null/absent) is always satisfied", () => {
  assert.equal(constraintViolation(null, { bytes: 9999 }), null);
  assert.equal(constraintViolation(undefined, { bytes: 9999 }), null);
  assert.equal(constraintViolation({}, { bytes: 9999 }), null);
});

test("max_bytes: within cap satisfies, over cap names the violation", () => {
  assert.equal(constraintViolation({ max_bytes: 4096 }, { bytes: 4096 }), null); // boundary ok
  assert.equal(constraintViolation({ max_bytes: 4096 }, { bytes: 100 }), null);
  assert.equal(constraintViolation({ max_bytes: 4096 }, { bytes: 5000 }), "max_bytes: 5000 > 4096");
  // a request that doesn't declare bytes isn't constrained on that axis
  assert.equal(constraintViolation({ max_bytes: 4096 }, {}), null);
});

test("max_calls: a per-request declared budget must stay within the cap", () => {
  assert.equal(constraintViolation({ max_calls: 10 }, { calls: 10 }), null);
  assert.equal(constraintViolation({ max_calls: 10 }, { calls: 11 }), "max_calls: 11 > 10");
  assert.equal(constraintViolation({ max_calls: 10 }, {}), null);
});

test("rate: a per-request declared rate must stay within the cap", () => {
  assert.equal(constraintViolation({ rate: 5 }, { rate: 5 }), null);
  assert.equal(constraintViolation({ rate: 5 }, { rate: 20 }), "rate: 20 > 5");
  assert.equal(constraintViolation({ rate: 5 }, {}), null);
});

test("methods: the request's method must be in the allowed set", () => {
  const c = { methods: ["GET", "POST"] };
  assert.equal(constraintViolation(c, { method: "GET" }), null);
  assert.equal(constraintViolation(c, { method: "POST" }), null);
  assert.equal(constraintViolation(c, { method: "DELETE" }), 'methods: "DELETE" not in {GET, POST}');
  // case-sensitive, matching HTTP convention
  assert.equal(constraintViolation(c, { method: "get" }), 'methods: "get" not in {GET, POST}');
  // a request with no method isn't constrained on that axis
  assert.equal(constraintViolation(c, {}), null);
});

test("path_depth: resource depth must not exceed the cap", () => {
  assert.equal(constraintViolation({ path_depth: 3 }, { resource: "src/auth/login.ts" }), null);
  assert.equal(constraintViolation({ path_depth: 2 }, { resource: "src/auth/login.ts" }), "path_depth: 3 > 2");
  assert.equal(constraintViolation({ path_depth: 1 }, { resource: "src" }), null);
});

test("constraintViolation reports the FIRST violation in key order", () => {
  const c = { max_bytes: 10, methods: ["GET"] };
  // both are violated; max_bytes is checked first
  assert.equal(constraintViolation(c, { bytes: 99, method: "DELETE" }), "max_bytes: 99 > 10");
});

test("unknown constraint keys are ignored (forward-compat, never a denial)", () => {
  assert.equal(constraintViolation({ some_future_key: 1 }, { bytes: 9999 }), null);
});

// --- constraintsSubsume (delegation tighten-only) --------------------------

test("a child may tighten or match a numeric parent cap, never loosen it", () => {
  assert.equal(constraintsSubsume({ max_bytes: 4096 }, { max_bytes: 1024 }), true); // tighter
  assert.equal(constraintsSubsume({ max_bytes: 4096 }, { max_bytes: 4096 }), true); // equal
  assert.equal(constraintsSubsume({ max_bytes: 4096 }, { max_bytes: 8192 }), false); // looser
  // omitting a cap the parent set means "unlimited" — strictly looser → rejected
  assert.equal(constraintsSubsume({ max_bytes: 4096 }, {}), false);
  assert.equal(constraintsSubsume({ max_bytes: 4096 }, undefined), false);
});

test("a child methods set must be a subset of the parent's", () => {
  assert.equal(constraintsSubsume({ methods: ["GET", "POST"] }, { methods: ["GET"] }), true);
  assert.equal(constraintsSubsume({ methods: ["GET", "POST"] }, { methods: ["GET", "POST"] }), true);
  assert.equal(constraintsSubsume({ methods: ["GET"] }, { methods: ["GET", "POST"] }), false);
  // omitting methods the parent restricts means "any method" — looser → rejected
  assert.equal(constraintsSubsume({ methods: ["GET"] }, {}), false);
});

test("a child may ADD a constraint on a dimension the parent leaves open", () => {
  assert.equal(constraintsSubsume({}, { max_bytes: 1024 }), true);
  assert.equal(constraintsSubsume(undefined, { methods: ["GET"] }), true);
  assert.equal(constraintsSubsume({}, {}), true);
});

test("path_depth and rate follow the same tighten-only numeric rule", () => {
  assert.equal(constraintsSubsume({ path_depth: 3 }, { path_depth: 2 }), true);
  assert.equal(constraintsSubsume({ path_depth: 3 }, { path_depth: 5 }), false);
  assert.equal(constraintsSubsume({ rate: 10 }, { rate: 5 }), true);
  assert.equal(constraintsSubsume({ rate: 10 }, { rate: 25 }), false);
});

// --- capabilityCovers / capabilityCoverage with constraints ----------------

test("a constrained capability covers a request that satisfies the constraint", () => {
  const cap = { action: "fs.write", resource: "src/**", constraints: { max_bytes: 4096 } };
  assert.equal(capabilityCovers(cap, "fs.write", "src/a.js", { bytes: 100 }), true);
  assert.equal(capabilityCovers(cap, "fs.write", "src/a.js", { bytes: 5000 }), false);
});

test("backward-compat: a constrained cap with NO request context still covers", () => {
  // bytes/method constraints only bite when the request declares them.
  const cap = { action: "fs.write", resource: "src/**", constraints: { max_bytes: 4096 } };
  assert.equal(capabilityCovers(cap, "fs.write", "src/a.js"), true);
});

test("path_depth constraint applies even with no explicit request context", () => {
  // the concrete resource is always known, so path_depth is always evaluable
  const cap = { action: "fs.write", resource: "src/**", constraints: { path_depth: 2 } };
  assert.equal(capabilityCovers(cap, "fs.write", "src/a.js"), true); // depth 2
  assert.equal(capabilityCovers(cap, "fs.write", "src/auth/a.js"), false); // depth 3
});

test("net methods constraint gates by request method", () => {
  const cap = { action: "net.fetch", resource: "api.github.com", constraints: { methods: ["GET"] } };
  assert.equal(capabilityCovers(cap, "net.fetch", "api.github.com", { method: "GET" }), true);
  assert.equal(capabilityCovers(cap, "net.fetch", "api.github.com", { method: "POST" }), false);
});

test("capabilityCoverage separates axes-miss from constraint-miss", () => {
  const cap = { action: "fs.write", resource: "src/**", constraints: { max_bytes: 10 } };
  // axes don't line up
  assert.deepEqual(capabilityCoverage(cap, "net.fetch", "src/a.js"), { axes: false, violation: null });
  // axes line up, constraint satisfied
  assert.deepEqual(capabilityCoverage(cap, "fs.write", "src/a.js", { bytes: 5 }), {
    axes: true,
    violation: null,
  });
  // axes line up, constraint violated
  assert.deepEqual(capabilityCoverage(cap, "fs.write", "src/a.js", { bytes: 99 }), {
    axes: true,
    violation: "max_bytes: 99 > 10",
  });
});

test("CONSTRAINT_KEYS documents the supported vocabulary", () => {
  assert.deepEqual(CONSTRAINT_KEYS, ["max_bytes", "max_calls", "rate", "methods", "path_depth"]);
});
