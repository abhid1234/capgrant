import { test } from "node:test";
import assert from "node:assert/strict";
import { actionImplies, resourceMatches, capabilityCovers } from "../src/capability.js";
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
