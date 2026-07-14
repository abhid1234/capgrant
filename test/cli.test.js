import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, readFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validateGrant } from "../src/schema.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "bin", "capgrant.js");

// Run the CLI as a child process. Returns { status, stdout, stderr }.
function run(args, env = {}) {
  const r = spawnSync("node", [CLI, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, ...env },
  });
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

let dir;
test.before(() => {
  dir = mkdtempSync(join(tmpdir(), "capgrant-cli-"));
});
test.after(() => {
  rmSync(dir, { recursive: true, force: true });
});

function fixture(name, data) {
  const p = join(dir, name);
  writeFileSync(p, typeof data === "string" ? data : JSON.stringify(data));
  return p;
}

function readRegistry(p) {
  return readFileSync(p, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

// --- grant + check round-trip ----------------------------------------------

test("grant writes one valid line and exits 0", () => {
  const reg = join(dir, "grant1.jsonl");
  const r = run([
    "grant",
    "--issuer", "alice", "--subject", "a1",
    "--cap", "fs.write:src/**", "--ttl", "20m",
    "--registry", reg,
  ]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /granted/);

  const records = readRegistry(reg);
  assert.equal(records.length, 1);
  const g = records[0];
  assert.equal(validateGrant(g).valid, true);
  assert.equal(g.subject, "a1");
  assert.equal(g.ttl_seconds, 1200);
  assert.deepEqual(g.capabilities, [{ action: "fs.write", resource: "src/**" }]);
  assert.equal(Date.parse(g.expires), Date.parse(g.created) + 1200 * 1000);
});

test("grant supports multiple --cap and --delegable + --json", () => {
  const reg = join(dir, "grant-multi.jsonl");
  const r = run([
    "grant", "--issuer", "alice", "--subject", "a1",
    "--cap", "fs.write:src/**", "--cap", "net.fetch:api.github.com",
    "--delegable", "--registry", reg, "--json",
  ]);
  assert.equal(r.status, 0, r.stderr);
  const g = JSON.parse(r.stdout);
  assert.equal(g.delegable, true);
  assert.equal(g.capabilities.length, 2);
  assert.deepEqual(g, readRegistry(reg)[0]);
});

test("grant resolves issuer/subject from env", () => {
  const reg = join(dir, "grant-env.jsonl");
  const r = run(["grant", "--cap", "fs.write:src/**", "--registry", reg, "--json"], {
    CAPGRANT_ISSUER: "env-issuer",
    CAPGRANT_AGENT: "env-agent",
  });
  assert.equal(r.status, 0, r.stderr);
  const g = JSON.parse(r.stdout);
  assert.equal(g.issuer, "env-issuer");
  assert.equal(g.subject, "env-agent");
});

test("grant then check within scope → allowed, exit 0", () => {
  const reg = join(dir, "check-allow.jsonl");
  run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**", "--registry", reg]);
  const r = run(["check", "fs.write", "src/auth/login.ts", "--subject", "a1", "--registry", reg]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /allowed/);
});

test("check out of scope → denied, exit 1", () => {
  const reg = join(dir, "check-deny.jsonl");
  run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**", "--registry", reg]);
  const r = run(["check", "proc.exec", "rm", "--subject", "a1", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /denied/);
});

test("check --json emits { allowed, matched_grant, reason }", () => {
  const reg = join(dir, "check-json.jsonl");
  run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**", "--registry", reg]);
  const r = run(["check", "fs.write", "src/a.js", "--subject", "a1", "--registry", reg, "--json"]);
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.equal(out.allowed, true);
  assert.ok(out.matched_grant);
});

test("check with a missing registry → treated as empty (denied), exit 1", () => {
  const r = run(["check", "fs.write", "src/a.js", "--subject", "a1", "--registry", join(dir, "nope.jsonl")]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /denied/);
});

test("check without action+resource → usage, exit 1", () => {
  const r = run(["check", "fs.write", "--subject", "a1"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /requires <action> and <resource>/);
});

// --- list ------------------------------------------------------------------

test("list on a missing registry → 'no active grants', exit 0", () => {
  const r = run(["list", "--registry", join(dir, "list-missing.jsonl")]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /no active grants/);
});

test("list --json on empty registry → []", () => {
  const r = run(["list", "--registry", join(dir, "list-empty.jsonl"), "--json"]);
  assert.equal(r.status, 0);
  assert.deepEqual(JSON.parse(r.stdout), []);
});

test("list shows active grants; --json returns the resolved array", () => {
  const reg = join(dir, "list-json.jsonl");
  run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**", "--registry", reg]);
  const r = run(["list", "--registry", reg, "--json"]);
  assert.equal(r.status, 0);
  const arr = JSON.parse(r.stdout);
  assert.equal(arr.length, 1);
  assert.equal(arr[0].status, "active");
  assert.equal(arr[0].subject, "a1");
});

test("list --subject filters to one holder", () => {
  const reg = join(dir, "list-subject.jsonl");
  run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:a/**", "--registry", reg]);
  run(["grant", "--issuer", "alice", "--subject", "a2", "--cap", "fs.write:b/**", "--registry", reg]);
  const arr = JSON.parse(run(["list", "--registry", reg, "--subject", "a2", "--json"]).stdout);
  assert.equal(arr.length, 1);
  assert.equal(arr[0].subject, "a2");
});

// --- delegate --------------------------------------------------------------

test("delegate a subset of a delegable parent → exit 0", () => {
  const reg = join(dir, "delegate-ok.jsonl");
  const parent = JSON.parse(
    run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**",
      "--delegable", "--ttl", "1h", "--registry", reg, "--json"]).stdout
  );
  const r = run([
    "delegate", "--parent", parent.id, "--issuer", "a1", "--subject", "a2",
    "--cap", "fs.write:src/auth/**", "--ttl", "20m", "--registry", reg, "--json",
  ]);
  assert.equal(r.status, 0, r.stderr);
  const sub = JSON.parse(r.stdout);
  assert.equal(sub.parent, parent.id);
  assert.equal(sub.subject, "a2");
});

test("delegate escalation (broader than parent) → error, exit 1", () => {
  const reg = join(dir, "delegate-esc.jsonl");
  const parent = JSON.parse(
    run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**",
      "--delegable", "--ttl", "1h", "--registry", reg, "--json"]).stdout
  );
  const r = run([
    "delegate", "--parent", parent.id, "--issuer", "a1", "--subject", "a2",
    "--cap", "fs:src/**", "--ttl", "20m", "--registry", reg,
  ]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /exceeds/);
});

test("delegate from a non-delegable parent → error, exit 1", () => {
  const reg = join(dir, "delegate-nondel.jsonl");
  const parent = JSON.parse(
    run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**",
      "--ttl", "1h", "--registry", reg, "--json"]).stdout
  );
  const r = run([
    "delegate", "--parent", parent.id, "--issuer", "a1", "--subject", "a2",
    "--cap", "fs.write:src/auth/**", "--ttl", "20m", "--registry", reg,
  ]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /not delegable/);
});

// --- revoke + cascade ------------------------------------------------------

test("revoke a parent cascades to a delegated child; both revoked in list --all", () => {
  const reg = join(dir, "revoke-cascade.jsonl");
  const parent = JSON.parse(
    run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**",
      "--delegable", "--ttl", "1h", "--registry", reg, "--json"]).stdout
  );
  const child = JSON.parse(
    run(["delegate", "--parent", parent.id, "--issuer", "a1", "--subject", "a2",
      "--cap", "fs.write:src/auth/**", "--ttl", "20m", "--registry", reg, "--json"]).stdout
  );

  const rev = run(["revoke", parent.id, "--issuer", "alice", "--reason", "leaked", "--registry", reg]);
  assert.equal(rev.status, 0, rev.stderr);
  assert.match(rev.stdout, /revoked/);

  // The active list is now empty; --all shows both as revoked.
  assert.match(run(["list", "--registry", reg]).stdout, /no active grants/);
  const all = JSON.parse(run(["list", "--registry", reg, "--all", "--json"]).stdout);
  const byId = Object.fromEntries(all.map((g) => [g.id, g]));
  assert.equal(byId[parent.id].status, "revoked");
  assert.equal(byId[child.id].status, "revoked");

  // check now denies the child's subject as revoked.
  const chk = run(["check", "fs.write", "src/auth/x.ts", "--subject", "a2", "--registry", reg]);
  assert.equal(chk.status, 1);
  assert.match(chk.stdout, /revoked/);
});

test("revoke of an unknown id → error, exit 1", () => {
  const reg = join(dir, "revoke-unknown.jsonl");
  run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**", "--registry", reg]);
  const r = run(["revoke", "deadbeefdeadbeef", "--issuer", "alice", "--reason", "x", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /no grant with id/);
});

test("revoke requires a --reason", () => {
  const reg = join(dir, "revoke-noreason.jsonl");
  const g = JSON.parse(
    run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**",
      "--registry", reg, "--json"]).stdout
  );
  const r = run(["revoke", g.id, "--issuer", "alice", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /reason/);
});

// --- audit -----------------------------------------------------------------

test("audit a mixed actions file → exit 1 with a violation; --json math", () => {
  const reg = join(dir, "audit.jsonl");
  run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**", "--registry", reg]);
  const actions = fixture("actions.json", [
    { action: "fs.write", resource: "src/a.js", subject: "a1" },
    { action: "fs.write", resource: "lib/x.js", subject: "a1" },
  ]);

  const human = run(["audit", actions, "--registry", reg]);
  assert.equal(human.status, 1);
  assert.match(human.stdout, /in-scope score/);

  const j = run(["audit", actions, "--registry", reg, "--json"]);
  assert.equal(j.status, 1);
  const out = JSON.parse(j.stdout);
  assert.equal(out.total, 2);
  assert.equal(out.allowed, 1);
  assert.equal(out.score, 0.5);
  assert.equal(out.violations.length, 1);
});

test("audit an all-in-scope file → exit 0, score 1.00", () => {
  const reg = join(dir, "audit-clean.jsonl");
  run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**", "--registry", reg]);
  const actions = fixture("actions-clean.json", [
    { action: "fs.write", resource: "src/a.js", subject: "a1" },
  ]);
  const r = run(["audit", actions, "--registry", reg, "--json"]);
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).score, 1);
});

test("audit a non-array file → clear error, exit 1", () => {
  const reg = join(dir, "audit-bad.jsonl");
  const actions = fixture("actions-bad.json", { not: "an array" });
  const r = run(["audit", actions, "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /must be a JSON array/);
});

// --- validate --------------------------------------------------------------

test("validate a valid grant file → exit 0", () => {
  const p = fixture("valid-grant.json", {
    id: "abc",
    type: "grant",
    issuer: "alice",
    subject: "a1",
    capabilities: [{ action: "fs.write", resource: "src/**" }],
    ttl_seconds: 1800,
    created: "2026-07-11T12:00:00Z",
    expires: "2026-07-11T12:30:00Z",
    delegable: false,
    status: "active",
  });
  const r = run(["validate", p]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /valid grant/);
});

test("validate an invalid grant file → errors printed, exit 1", () => {
  const p = fixture("invalid-grant.json", {
    id: "abc",
    type: "grant",
    issuer: "alice",
    subject: "a1",
    capabilities: [{ action: "NOPE", resource: "src/**" }],
    ttl_seconds: 1800,
    created: "2026-07-11T12:00:00Z",
    expires: "2026-07-11T12:30:00Z",
    delegable: false,
    status: "active",
  });
  const r = run(["validate", p]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /INVALID_ACTION/);
});

test("validate a registry (array) file and a revocation file route correctly", () => {
  const revP = fixture("rev.json", {
    id: "r",
    type: "revocation",
    grant_id: "g",
    issuer: "alice",
    reason: "x",
    at: "2026-07-11T12:00:00Z",
  });
  assert.match(run(["validate", revP]).stdout, /valid revocation/);

  const arrP = fixture("arr.json", []);
  assert.match(run(["validate", arrP]).stdout, /valid registry/);
});

test("validate --json emits parseable { valid, errors }", () => {
  const p = fixture("val-json.json", { type: "grant" });
  const r = run(["validate", p, "--json"]);
  assert.equal(r.status, 1);
  const out = JSON.parse(r.stdout);
  assert.equal(out.valid, false);
  assert.ok(out.errors.length > 0);
});

test("validate a missing file → clear error, exit 1", () => {
  const r = run(["validate", join(dir, "does-not-exist.json")]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /cannot read file/);
});

// --- router / argument handling --------------------------------------------

test("unknown subcommand → usage on stderr, exit 1", () => {
  const r = run(["frobnicate"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Usage/);
});

test("no subcommand → usage on stderr, exit 1", () => {
  const r = run([]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Usage/);
});

test("an unknown flag → error, exit 1", () => {
  const reg = join(dir, "unknown-flag.jsonl");
  const r = run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**", "--bogus", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /unknown flag/);
});

test("grant with a malformed --cap → error, exit 1, nothing written", () => {
  const reg = join(dir, "bad-cap.jsonl");
  const r = run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "no-colon", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /--cap/);
  assert.equal(existsSync(reg), false);
});

test("grant with an invalid --ttl → error, exit 1, nothing written", () => {
  const reg = join(dir, "bad-ttl.jsonl");
  const r = run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**", "--ttl", "20x", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /invalid --ttl/);
  assert.equal(existsSync(reg), false);
});

test("CAPGRANT_REGISTRY env selects the registry when --registry is omitted", () => {
  const reg = join(dir, "env-registry.jsonl");
  const g = run(["grant", "--issuer", "alice", "--subject", "a1", "--cap", "fs.write:src/**"], {
    CAPGRANT_REGISTRY: reg,
  });
  assert.equal(g.status, 0, g.stderr);
  assert.equal(existsSync(reg), true);
  const chk = run(["check", "fs.write", "src/a.js", "--subject", "a1"], { CAPGRANT_REGISTRY: reg });
  assert.equal(chk.status, 0);
});

// --- request / approve / deny / pending (HITL) -----------------------------

test("request writes one pending approval_request and exits 0", () => {
  const reg = join(dir, "req1.jsonl");
  const r = run([
    "request", "fs.write", "src/auth/**",
    "--subject", "a1", "--reason", "need to patch auth",
    "--registry", reg,
  ]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /requested/);

  const records = readRegistry(reg);
  assert.equal(records.length, 1);
  const req = records[0];
  assert.equal(req.type, "approval_request");
  assert.equal(req.subject, "a1");
  assert.equal(req.action, "fs.write");
  assert.equal(req.resource, "src/auth/**");
  assert.equal(req.status, "pending");
  // requested_by defaults to the subject.
  assert.equal(req.requested_by, "a1");
});

test("request --requested-by overrides the default and --json emits the record", () => {
  const reg = join(dir, "req-json.jsonl");
  const r = run([
    "request", "net.fetch", "api.github.com",
    "--subject", "a1", "--reason", "fetch a PR",
    "--requested-by", "orchestrator", "--registry", reg, "--json",
  ]);
  assert.equal(r.status, 0, r.stderr);
  const req = JSON.parse(r.stdout);
  assert.equal(req.requested_by, "orchestrator");
  assert.deepEqual(req, readRegistry(reg)[0]);
});

test("request requires a --reason", () => {
  const reg = join(dir, "req-noreason.jsonl");
  const r = run(["request", "fs.write", "src/**", "--subject", "a1", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /reason/);
  assert.equal(existsSync(reg), false);
});

test("request without action+resource → usage, exit 1", () => {
  const r = run(["request", "fs.write", "--subject", "a1", "--reason", "x"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /requires <action> and <resource>/);
});

test("check on a covered pending request → needs approval (exit 1, not a flat deny)", () => {
  const reg = join(dir, "req-needs.jsonl");
  run(["request", "fs.write", "src/auth/**", "--subject", "a1", "--reason", "patch", "--registry", reg]);
  const r = run(["check", "fs.write", "src/auth/login.ts", "--subject", "a1", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /needs approval/);

  const j = JSON.parse(
    run(["check", "fs.write", "src/auth/login.ts", "--subject", "a1", "--registry", reg, "--json"]).stdout
  );
  assert.equal(j.allowed, false);
  assert.equal(j.needs_approval, true);
});

test("pending lists open requests; --json returns the array; --subject filters", () => {
  const reg = join(dir, "pending.jsonl");
  run(["request", "fs.write", "src/**", "--subject", "a1", "--reason", "r1", "--registry", reg]);
  run(["request", "net.fetch", "api.x.com", "--subject", "a2", "--reason", "r2", "--registry", reg]);

  const human = run(["pending", "--registry", reg]);
  assert.equal(human.status, 0);
  assert.match(human.stdout, /fs\.write on src/);

  const all = JSON.parse(run(["pending", "--registry", reg, "--json"]).stdout);
  assert.equal(all.length, 2);

  const filtered = JSON.parse(run(["pending", "--registry", reg, "--subject", "a2", "--json"]).stdout);
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].subject, "a2");
});

test("pending on an empty registry → 'no pending requests', exit 0", () => {
  const r = run(["pending", "--registry", join(dir, "pending-empty.jsonl")]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /no pending requests/);
});

test("approve mints a just-in-time grant that then passes check", () => {
  const reg = join(dir, "approve.jsonl");
  const req = JSON.parse(
    run(["request", "fs.write", "src/auth/**", "--subject", "a1", "--reason", "patch",
      "--registry", reg, "--json"]).stdout
  );

  const ap = run(["approve", req.id, "--approver", "human", "--ttl", "10m", "--registry", reg]);
  assert.equal(ap.status, 0, ap.stderr);
  assert.match(ap.stdout, /approved/);

  // The decision landed as a record; the request now resolves to approved.
  const records = readRegistry(reg);
  assert.equal(records.length, 2);
  assert.ok(records.some((r) => r.type === "decision" && r.decision === "approve"));
  assert.match(run(["pending", "--registry", reg]).stdout, /no pending requests/);

  // The minted grant authorizes the exact action.
  const chk = run(["check", "fs.write", "src/auth/login.ts", "--subject", "a1", "--registry", reg]);
  assert.equal(chk.status, 0, chk.stderr);
  assert.match(chk.stdout, /allowed/);

  // It shows up in list as an active grant for a1, parented to the request.
  const listed = JSON.parse(run(["list", "--registry", reg, "--json"]).stdout);
  assert.equal(listed.length, 1);
  assert.equal(listed[0].subject, "a1");
  assert.equal(listed[0].parent, req.id);
});

test("approve --json emits the decision carrying grant_ttl_seconds", () => {
  const reg = join(dir, "approve-json.jsonl");
  const req = JSON.parse(
    run(["request", "fs.write", "src/**", "--subject", "a1", "--reason", "r",
      "--registry", reg, "--json"]).stdout
  );
  const dec = JSON.parse(
    run(["approve", req.id, "--approver", "human", "--ttl", "20m", "--registry", reg, "--json"]).stdout
  );
  assert.equal(dec.type, "decision");
  assert.equal(dec.decision, "approve");
  assert.equal(dec.request_id, req.id);
  assert.equal(dec.grant_ttl_seconds, 1200);
});

test("approve requires a --ttl (the minted grant's lifetime)", () => {
  const reg = join(dir, "approve-nottl.jsonl");
  const req = JSON.parse(
    run(["request", "fs.write", "src/**", "--subject", "a1", "--reason", "r",
      "--registry", reg, "--json"]).stdout
  );
  const r = run(["approve", req.id, "--approver", "human", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /requires --ttl/);
});

test("approve resolves by an unambiguous id prefix", () => {
  const reg = join(dir, "approve-prefix.jsonl");
  const req = JSON.parse(
    run(["request", "fs.write", "src/**", "--subject", "a1", "--reason", "r",
      "--registry", reg, "--json"]).stdout
  );
  const r = run(["approve", req.id.slice(0, 8), "--approver", "human", "--ttl", "5m", "--registry", reg]);
  assert.equal(r.status, 0, r.stderr);
});

test("approve of an unknown request id → error, exit 1", () => {
  const reg = join(dir, "approve-unknown.jsonl");
  run(["request", "fs.write", "src/**", "--subject", "a1", "--reason", "r", "--registry", reg]);
  const r = run(["approve", "deadbeefdeadbeef", "--approver", "human", "--ttl", "5m", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /no approval request with id/);
});

test("deny leaves the request refused, mints nothing, and check is a hard deny", () => {
  const reg = join(dir, "deny.jsonl");
  const req = JSON.parse(
    run(["request", "fs.write", "src/auth/**", "--subject", "a1", "--reason", "patch",
      "--registry", reg, "--json"]).stdout
  );

  const dn = run(["deny", req.id, "--approver", "human", "--reason", "too risky", "--registry", reg]);
  assert.equal(dn.status, 0, dn.stderr);
  assert.match(dn.stdout, /denied/);

  // No active grants minted; the request is off the pending list.
  assert.match(run(["list", "--registry", reg]).stdout, /no active grants/);
  assert.match(run(["pending", "--registry", reg]).stdout, /no pending requests/);

  // check is now a plain deny (not needs_approval — the request was resolved).
  const j = JSON.parse(
    run(["check", "fs.write", "src/auth/login.ts", "--subject", "a1", "--registry", reg, "--json"]).stdout
  );
  assert.equal(j.allowed, false);
  assert.equal(j.needs_approval, false);
});

test("deny rejects a --ttl (nothing is minted)", () => {
  const reg = join(dir, "deny-ttl.jsonl");
  const req = JSON.parse(
    run(["request", "fs.write", "src/**", "--subject", "a1", "--reason", "r",
      "--registry", reg, "--json"]).stdout
  );
  const r = run(["deny", req.id, "--approver", "human", "--ttl", "5m", "--registry", reg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /--ttl is not valid/);
});

test("approve/deny take the approver from CAPGRANT_ISSUER when --approver is omitted", () => {
  const reg = join(dir, "approve-env.jsonl");
  const req = JSON.parse(
    run(["request", "fs.write", "src/**", "--subject", "a1", "--reason", "r",
      "--registry", reg, "--json"]).stdout
  );
  const dec = JSON.parse(
    run(["approve", req.id, "--ttl", "5m", "--registry", reg, "--json"], { CAPGRANT_ISSUER: "boss" }).stdout
  );
  assert.equal(dec.approver, "boss");
});

// --- hook (CLI) ------------------------------------------------------------

test("hook without a subcommand → usage, exit 1", () => {
  const r = run(["hook"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /requires a subcommand/);
});

test("hook with an unknown subcommand → error, exit 1", () => {
  const r = run(["hook", "frobnicate"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /unknown hook subcommand/);
});
