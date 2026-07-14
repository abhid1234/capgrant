import { test } from "node:test";
import assert from "node:assert/strict";
import { requestApproval, decide } from "../src/approval.js";
import { resolveRecords, computeRecordId, shortId } from "../src/registry.js";
import { check } from "../src/check.js";
import { validateApprovalRequest, validateDecision } from "../src/schema.js";
import { makeGrant } from "../src/grant.js";

// A fixed clock so expiry is deterministic. Request created 12:00; a decision at
// 12:05 mints a grant of ttl 600 → expires 12:15.
const CREATED = "2026-07-11T12:00:00Z";
const DECIDED = "2026-07-11T12:05:00Z";
const NOW = Date.parse("2026-07-11T12:10:00Z"); // inside a 12:05+600s lease
const AFTER = Date.parse("2026-07-11T12:20:00Z"); // past a 12:05+600s lease

const REQ_META = {
  subject: "agent-A",
  reason: "need to write the fix",
  requested_by: "agent-A",
  created: CREATED,
};

// --- requestApproval: shape + throws ---------------------------------------

test("requestApproval builds a well-formed, valid approval_request", () => {
  const req = requestApproval("fs.write", "src/auth/**", REQ_META);
  assert.equal(validateApprovalRequest(req).valid, true);
  assert.equal(req.type, "approval_request");
  assert.equal(req.subject, "agent-A");
  assert.equal(req.action, "fs.write");
  assert.equal(req.resource, "src/auth/**");
  assert.equal(req.reason, "need to write the fix");
  assert.equal(req.requested_by, "agent-A");
  assert.equal(req.created, CREATED);
  assert.equal(req.status, "pending");
});

test("requestApproval field order is canonical", () => {
  const req = requestApproval("fs.write", "src/**", REQ_META);
  assert.deepEqual(Object.keys(req), [
    "id",
    "type",
    "subject",
    "action",
    "resource",
    "reason",
    "requested_by",
    "created",
    "status",
  ]);
});

test("requestApproval id is the deterministic content hash", () => {
  const req = requestApproval("fs.write", "src/**", REQ_META);
  assert.match(req.id, /^[0-9a-f]{64}$/);
  const { id, ...rest } = req;
  assert.equal(id, computeRecordId(rest));
  assert.equal(requestApproval("fs.write", "src/**", REQ_META).id, req.id);
});

test("requestApproval throws on an invalid action", () => {
  assert.throws(() => requestApproval("NOPE", "src/**", REQ_META), /action/);
  assert.throws(() => requestApproval("", "src/**", REQ_META), /action/);
});

test("requestApproval throws on empty resource / subject / reason / requested_by", () => {
  assert.throws(() => requestApproval("fs.write", "", REQ_META), /resource/);
  assert.throws(() => requestApproval("fs.write", "src/**", { ...REQ_META, subject: "" }), /subject/);
  assert.throws(() => requestApproval("fs.write", "src/**", { ...REQ_META, reason: "  " }), /reason/);
  assert.throws(
    () => requestApproval("fs.write", "src/**", { ...REQ_META, requested_by: undefined }),
    /requested_by/
  );
});

test("requestApproval throws on an unparseable created", () => {
  assert.throws(() => requestApproval("fs.write", "src/**", { ...REQ_META, created: "nope" }), /created/);
});

// --- decide: shape + throws ------------------------------------------------

function pendingReq() {
  return requestApproval("fs.write", "src/auth/**", REQ_META);
}

test("decide builds a valid approve decision that carries grant_ttl_seconds", () => {
  const req = pendingReq();
  const dec = decide(req, { approver: "human", decision: "approve", at: DECIDED, grant_ttl_seconds: 600 });
  assert.equal(validateDecision(dec).valid, true);
  assert.equal(dec.type, "decision");
  assert.equal(dec.request_id, req.id);
  assert.equal(dec.decision, "approve");
  assert.equal(dec.approver, "human");
  assert.equal(dec.at, DECIDED);
  assert.equal(dec.grant_ttl_seconds, 600);
  assert.match(dec.id, /^[0-9a-f]{64}$/);
  const { id, ...rest } = dec;
  assert.equal(id, computeRecordId(rest));
});

test("decide field order is canonical (approve, with optional reason)", () => {
  const req = pendingReq();
  const dec = decide(req, {
    approver: "human",
    decision: "approve",
    at: DECIDED,
    reason: "looks safe",
    grant_ttl_seconds: 600,
  });
  assert.deepEqual(Object.keys(dec), [
    "id",
    "type",
    "request_id",
    "decision",
    "approver",
    "reason",
    "at",
    "grant_ttl_seconds",
  ]);
});

test("decide builds a valid deny decision that mints nothing (no grant_ttl_seconds)", () => {
  const req = pendingReq();
  const dec = decide(req, { approver: "human", decision: "deny", at: DECIDED });
  assert.equal(validateDecision(dec).valid, true);
  assert.equal(dec.decision, "deny");
  assert.ok(!("grant_ttl_seconds" in dec));
  assert.deepEqual(Object.keys(dec), ["id", "type", "request_id", "decision", "approver", "at"]);
});

test("decide throws on an invalid decision value", () => {
  const req = pendingReq();
  assert.throws(() => decide(req, { approver: "h", decision: "maybe", at: DECIDED }), /decision/);
});

test("decide throws on empty approver / bad at", () => {
  const req = pendingReq();
  assert.throws(() => decide(req, { approver: "", decision: "deny", at: DECIDED }), /approver/);
  assert.throws(() => decide(req, { approver: "h", decision: "deny", at: "nope" }), /at/);
});

test("decide requires grant_ttl_seconds on an approve (a minted grant is always expiring)", () => {
  const req = pendingReq();
  assert.throws(() => decide(req, { approver: "h", decision: "approve", at: DECIDED }), /grant_ttl_seconds/);
  assert.throws(
    () => decide(req, { approver: "h", decision: "approve", at: DECIDED, grant_ttl_seconds: 0 }),
    /grant_ttl_seconds/
  );
});

test("decide rejects grant_ttl_seconds on a deny (nothing is minted)", () => {
  const req = pendingReq();
  assert.throws(
    () => decide(req, { approver: "h", decision: "deny", at: DECIDED, grant_ttl_seconds: 600 }),
    /grant_ttl_seconds/
  );
});

test("decide throws on a non-object request or a request with no id", () => {
  assert.throws(() => decide(null, { approver: "h", decision: "deny", at: DECIDED }), /approval_request/);
  assert.throws(() => decide({}, { approver: "h", decision: "deny", at: DECIDED }), /request\.id/);
});

// --- resolveRecords: fold pending → approved → live grant -------------------

test("a lone request with no decision stays pending and mints nothing", () => {
  const req = pendingReq();
  const { grants, requests } = resolveRecords([req], { now: NOW });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].status, "pending");
  assert.equal(grants.length, 0);
});

test("an approve folds the request to approved AND mints a live grant", () => {
  const req = pendingReq();
  const dec = decide(req, { approver: "human", decision: "approve", at: DECIDED, grant_ttl_seconds: 600 });
  const { grants, requests, notes } = resolveRecords([req, dec], { now: NOW });

  // Request derived to approved.
  assert.equal(requests.length, 1);
  assert.equal(requests[0].status, "approved");
  assert.equal(requests[0].decided_by, "human");
  assert.equal(requests[0].decided_at, DECIDED);

  // A single just-in-time grant, parented to the request, for the exact scope.
  assert.equal(grants.length, 1);
  const g = grants[0];
  assert.equal(g.type, "grant");
  assert.equal(g.status, "active");
  assert.equal(g.subject, "agent-A");
  assert.equal(g.issuer, "human");
  assert.equal(g.parent, req.id);
  assert.deepEqual(g.capabilities, [{ action: "fs.write", resource: "src/auth/**" }]);
  assert.equal(g.ttl_seconds, 600);
  assert.equal(g.created, DECIDED);
  assert.equal(Date.parse(g.expires), Date.parse(DECIDED) + 600 * 1000);
  // Content-hash id holds for the minted grant too.
  const { id, ...rest } = g;
  assert.equal(id, computeRecordId(rest));
  assert.ok(notes.some((n) => /approved → minted grant/.test(n)));
});

test("a deny folds the request to denied and mints nothing", () => {
  const req = pendingReq();
  const dec = decide(req, { approver: "human", decision: "deny", at: DECIDED, reason: "too risky" });
  const { grants, requests } = resolveRecords([req, dec], { now: NOW });
  assert.equal(requests[0].status, "denied");
  assert.equal(requests[0].decided_by, "human");
  assert.equal(requests[0].decided_reason, "too risky");
  assert.equal(grants.length, 0);
});

test("the latest decision wins (deny then approve → approved + minted)", () => {
  const req = pendingReq();
  const deny = decide(req, { approver: "human", decision: "deny", at: "2026-07-11T12:03:00Z" });
  const approve = decide(req, { approver: "human", decision: "approve", at: DECIDED, grant_ttl_seconds: 600 });
  const { grants, requests } = resolveRecords([req, deny, approve], { now: NOW });
  assert.equal(requests[0].status, "approved");
  assert.equal(grants.length, 1);
});

test("the latest decision wins (approve then deny → denied, nothing minted)", () => {
  const req = pendingReq();
  const approve = decide(req, {
    approver: "human",
    decision: "approve",
    at: "2026-07-11T12:03:00Z",
    grant_ttl_seconds: 600,
  });
  const deny = decide(req, { approver: "human", decision: "deny", at: DECIDED });
  const { grants, requests } = resolveRecords([req, approve, deny], { now: NOW });
  assert.equal(requests[0].status, "denied");
  assert.equal(grants.length, 0);
});

test("a decision for an unknown request_id is ignored with a note", () => {
  const dec = { type: "decision", request_id: "no-such-request", decision: "deny", approver: "h", at: DECIDED };
  dec.id = computeRecordId(dec);
  const { grants, requests, notes } = resolveRecords([dec], { now: NOW });
  assert.equal(requests.length, 0);
  assert.equal(grants.length, 0);
  assert.ok(notes.some((n) => /unknown request_id/.test(n)));
});

test("resolveRecords never throws on malformed approval records", () => {
  assert.doesNotThrow(() =>
    resolveRecords([{ type: "decision" }, { type: "approval_request" }, null], { now: NOW })
  );
});

// --- the minted grant participates in check --------------------------------

test("an approved request's minted grant passes check for its subject", () => {
  const req = pendingReq();
  const dec = decide(req, { approver: "human", decision: "approve", at: DECIDED, grant_ttl_seconds: 600 });
  const { grants } = resolveRecords([req, dec], { now: NOW });
  const res = check("fs.write", "src/auth/login.ts", grants, { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, true);
  assert.match(res.reason, /authorized by grant/);
});

test("the minted grant's TTL expires (check denies past the lease)", () => {
  const req = pendingReq();
  const dec = decide(req, { approver: "human", decision: "approve", at: DECIDED, grant_ttl_seconds: 600 });
  // Resolve AFTER the lease → the minted grant is derived to expired.
  const { grants } = resolveRecords([req, dec], { now: AFTER });
  assert.equal(grants.length, 1);
  assert.equal(grants[0].status, "expired");
  const res = check("fs.write", "src/auth/login.ts", grants, { subject: "agent-A", now: AFTER });
  assert.equal(res.allowed, false);
  assert.match(res.reason, /expired/);
});

test("a minted grant only authorizes the approved subject, not another agent", () => {
  const req = pendingReq();
  const dec = decide(req, { approver: "human", decision: "approve", at: DECIDED, grant_ttl_seconds: 600 });
  const { grants } = resolveRecords([req, dec], { now: NOW });
  const res = check("fs.write", "src/auth/login.ts", grants, { subject: "agent-B", now: NOW });
  assert.equal(res.allowed, false);
});

// --- check: needs_approval for a pending request ---------------------------

test("check returns needs_approval for a matching PENDING request", () => {
  const req = pendingReq();
  const { grants, requests } = resolveRecords([req], { now: NOW });
  const res = check("fs.write", "src/auth/login.ts", grants, {
    subject: "agent-A",
    now: NOW,
    requests,
  });
  assert.equal(res.allowed, false);
  assert.equal(res.needs_approval, true);
  assert.equal(res.request_id, req.id);
  assert.match(res.reason, /no grant — request approval/);
});

test("needs_approval requires the pending request's subject/action/resource to match", () => {
  const req = pendingReq(); // agent-A wants fs.write on src/auth/**
  const { grants, requests } = resolveRecords([req], { now: NOW });
  // Different subject → hard deny, not needs_approval.
  const other = check("fs.write", "src/auth/login.ts", grants, { subject: "agent-B", now: NOW, requests });
  assert.equal(other.needs_approval, false);
  // Different action → hard deny.
  const act = check("proc.exec", "src/auth/login.ts", grants, { subject: "agent-A", now: NOW, requests });
  assert.equal(act.needs_approval, false);
});

test("once approved, check allows (not needs_approval) — the pending request is gone", () => {
  const req = pendingReq();
  const dec = decide(req, { approver: "human", decision: "approve", at: DECIDED, grant_ttl_seconds: 600 });
  const { grants, requests } = resolveRecords([req, dec], { now: NOW });
  const res = check("fs.write", "src/auth/login.ts", grants, { subject: "agent-A", now: NOW, requests });
  assert.equal(res.allowed, true);
  assert.equal(res.needs_approval, false);
});

test("a denied request does NOT trigger needs_approval (it is a hard deny)", () => {
  const req = pendingReq();
  const dec = decide(req, { approver: "human", decision: "deny", at: DECIDED });
  const { grants, requests } = resolveRecords([req, dec], { now: NOW });
  const res = check("fs.write", "src/auth/login.ts", grants, { subject: "agent-A", now: NOW, requests });
  assert.equal(res.allowed, false);
  assert.equal(res.needs_approval, false);
});

test("check without a requests array is backward-compatible (needs_approval false)", () => {
  const res = check("fs.write", "src/a.js", [], { subject: "agent-A", now: NOW });
  assert.equal(res.allowed, false);
  assert.equal(res.needs_approval, false);
});

// --- end-to-end: a real grant still wins over a pending request ------------

test("a live grant authorizes even while a pending request exists (grant wins)", () => {
  const grant = makeGrant([{ action: "fs.write", resource: "src/**" }], {
    issuer: "alice",
    subject: "agent-A",
    ttl_seconds: 1800,
    created: CREATED,
  });
  const req = requestApproval("fs.write", "src/auth/**", REQ_META);
  const { grants, requests } = resolveRecords([grant, req], { now: NOW });
  const res = check("fs.write", "src/auth/login.ts", grants, { subject: "agent-A", now: NOW, requests });
  assert.equal(res.allowed, true);
  assert.equal(res.needs_approval, false);
});
