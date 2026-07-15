// capgrant — browser port of the human-in-the-loop approval constructors.
//
// The request + decision record builders from src/approval.js, copied with their
// REAL invariant checks intact — `requireNonEmptyString` / `requirePositiveInt` /
// `requireIso` / `requireDottedAction`, the pending-status stamp on a request,
// and the approve-only `grant_ttl_seconds` rule on a decision. The ONLY change
// from the Node source is that `computeRecordId` is async here (WebCrypto), so
// `requestApproval` / `decide` are `async` and `await` the id. Every validation
// is unchanged — a malformed request or decision still throws. The FOLD (a
// request's status, and the just-in-time grant an approval mints) lives in
// `resolveRecords` (registry-browser.js).

import { computeRecordId } from "./registry-browser.js";
import { isDottedAction } from "./schema.js";

function fail(msg) {
  throw new Error(`capgrant: ${msg}`);
}

function requireNonEmptyString(value, name) {
  if (typeof value !== "string" || value.trim().length === 0) {
    fail(`${name} must be a non-empty string`);
  }
}

function requirePositiveInt(value, name) {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    fail(`${name} must be a positive integer`);
  }
}

function requireIso(value, name) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    fail(`${name} must be an ISO-8601 timestamp`);
  }
}

// requireDottedAction(action) — the requested action must be a dotted,
// hierarchical action (or the `*` wildcard), exactly like a capability's action,
// so a minted grant's capability is always well-formed.
function requireDottedAction(value, name) {
  requireNonEmptyString(value, name);
  if (!isDottedAction(value)) {
    fail(`${name} must be dotted lowercase segments (e.g. fs.write) or *`);
  }
}

// requestApproval(action, resource, meta) → an approval_request record in
// canonical field order with a content-hash `id`. It records that some subject
// wants to perform `action` on `resource` and needs a human to say yes; its
// `status` starts "pending" and is derived to "approved"/"denied" at read time
// once a decision folds in. Throws on any invalid input. [async id only]
export async function requestApproval(action, resource, meta = {}) {
  const { subject, reason, requested_by, created } = meta;

  requireDottedAction(action, "action");
  requireNonEmptyString(resource, "resource");
  requireNonEmptyString(subject, "subject");
  requireNonEmptyString(reason, "reason");
  requireNonEmptyString(requested_by, "requested_by");
  requireIso(created, "created");

  const record = {
    type: "approval_request",
    subject,
    action,
    resource,
    reason,
    requested_by,
    created,
    status: "pending",
  };
  return { id: await computeRecordId(record), ...record };
}

// decide(request, meta) → a decision record that resolves an approval_request.
// An `approve` decision, when folded by `resolveRecords`, MINTS a grant for the
// request's subject/action/resource that expires `grant_ttl_seconds` after this
// decision's `at` — the just-in-time grant. A `deny` decision simply leaves the
// request denied and mints nothing. Throws on any invalid input. [async id only]
export async function decide(request, meta = {}) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    fail("decide requires an approval_request object");
  }
  requireNonEmptyString(request.id, "request.id");

  const { approver, decision, at, reason, grant_ttl_seconds } = meta;

  requireNonEmptyString(approver, "approver");
  if (decision !== "approve" && decision !== "deny") {
    fail('decision must be "approve" or "deny"');
  }
  requireIso(at, "at");
  if (reason !== undefined) requireNonEmptyString(reason, "reason");
  if (decision === "approve") {
    requirePositiveInt(grant_ttl_seconds, "grant_ttl_seconds");
  } else if (grant_ttl_seconds !== undefined) {
    fail("grant_ttl_seconds is only valid on an approve decision");
  }

  // Build in canonical field order; `reason` and `grant_ttl_seconds` are present
  // only when they apply, so a bare deny has neither key.
  const record = {
    type: "decision",
    request_id: request.id,
    decision,
    approver,
    ...(reason !== undefined ? { reason } : {}),
    at,
    ...(decision === "approve" ? { grant_ttl_seconds } : {}),
  };
  return { id: await computeRecordId(record), ...record };
}
