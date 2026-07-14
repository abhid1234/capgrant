// capgrant — human-in-the-loop approval: request + decision constructors.
//
// capgrant's grants answer "what is this agent PRE-authorized to do." This
// module is the missing other half: when an action is NOT covered by a live
// grant, instead of a flat DENY the agent can raise an APPROVAL REQUEST to a
// human, and the human's DECISION to approve MINTS a scoped, expiring grant for
// exactly that action — the "just-in-time" grant. So the authorization story is
// complete: grant ahead of time OR request → approve just in time.
//
// Like the grant/revocation constructors, these THROW a clear Error on invalid
// input rather than emit a malformed record: an approval flow is a security
// artifact too. There is NO I/O and NO clock here — `created` / `at` are
// injected, so every record is fully determined by its inputs and unit-testable;
// the CLI is the only part that reads the wall clock and appends to the store.
// The FOLD (a request's status, and the grant an approval mints) lives in
// `resolveRecords` (registry.js), so a raw append log resolves to live grants.

import { computeRecordId } from "./registry.js";
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
  // Accept any Date-parseable string here (a NaN parse is an immediate hard
  // failure) and let the record validator enforce strict ISO-8601-UTC
  // downstream — the same contract the grant constructors use for `created`.
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
// once a decision folds in. Throws on any invalid input.
//
//   meta.subject      — the agent the (eventual) grant would be for
//   meta.reason       — why the action is needed (the human reads this)
//   meta.requested_by — who raised the request (often the subject itself)
//   meta.created      — ISO-8601-UTC timestamp the request is raised at
export function requestApproval(action, resource, meta = {}) {
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
  return { id: computeRecordId(record), ...record };
}

// decide(request, meta) → a decision record that resolves an approval_request.
// An `approve` decision, when folded by `resolveRecords`, MINTS a grant for the
// request's subject/action/resource that expires `grant_ttl_seconds` after this
// decision's `at` — the just-in-time grant. A `deny` decision simply leaves the
// request denied and mints nothing. Throws on any invalid input.
//
//   request                — the approval_request being decided (its `id` is
//                            stamped as `request_id`)
//   meta.approver          — the human (or authority) making the call
//   meta.decision          — "approve" | "deny"
//   meta.at                — ISO-8601-UTC timestamp of the decision (a minted
//                            grant's `created`)
//   meta.reason            — optional note explaining the decision
//   meta.grant_ttl_seconds — REQUIRED on an approve (a minted grant is always
//                            expiring); rejected on a deny (nothing is minted)
export function decide(request, meta = {}) {
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
  return { id: computeRecordId(record), ...record };
}
