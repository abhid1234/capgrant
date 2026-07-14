// capgrant — browser port of the grant / delegation / revocation constructors.
//
// The record builders from src/grant.js, copied with their REAL invariant checks
// intact — `requireNonEmptyString` / `requirePositiveInt` / `requireIso` /
// `requireCapabilities`, the delegable-only + subset-only (no privilege
// escalation, via `capabilityCovers`) + expiry-containment invariants in
// `delegate`, and the `revoke` shape. The ONLY change from the Node source is
// that `computeRecordId` is async here (WebCrypto), so `makeGrant` / `delegate`
// / `revoke` are `async` and `await` the id. Every validation and every invariant
// is unchanged — a malformed or privilege-escalating grant still throws.

import { computeRecordId } from "./registry-browser.js";
import { validateCapability } from "./schema.js";
import { capabilityCoverage, constraintsSubsume } from "./capability.js";

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

// created + ttl_seconds as an ISO-8601-UTC string, to the millisecond.
function isoAddSeconds(created, ttl_seconds) {
  return new Date(Date.parse(created) + ttl_seconds * 1000).toISOString();
}

// Validate a capabilities array (non-empty, each a well-formed capability),
// throwing the first structural problem. [VERBATIM]
function requireCapabilities(capabilities) {
  if (!Array.isArray(capabilities) || capabilities.length === 0) {
    fail("capabilities must be a non-empty array");
  }
  capabilities.forEach((cap, i) => {
    const res = validateCapability(cap, `capabilities[${i}].`);
    if (!res.valid) {
      const first = res.errors[0];
      fail(`${first.path}: ${first.message}`);
    }
  });
}

// makeGrant(capabilities, meta) → a grant record in canonical GRANT_FIELDS
// order, with `expires` computed from `created + ttl_seconds` and a
// content-hash `id`. Throws on any invalid input. [async id only]
export async function makeGrant(capabilities, meta = {}) {
  const { issuer, subject, ttl_seconds, created, delegable = false, parent } = meta;

  requireNonEmptyString(issuer, "issuer");
  requireNonEmptyString(subject, "subject");
  requirePositiveInt(ttl_seconds, "ttl_seconds");
  requireIso(created, "created");
  requireCapabilities(capabilities);
  if (typeof delegable !== "boolean") fail("delegable must be a boolean");
  if (parent !== undefined) requireNonEmptyString(parent, "parent");

  const expires = isoAddSeconds(created, ttl_seconds);

  const record = {
    type: "grant",
    issuer,
    subject,
    capabilities,
    ttl_seconds,
    created,
    expires,
    delegable,
    ...(parent !== undefined ? { parent } : {}),
    status: "active",
  };
  return { id: await computeRecordId(record), ...record };
}

// delegate(parentGrant, capabilities, meta) → a sub-grant whose `parent` is
// `parentGrant.id`. Enforces the three delegation invariants and throws if any
// is violated:
//   1. the parent must be `delegable`;
//   2. NO PRIVILEGE ESCALATION — every delegated capability must be COVERED by
//      some capability the parent holds (its action+resource axes must fall
//      inside a parent cap) AND, if that parent cap carries constraints, the
//      delegated cap may only TIGHTEN them, never loosen (`constraintsSubsume`);
//   3. the sub-grant must not outlive the parent. [async id only]
export async function delegate(parentGrant, capabilities, meta = {}) {
  if (!parentGrant || typeof parentGrant !== "object") {
    fail("delegate requires a parent grant object");
  }
  if (parentGrant.delegable !== true) {
    fail("parent grant is not delegable");
  }
  requireCapabilities(capabilities);

  // 2. Subset check: each requested capability must fall inside some parent
  //    capability's authority — its action+resource axes must be covered by a
  //    parent cap AND (when that parent cap constrains a dimension) the child's
  //    constraints must only tighten it. We test the axes with `capabilityCoverage`
  //    (not `capabilityCovers`) so the parent's constraints are NOT evaluated as
  //    if the child's resource pattern were a concrete request — constraint
  //    containment is a separate, structural `constraintsSubsume` check.
  const parentCaps = Array.isArray(parentGrant.capabilities) ? parentGrant.capabilities : [];
  capabilities.forEach((cap, i) => {
    const covered = parentCaps.some(
      (pc) =>
        capabilityCoverage(pc, cap.action, cap.resource).axes &&
        constraintsSubsume(pc.constraints, cap.constraints)
    );
    if (!covered) {
      fail(
        `capabilities[${i}] (${cap.action} on ${cap.resource}) exceeds the parent grant's authority`
      );
    }
  });

  // Build the sub-grant (validates issuer/subject/ttl/created and stamps parent).
  const { issuer, subject, ttl_seconds, created } = meta;
  const sub = await makeGrant(capabilities, {
    issuer,
    subject,
    ttl_seconds,
    created,
    parent: parentGrant.id,
  });

  // 3. Expiry containment.
  if (Date.parse(sub.expires) > Date.parse(parentGrant.expires)) {
    fail(
      `sub-grant expires ${sub.expires} after the parent grant (${parentGrant.expires})`
    );
  }

  return sub;
}

// revoke(grantId, meta) → a revocation record that withdraws `grantId`. Pure;
// throws on missing/invalid input. Applying it (and cascading to any delegated
// children) happens at read time in `resolveRecords`. [async id only]
export async function revoke(grantId, meta = {}) {
  requireNonEmptyString(grantId, "grantId");
  const { issuer, reason, at } = meta;
  requireNonEmptyString(issuer, "issuer");
  requireNonEmptyString(reason, "reason");
  requireIso(at, "at");

  const record = {
    type: "revocation",
    grant_id: grantId,
    issuer,
    reason,
    at,
  };
  return { id: await computeRecordId(record), ...record };
}

// parseTtl(input) → integer seconds, or null on anything invalid. [VERBATIM]
export function parseTtl(input) {
  if (typeof input === "number") {
    return Number.isInteger(input) && input > 0 ? input : null;
  }
  if (typeof input !== "string") return null;

  const s = input.trim();
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    return n > 0 ? n : null; // bare seconds; "0" → null
  }

  const m = /^(\d+)(s|m|h|d)$/.exec(s);
  if (!m) return null;
  const n = Number(m[1]);
  if (n <= 0) return null; // "0m" → null
  const mult = { s: 1, m: 60, h: 3600, d: 86400 }[m[2]];
  return n * mult;
}
