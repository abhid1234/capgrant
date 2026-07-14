// capgrant — `check` core (pure authorization decision over the capability engine).
//
// The pre-action gate: given a requested `action` on a `resource` and a resolved
// registry of grants, decide whether some live grant AUTHORIZES it. No
// filesystem, no clock — `now` is injected so expiry is deterministic in tests.
// A concrete path is a degenerate glob and an action is a dotted hierarchy, so
// the whole decision reduces to scanning for one grant that (a) is live for the
// asking subject and (b) holds a capability that COVERS the request.

import { capabilityCovers } from "./capability.js";
import { shortId } from "./registry.js";

// check(action, resource, grants, opts) → { allowed, matched_grant, reason }
//
//   opts.subject — the agent asking; only grants whose `subject` matches are
//                  considered (a grant for another agent never authorizes you).
//                  If null/undefined, subject is not filtered.
//   opts.now     — epoch ms used to evaluate `expires`; injected for determinism.
//
// Scans in registry order (sorted by soonest expiry) for the FIRST grant that is
// status "active", not expired at `now`, matches `subject`, and carries some
// capability covering `action`+`resource`. First match → allowed. On no match,
// the `reason` is specific — it distinguishes an empty registry, no grant for
// the subject, an out-of-scope request, an expired grant, and a revoked grant —
// so the caller can tell "you were never granted this" from "your grant lapsed".
export function check(action, resource, grants, opts = {}) {
  const { subject = null, now = Date.now() } = opts;

  let sawSubjectMatch = false; // some grant is for this subject
  let sawActiveInScopeMiss = false; // a live subject grant existed but didn't cover
  let sawExpired = false; // a subject grant matched but had lapsed
  let sawRevoked = false; // a subject grant matched but was revoked

  for (const grant of grants) {
    if (subject != null && grant.subject !== subject) continue;
    sawSubjectMatch = true;

    if (grant.status === "revoked") {
      sawRevoked = true;
      continue;
    }
    if (grant.status === "expired") {
      sawExpired = true;
      continue;
    }
    if (grant.status !== "active") continue;

    // Wall-clock expiry check (belt-and-suspenders alongside the resolved
    // status, so a caller who passes an unexpired-but-stale array is still safe).
    if (grant.expires != null) {
      const exp = Date.parse(grant.expires);
      if (!Number.isNaN(exp) && exp <= now) {
        sawExpired = true;
        continue;
      }
    }

    const caps = Array.isArray(grant.capabilities) ? grant.capabilities : [];
    const cap = caps.find((c) => capabilityCovers(c, action, resource));
    if (cap) {
      return {
        allowed: true,
        matched_grant: grant,
        reason: `authorized by grant ${shortId(grant.id)}: "${cap.action}" on "${cap.resource}"`,
      };
    }
    sawActiveInScopeMiss = true;
  }

  return { allowed: false, matched_grant: null, reason: denialReason() };

  function denialReason() {
    const who = subject != null ? `subject "${subject}"` : "the subject";
    if (grants.length === 0) return "denied: no grants in the registry";
    if (subject != null && !sawSubjectMatch) return `denied: no grant for ${who}`;
    if (sawActiveInScopeMiss) {
      return `denied: "${action}" on "${resource}" is outside the scope of ${who}'s active grants`;
    }
    if (sawExpired) return `denied: ${who}'s matching grant(s) have expired`;
    if (sawRevoked) return `denied: ${who}'s matching grant(s) were revoked`;
    return `denied: no active grant authorizes "${action}" on "${resource}" for ${who}`;
  }
}
