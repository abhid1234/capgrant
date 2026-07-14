// capgrant — the capability-matching engine (pure, zero-dependency).
//
// This is the heart that makes capgrant an AUTHORIZATION format rather than a
// coordination one: given a capability a grant confers and a concrete action a
// subject wants to perform, does the grant COVER it? Two independent axes have
// to line up — the action hierarchy and the resource pattern — and both are
// pure, total functions over strings, so a `check` is deterministic and needs
// no clock or filesystem.
//
//   action axis   — a dotted hierarchy (`fs` ⊇ `fs.write` ⊇ `fs.write.foo`),
//                   with `*` at the top. IMPLICATION FLOWS DOWNWARD ONLY: a
//                   broader grant covers a narrower request, never the reverse.
//   resource axis — a pattern matched against a concrete/requested resource,
//                   reusing the zero-dep `globsOverlap` engine for path-like
//                   resources and exact equality for opaque ones (hosts, ids).

import { globsOverlap } from "./glob.js";

// actionImplies(granted, requested) → does holding `granted` authorize doing
// `requested`? Dot segments form the hierarchy:
//   - `*` implies everything.
//   - equal actions imply each other.
//   - a granted action implies a requested one iff granted is a segment-wise
//     PREFIX of requested — `fs` implies `fs.write` and `fs.write.foo`, but
//     `fs.write` does NOT imply `fs` (narrower never grants broader).
export function actionImplies(granted, requested) {
  if (granted === "*") return true;
  if (typeof granted !== "string" || typeof requested !== "string") return false;
  if (granted === requested) return true;

  const g = granted.split(".");
  const r = requested.split(".");
  if (g.length > r.length) return false; // granted is deeper ⇒ narrower ⇒ can't cover
  for (let i = 0; i < g.length; i++) {
    if (g[i] !== r[i]) return false; // segments must match on the shared prefix
  }
  return true; // granted is a proper prefix of requested ⇒ implies it
}

// resourceMatches(pattern, resource) → does a grant's resource `pattern` apply
// to a concrete/requested `resource`?
//   - `*` matches any resource.
//   - if EITHER side looks glob-like (contains `*` or `/`), defer to
//     `globsOverlap` — a concrete path is just a degenerate (wildcard-free)
//     glob, so `src/**` vs `src/auth.js` and `src/**` vs `src/*` both resolve
//     through the one satisfiability engine.
//   - otherwise both are opaque tokens (a host, an id, a bare name) → exact,
//     case-sensitive string equality.
export function resourceMatches(pattern, resource) {
  if (pattern === "*") return true;
  if (typeof pattern !== "string" || typeof resource !== "string") return false;
  const globLike = (s) => s.includes("*") || s.includes("/");
  if (globLike(pattern) || globLike(resource)) return globsOverlap(pattern, resource);
  return pattern === resource;
}

// capabilityCovers(cap, action, resource) → does a single `{action, resource}`
// capability authorize the requested action on the requested resource? Both
// axes must line up: the capability's action must IMPLY the requested action
// AND its resource pattern must MATCH the requested resource. This is the atom
// `check` and `audit` scan for.
export function capabilityCovers(cap, action, resource) {
  if (!cap || typeof cap !== "object") return false;
  return actionImplies(cap.action, action) && resourceMatches(cap.resource, resource);
}
