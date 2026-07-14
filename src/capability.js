// capgrant — the capability-matching engine (pure, zero-dependency).
//
// This is the heart that makes capgrant an AUTHORIZATION format rather than a
// coordination one: given a capability a grant confers and a concrete action a
// subject wants to perform, does the grant COVER it? Two independent axes have
// to line up — the action hierarchy and the resource pattern — and, when the
// capability carries them, a set of optional CONSTRAINTS the request must also
// satisfy. All of it is pure, total functions over strings/numbers, so a
// `check` is deterministic and needs no clock or filesystem.
//
//   action axis   — a dotted hierarchy (`fs` ⊇ `fs.write` ⊇ `fs.write.foo`),
//                   with `*` at the top. IMPLICATION FLOWS DOWNWARD ONLY: a
//                   broader grant covers a narrower request, never the reverse.
//   resource axis — a pattern matched against a concrete/requested resource,
//                   reusing the zero-dep `globsOverlap` engine for path-like
//                   resources and exact equality for opaque ones (hosts, ids).
//   constraints   — a small, documented set of extra conditions a covered
//                   request must ALSO meet (a byte cap, a per-request budget, an
//                   HTTP-method allow-list, a resource-depth cap). Advisory and
//                   STATELESS — capgrant keeps no counters; a constraint scores
//                   the budget a single request declares for itself.

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

// The documented constraint vocabulary a capability may carry. Everything else
// in a `constraints` object is forward-compat noise, ignored here (never a
// silent denial), so the format can grow new conditions without breaking old
// checkers. Each key below is a self-contained, STATELESS predicate over the
// budget a single request declares for itself — capgrant holds no counters.
export const CONSTRAINT_KEYS = ["max_bytes", "max_calls", "rate", "methods", "path_depth"];

// resourceDepth(resource) → the path depth of a concrete resource: the count of
// non-empty `/`-separated segments. `src/auth/login.ts` → 3, `src` → 1, `*` → 1.
// Used only by the `path_depth` constraint, evaluated against the CONCRETE
// requested resource (never a pattern).
export function resourceDepth(resource) {
  if (typeof resource !== "string") return 0;
  return resource.split("/").filter((seg) => seg.length > 0).length;
}

// constraintViolation(constraints, ctx) → null if the request satisfies every
// constraint, else a short human string naming the FIRST one it violates (the
// exact tail `check` reports, e.g. `max_bytes: 5000 > 4096`). Pure and total —
// a null/absent `constraints`, or a request that simply doesn't DECLARE the
// dimension a constraint governs, is treated as satisfied. That is the advisory
// contract: a constraint scores the budget a request declares for itself, so a
// request that declares nothing is unconstrained on that axis (the `path_depth`
// axis is the exception — a request always has a resource, so it always
// applies). `ctx` fields: `bytes`, `calls`, `rate` (numbers the request
// declares), `method` (string), and `resource` (the concrete request resource).
export function constraintViolation(constraints, ctx = {}) {
  if (!constraints || typeof constraints !== "object") return null;
  const c = constraints;
  const q = ctx || {};

  // max_bytes — the request's declared payload size must fit under the cap.
  if (typeof c.max_bytes === "number" && typeof q.bytes === "number") {
    if (q.bytes > c.max_bytes) return `max_bytes: ${q.bytes} > ${c.max_bytes}`;
  }
  // max_calls — a per-request DECLARED call budget the request must stay within
  // (stateless: capgrant never counts calls across requests; it checks the
  // budget one request claims for itself against the cap the grant permits).
  if (typeof c.max_calls === "number" && typeof q.calls === "number") {
    if (q.calls > c.max_calls) return `max_calls: ${q.calls} > ${c.max_calls}`;
  }
  // rate — same per-request declared-budget semantics as max_calls, for a
  // requests-per-interval figure the request declares (e.g. `rate: 5`).
  if (typeof c.rate === "number" && typeof q.rate === "number") {
    if (q.rate > c.rate) return `rate: ${q.rate} > ${c.rate}`;
  }
  // methods — for net.* style actions, the request's `method` must be in the
  // allowed set (case-sensitive, as HTTP methods are conventionally upper-case).
  if (Array.isArray(c.methods) && q.method != null) {
    if (!c.methods.includes(q.method)) {
      return `methods: "${q.method}" not in {${c.methods.join(", ")}}`;
    }
  }
  // path_depth — the CONCRETE resource's depth must not exceed the cap, so a
  // grant for `src/**` can still forbid reaching too deep into the tree.
  if (typeof c.path_depth === "number" && typeof q.resource === "string") {
    const depth = resourceDepth(q.resource);
    if (depth > c.path_depth) return `path_depth: ${depth} > ${c.path_depth}`;
  }
  return null;
}

// constraintsSubsume(parent, child) → does the CHILD constraint set confer no
// more authority than the PARENT's? The delegation rule: a delegated capability
// may only ever TIGHTEN a constraint, never loosen it.
//   - a numeric cap (`max_bytes`/`max_calls`/`rate`/`path_depth`) the parent
//     sets must be present on the child and no larger (omitting it on the child
//     would mean "unlimited" — strictly looser — so it's rejected);
//   - a `methods` allow-list the parent sets requires the child to declare a
//     SUBSET (omitting it means "any method" — looser — so it's rejected);
//   - a dimension the parent does NOT constrain the child may freely add
//     (adding a cap only narrows authority) or leave open.
export function constraintsSubsume(parent, child) {
  const p = parent && typeof parent === "object" ? parent : {};
  const c = child && typeof child === "object" ? child : {};
  for (const key of ["max_bytes", "max_calls", "rate", "path_depth"]) {
    if (typeof p[key] === "number") {
      if (typeof c[key] !== "number" || c[key] > p[key]) return false;
    }
  }
  if (Array.isArray(p.methods)) {
    if (!Array.isArray(c.methods)) return false;
    for (const m of c.methods) if (!p.methods.includes(m)) return false;
  }
  return true;
}

// capabilityCoverage(cap, action, resource, requestContext) → { axes, violation }
// The full atom, separating the two failure modes `check` reports differently:
//   axes      — do BOTH the action hierarchy and the resource pattern line up?
//   violation — when `axes` holds, null if the request satisfies the cap's
//               constraints, else the first constraint it violates. The concrete
//               `resource` is always folded into the context so `path_depth`
//               evaluates against the real request, whatever the caller passed.
export function capabilityCoverage(cap, action, resource, requestContext) {
  if (!cap || typeof cap !== "object") return { axes: false, violation: null };
  const axes = actionImplies(cap.action, action) && resourceMatches(cap.resource, resource);
  if (!axes) return { axes: false, violation: null };
  const violation = constraintViolation(cap.constraints, { ...requestContext, resource });
  return { axes: true, violation };
}

// capabilityCovers(cap, action, resource, requestContext?) → does a single
// `{action, resource, constraints?}` capability authorize the requested action
// on the requested resource? Both axes must line up AND — when the capability
// carries constraints — the request must satisfy them. Fully backward
// compatible: a cap with no constraints (or a call with no request context)
// reduces to the v0.1 two-axis test. This is the atom `check` and `audit` scan
// for; `check` uses `capabilityCoverage` directly to report WHY a covered-but-
// constrained request was denied.
export function capabilityCovers(cap, action, resource, requestContext) {
  const cov = capabilityCoverage(cap, action, resource, requestContext);
  return cov.axes && cov.violation == null;
}
