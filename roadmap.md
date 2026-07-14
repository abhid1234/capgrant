# capgrant — roadmap

## Direction
- Zero runtime dependencies. Always. (`node:` builtins only.)
- Advisory-first: the format expresses and audits authority; it never pretends
  to be a sandbox. A real gate (the git hook) is opt-in and warns by default.
- Pure core + thin I/O edge. Every decision (`check`, `audit`, capability
  matching) is a pure function over injected `now`; only the registry store and
  the git adapter touch the filesystem.
- Content-addressed, append-only registry — a grant's `id` is its content hash,
  so the log never merge-conflicts with itself even when many agents write.

## Shipped (v0.1)
- `makeGrant` / `delegate` / `revoke` / `parseTtl` record constructors.
- Capability engine: dotted-hierarchy `actionImplies`, glob/host `resourceMatches`,
  `capabilityCovers`.
- `check` — pure pre-action authorization decision with a specific denial reason.
- `audit` — after-the-fact in-scope score over a batch of actions.
- Append-only JSONL registry with cascade-aware revocation and TTL expiry.
- Non-throwing schema validators for grants, revocations, and registries.
- git pre-commit adapter (advisory by default, `CAPGRANT_ENFORCE=1` to block).
- CLI: `grant`, `check`, `list`, `revoke`, `delegate`, `audit`, `hook`, `validate`.

## Shipped (v0.2)
- Capability `constraints` semantics — the optional `constraints` object now has
  real matching meaning in `capabilityCovers` / `check`: `max_bytes`, per-request
  `max_calls` / `rate` budgets, a `methods` allow-list, and a `path_depth` cap. A
  covered request that violates one is DENIED with the specific constraint named.
  Stateless and advisory; fully backward-compatible (no `constraints` ⇒ v0.1
  behavior). Delegation subset checks enforce TIGHTEN-only — a delegated cap may
  only narrow a constraint, never loosen it (`constraintsSubsume`).
- Signed grants (`src/sign.js`) — layered, optional tamper-evidence over the same
  canonical pre-image the content-hash id is built from: detached-or-embedded
  HMAC-SHA256 (`signHmac` / `verifyHmac`) and zero-config ed25519 (`generateKeypair`
  / `signAsym` / `verifyAsym`), all `node:crypto`, zero-dep. Signers throw on a bad
  key; verifiers never throw (a bad sig/key is simply unverified).

## Shipped (v0.3)
- Human-in-the-loop (HITL) approval (`src/approval.js`) — the other half of the
  authorization story. When no live grant covers an action, an agent raises an
  `approval_request` instead of taking a flat DENY; a human's `decision` to
  approve MINTS a scoped, expiring **just-in-time grant** for exactly that
  subject/action/resource (expiring `grant_ttl_seconds` after the decision),
  parented to the request. So authority is either granted ahead of time OR
  requested → approved just in time.
  - `requestApproval(action, resource, { subject, reason, requested_by, created })`
    and `decide(request, { approver, decision, at, reason?, grant_ttl_seconds? })`
    record constructors — throw on bad input, like the grant constructors.
  - `resolveRecords` now folds `approval_request` + `decision` records too: a
    request's status derives to `approved`/`denied`/`pending`, and an approved
    request yields a live grant that participates in `check`/`audit` exactly like
    any grant. Still pure, deterministic, and tolerant — a bad record is noted,
    never thrown.
  - `check` gained an additive `needs_approval` flag: when no grant covers the
    request but a matching PENDING request exists, the deny is *soft*
    (`needs_approval: true`) rather than flat. `allowed` is unchanged — fully
    backward-compatible.
  - Non-throwing `validateApprovalRequest` / `validateDecision` validators.
  - CLI: `request`, `approve`, `deny`, `pending`.

## Near-term (aligned — welcome)
- More action namespaces documented (a small conventional vocabulary:
  `fs.* net.* proc.* git.* deploy.*`).
- Harness adapters that read a session's actual tool calls and `audit` them.
- CLI + git-hook surfacing for constraints and signature verification.

## Out of scope (for now)
- Actual syscall/network enforcement or a sandbox runtime.
- A central authorization server or online revocation lists.
- Runtime dependencies of any kind.
