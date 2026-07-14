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

## Near-term (aligned — welcome)
- More action namespaces documented (a small conventional vocabulary:
  `fs.* net.* proc.* git.* deploy.*`).
- `constraints` on a capability (e.g. rate, byte cap) — the field exists; give it
  matching semantics in `capabilityCovers`.
- Harness adapters that read a session's actual tool calls and `audit` them.
- Signed grants (detached HMAC/Ed25519) for tamper-evidence across trust domains.

## Out of scope (for now)
- Actual syscall/network enforcement or a sandbox runtime.
- A central authorization server or online revocation lists.
- Runtime dependencies of any kind.
