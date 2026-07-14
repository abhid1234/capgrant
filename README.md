# capgrant

**The open format for scoped, expiring agent capability grants.** An issuer grants an agent a set of *capabilities* — "you may `fs.write` under `src/**` for the next 30 minutes" — to a shared, append-only registry. Before it acts, the agent `check`s whether a live grant authorizes the action; after the fact, an `audit` scores whether the fleet stayed in scope. So a fleet of agents stops running with unbounded ambient authority, and you can prove afterward that each one stayed in bounds. Zero dependencies.

> Working name — see [`vision.md`](vision.md). Grounded in the mid-2026 state of multi-agent coding.

A fleet of AI coding agents runs with far too much ambient authority. Each agent can usually write anywhere, run anything, and reach any network endpoint the process can — because the harness, not the task, defines the blast radius (Claude Code, Codex, Cursor, Google Antigravity all inherit the same broad process permissions). The ecosystem standardized how agents *call* tools (MCP) and how they *hand off* tasks (A2A), but not the **authority** an agent carries: what it may do, over what, for how long, and who said so. capgrant is the missing authorization layer: an open format for *scoped intent*, not another sandbox.

```bash
npx @avee1234/capgrant grant --issuer alice --subject builder --cap "fs.write:src/**" --ttl 30m
npx @avee1234/capgrant check fs.write src/auth/login.ts --subject builder   # allowed? exit 0/1
npx @avee1234/capgrant list                                                  # who holds what, expiring when
npx @avee1234/capgrant delegate --parent <id> --subject reviewer --cap "fs.write:src/auth/**"
npx @avee1234/capgrant revoke <id> --reason "task done"                      # cascades to delegated children
npx @avee1234/capgrant audit actions.json                                    # did the fleet stay in scope?
npx @avee1234/capgrant hook install                                          # check staged writes before every commit
```

**Why it's different:** advisory *and* verifiable, not a sandbox — capgrant doesn't intercept syscalls, it's the shared *format* any harness can read and write. The registry is append-only JSONL with content-hash IDs, so it never merge-conflicts with itself even when many agents write at once. Least privilege that composes: grants **delegate** (a delegable grant mints a strictly narrower sub-grant) and revocation **cascades** down the delegation chain, so authority can only narrow as it flows outward and pulling one grant pulls everything derived from it. Harness-neutral: Claude Code, Codex, Cursor, Google Antigravity, or a factory worker.

Same open-format-and-conformance playbook as [worklease](https://github.com/abhid1234/worklease) (coordination) and [provenant](https://github.com/abhid1234/provenant) (provenance) — the authorization standard for the one thing a fleet can't currently express: *what each agent is allowed to do, over what, for how long, and who said so.*

## The grant format

A grant is one JSON object. `id` is the sha256 content hash of the record itself (its own `id` excluded), so a record's identity *is* its content — a tampered line no longer matches its id and is dropped on read. `expires` is `created + ttl_seconds`, so the lease is self-describing.

```json
{
  "id": "9f2c1a…",
  "type": "grant",
  "issuer": "alice",
  "subject": "builder",
  "capabilities": [
    { "action": "fs.write", "resource": "src/**" },
    { "action": "net.fetch", "resource": "api.github.com" }
  ],
  "ttl_seconds": 1800,
  "created": "2026-07-11T12:00:00Z",
  "expires": "2026-07-11T12:30:00Z",
  "delegable": true,
  "status": "active"
}
```

- `issuer` — **who** is granting the authority.
- `subject` — **which agent** the grant is for (only its own grants ever authorize it).
- `capabilities` — **what**: one or more `{ action, resource }` leaves (`constraints` optional, reserved).
- `ttl_seconds` / `created` / `expires` — **for how long** (an ISO-8601-**UTC** lease; offsets and impossible calendar dates are rejected).
- `delegable` — may the subject mint a strictly narrower sub-grant?
- `parent` *(delegated grants only)* — the parent grant's id (revocation cascades along it).

A **revocation** withdraws a grant: `{ id, type: "revocation", grant_id, issuer, reason, at }`. Revocations are appended, never deletions — the registry stays append-only, and the resolver folds them in (and cascades them) at read time.

## The model

Two independent axes must both line up for a capability to **cover** a request — this is what makes capgrant an *authorization* format, not a coordination one:

- **Action hierarchy** — a dotted namespace where implication flows **downward only**. `fs` implies `fs.write` and `fs.write.foo`; `fs.write` does **not** imply `fs` (narrower never grants broader); `*` implies anything. A broader grant covers a narrower request, never the reverse.
- **Resource patterns** — `*` matches anything; a glob-like resource (`src/**`, `src/*`) resolves through a zero-dependency glob-overlap engine (a concrete path is a degenerate glob, so the check is correct even for a file that doesn't exist yet); an opaque token (a host, an id) is matched by exact equality.
- **TTL** — a grant with `expires ≤ now` is derived to `expired` at read time; the stored log is never rewritten.
- **Delegation** — a `delegable` grant can mint a sub-grant, subject to three invariants: the parent must be delegable, every delegated capability must be **covered** by some parent capability (no privilege escalation), and the sub-grant must not outlive the parent.
- **Cascade revocation** — revoking a grant revokes every grant whose parent chain leads back to it, to a fixed point, so one revocation collapses an entire delegation subtree.

## Library API

Zero-dependency ESM. `import { … } from "@avee1234/capgrant"`. Every core function is pure and clock-injected (`created` / `now` are passed in, no I/O except the registry store), so the whole decision layer is deterministic and unit-testable.

**Schema & validation** — never throw; each returns `{ valid, errors }` collecting *every* violation.
- `validateGrant(obj)` / `validateCapability(obj)` / `validateRevocation(obj)` / `validateRegistry(arr)`
- `isDottedAction(s)`, `isIso8601Utc(s)` — the two format primitives
- `GRANT_FIELDS`, `CAPABILITY_FIELDS`, `STATUSES`, `RECORD_TYPES`, `ERROR_CODES`

**Capability engine** — pure, total matching over strings.
- `actionImplies(granted, requested)` — the downward-only action hierarchy
- `resourceMatches(pattern, resource)` — `*` / glob-overlap / exact-token matching
- `capabilityCovers(cap, action, resource)` — both axes must hold
- `globsOverlap(a, b)` — the zero-dep glob satisfiability engine

**Record constructors** — throw on bad input rather than emit a malformed (or escalating) grant.
- `makeGrant(capabilities, { issuer, subject, ttl_seconds, created, delegable, parent })`
- `delegate(parentGrant, capabilities, { issuer, subject, ttl_seconds, created })` — enforces the delegation invariants
- `revoke(grantId, { issuer, reason, at })`
- `parseTtl(input)` — `30s` / `20m` / `2h` / `1d` / bare seconds → integer seconds, or `null`

**Registry store** — the append-only JSONL layer.
- `loadRegistry(path, { now, expire })` → `{ grants, notes }` (missing file → empty, no throw)
- `appendRecord(path, record)` — append exactly one line (`O_APPEND`); existing lines are never rewritten
- `resolveRecords(records, { now, expire })` — fold a raw log into the current grant set (integrity filter, revocations, cascade, TTL)
- `defaultRegistryPath(cwd)` — `CAPGRANT_REGISTRY`, else `.capgrant/registry.jsonl`
- `canonicalize`, `computeRecordId`, `listActive`, `formatRelative`, `shortId`

**Decide & audit** — pure, over a resolved grant array.
- `check(action, resource, grants, { subject, now })` → `{ allowed, matched_grant, reason }` (specific denial reasons)
- `audit(actions, grants, { now })` → `{ score, total, allowed, violations }`

**Git adapter** *(the dogfood surface)*
- `stagedPaths`, `checkStagedWrites(paths, { registry, subject, now })`, `installHook`, `hookPath`, `renderHookBlock`

## CLI

```bash
capgrant grant --issuer <id> --subject <id> --cap <action:resource> [...] [--ttl <dur>] [--delegable] [--registry <path>] [--json]
capgrant check <action> <resource> --subject <id> [--registry <path>] [--json]
capgrant list [--all] [--subject <id>] [--registry <path>] [--json]
capgrant delegate --parent <id> --issuer <id> --subject <id> --cap <action:resource> [...] --ttl <dur> [--registry <path>] [--json]
capgrant revoke <id> --issuer <id> --reason "<why>" [--registry <path>] [--json]
capgrant audit <actions.json> [--registry <path>] [--json]
capgrant hook install|run [--registry <path>] [--json]
capgrant validate <file> [--json]
```

- **`grant`** — issue a scoped, expiring grant: the subject may perform each `<action>` on each `<resource>` until it expires. Repeat `--cap` for multiple capabilities. The record is validated before it's written. Exit `0` on write.
- **`check <action> <resource>`** — the pre-action gate: does a live grant for `--subject` authorize this? Exit `0` = allowed, `1` = denied (with a specific reason — empty registry, no grant for the subject, out of scope, expired, or revoked).
- **`list`** — active grants (who holds what, expiring when). `--all` also shows revoked/expired grants labeled with their effective status; `--subject` filters to one holder.
- **`delegate`** — mint a narrower sub-grant from a delegable parent (full id or unambiguous prefix). Every capability must fall inside the parent's authority and it cannot outlive the parent. Exit `1` on any escalation.
- **`revoke <id> --reason`** — withdraw a grant by appending a revocation; **cascades** to any grant delegated from it. A no-op with a note if already revoked (still exit `0`).
- **`audit <actions.json>`** — replay a JSON array of `{ action, resource, subject, at? }` and score how many stayed in scope (each `at` is that action's `now`, so a grant that was live *then* counts even if it has since expired). Exit `0` = all in scope, `1` = at least one violation.
- **`validate <file>`** — validate a grant, revocation, or registry JSON file (auto-detected). Exit `1` if invalid.

Common flags: `--issuer <id>` (or `CAPGRANT_ISSUER`), `--subject <id>` (or `CAPGRANT_AGENT`), `--registry <path>` (or `CAPGRANT_REGISTRY`, default `.capgrant/registry.jsonl`), `--json` for machine-readable output.

## The git-hook dogfood

`capgrant hook install` writes a **git pre-commit hook** that treats a commit as a batch of `fs.write` actions — one per staged path — and `check`s each against the committing agent's grants. A path the agent has no `fs.write` grant for is an out-of-scope write.

```bash
capgrant hook install            # advisory: warns on out-of-scope writes, never blocks a commit
CAPGRANT_ENFORCE=1 git commit …  # enforce mode: an out-of-scope write aborts the commit (exit 1)
```

The hook is **advisory by default** (vision principle: coordinate, don't enforce) — it prints the out-of-scope writes and lets the commit through. Set `CAPGRANT_ENFORCE=1` in the commit environment to make an out-of-scope write fatal, and `CAPGRANT_AGENT` to the committing agent's id so its own grants count. Install is **idempotent** and **preserves an existing hook** — it manages only a marked block (`# >>> capgrant >>>` … `# <<< capgrant <<<`), so re-running it never duplicates the block or clobbers hand-written hook logic.

## The registry

The store is an **append-only JSONL file** (default `.capgrant/registry.jsonl`), meant to be **committed** so grants travel with the repo across worktrees and harnesses. New records are appended as whole lines; existing lines are never rewritten. Every record's `id` is a content hash of its own content, so a duplicated append is idempotent on read and two agents appending at once union-merge cleanly instead of conflicting. A line that fails its integrity check (its `id` no longer matches its content — i.e. it was tampered) or won't parse is skipped with a note surfaced to stderr — one bad line never discards the rest of the registry.

## Install

```bash
npm install @avee1234/capgrant      # library
npx @avee1234/capgrant grant …      # CLI, no install
```

Requires Node ≥ 18. Run the test suite with `node --test`.

Status: **v0.1** — see [`roadmap.md`](roadmap.md). MIT · zero dependencies · harness-neutral.
