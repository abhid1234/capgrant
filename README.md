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
- `capabilities` — **what**: one or more `{ action, resource }` leaves, each with an optional `constraints` object (byte cap, per-request budget, method allow-list, path-depth cap — see [Capability constraints](#capability-constraints)).
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

### Capability constraints

Beyond the two axes, a capability may carry an optional `constraints` object — extra conditions a covered request must **also** satisfy. They are **advisory and stateless**: capgrant keeps no counters, so a constraint scores the budget a *single request declares for itself* against the cap the grant permits. A request passes its context (`{ bytes, method, calls, rate }`) to `check`; if a covering capability has constraints the request violates, it's **denied with the specific constraint named** (`"… within scope of grant a1b2c3d4 but violates constraint max_bytes: 5000 > 4096"`).

```json
{ "action": "net.fetch", "resource": "api.github.com",
  "constraints": { "methods": ["GET", "HEAD"], "max_bytes": 1048576, "rate": 5 } }
```

| constraint | request context | semantics |
| --- | --- | --- |
| `max_bytes` (number) | `bytes` | the request's declared payload size must be **≤** the cap |
| `max_calls` (number) | `calls` | a per-request declared call budget must stay **≤** the cap (stateless — the budget one request claims, not a running total) |
| `rate` (number) | `rate` | a per-request declared requests-per-interval figure must stay **≤** the cap |
| `methods` (array) | `method` | for `net.*` actions, the request's method must be **in** the allowed set (case-sensitive) |
| `path_depth` (number) | *(the resource itself)* | the concrete resource's depth — its count of `/`-separated segments — must be **≤** the cap |

Two rules keep it safe and compatible:

- **Backward-compatible.** A capability with no `constraints` behaves exactly as v0.1, and a `check` with no request context still works — a numeric/method constraint only bites when the request *declares* that dimension (a request that declares nothing is unconstrained on that axis). `path_depth` is the one exception: a request always has a resource, so it always applies. Unknown constraint keys are ignored (forward-compat), never a silent denial.
- **Delegation can only TIGHTEN.** A delegated capability may narrow a constraint (a smaller `max_bytes`, a subset of `methods`) or add one to a dimension the parent left open — never loosen it. Dropping a cap the parent set (which would mean "unlimited") is a privilege escalation and is refused, exactly like widening the action or resource.

## Library API

Zero-dependency ESM. `import { … } from "@avee1234/capgrant"`. Every core function is pure and clock-injected (`created` / `now` are passed in, no I/O except the registry store), so the whole decision layer is deterministic and unit-testable.

**Schema & validation** — never throw; each returns `{ valid, errors }` collecting *every* violation.
- `validateGrant(obj)` / `validateCapability(obj)` / `validateRevocation(obj)` / `validateRegistry(arr)`
- `validateApprovalRequest(obj)` / `validateDecision(obj)` — the HITL record validators
- `isDottedAction(s)`, `isIso8601Utc(s)` — the two format primitives
- `GRANT_FIELDS`, `CAPABILITY_FIELDS`, `STATUSES`, `RECORD_TYPES`, `ERROR_CODES`

**Capability engine** — pure, total matching over strings.
- `actionImplies(granted, requested)` — the downward-only action hierarchy
- `resourceMatches(pattern, resource)` — `*` / glob-overlap / exact-token matching
- `capabilityCovers(cap, action, resource, requestContext?)` — both axes hold **and** constraints are satisfied
- `capabilityCoverage(cap, action, resource, requestContext?)` → `{ axes, violation }` — the richer atom `check` uses to report *why*
- `constraintViolation(constraints, ctx)` → `null` or the first violated constraint (`"max_bytes: 5000 > 4096"`)
- `constraintsSubsume(parent, child)` — is the child constraint set no looser than the parent's? (the delegation tighten-only rule)
- `resourceDepth(resource)`, `CONSTRAINT_KEYS`
- `globsOverlap(a, b)` — the zero-dep glob satisfiability engine

**Record constructors** — throw on bad input rather than emit a malformed (or escalating) grant.
- `makeGrant(capabilities, { issuer, subject, ttl_seconds, created, delegable, parent })`
- `delegate(parentGrant, capabilities, { issuer, subject, ttl_seconds, created })` — enforces the delegation invariants
- `revoke(grantId, { issuer, reason, at })`
- `requestApproval(action, resource, { subject, reason, requested_by, created })` — raise an `approval_request` (HITL)
- `decide(request, { approver, decision, at, reason?, grant_ttl_seconds? })` — a `decision`; an `approve` mints the just-in-time grant on fold
- `parseTtl(input)` — `30s` / `20m` / `2h` / `1d` / bare seconds → integer seconds, or `null`

**Registry store** — the append-only JSONL layer.
- `loadRegistry(path, { now, expire })` → `{ grants, requests, notes }` (missing file → empty, no throw)
- `appendRecord(path, record)` — append exactly one line (`O_APPEND`); existing lines are never rewritten
- `resolveRecords(records, { now, expire })` → `{ grants, requests, notes }` — fold a raw log into the current grant set **and** approval-request set (integrity filter, revocations, cascade, TTL, plus HITL: request status + any just-in-time grant an approval minted)
- `defaultRegistryPath(cwd)` — `CAPGRANT_REGISTRY`, else `.capgrant/registry.jsonl`
- `canonicalize`, `computeRecordId`, `listActive`, `formatRelative`, `shortId`

**Decide & audit** — pure, over a resolved grant array.
- `check(action, resource, grants, { subject, now, bytes?, method?, calls?, rate?, request?, requests? })` → `{ allowed, needs_approval, matched_grant, reason }` (request context scores a constrained grant; specific denial reasons, including the violated constraint; pass the resolved `requests` and a soft deny sets `needs_approval: true` when a matching PENDING request exists — `allowed` is unchanged and additive)
- `audit(actions, grants, { now })` → `{ score, total, allowed, violations }` (each action may carry `bytes` / `method` / `calls` / `rate`)

**Signed grants** — layered, optional tamper-evidence across trust domains (`node:crypto`, zero-dep). Signers throw on a bad key; verifiers never throw.
- `signHmac(record, secret)` / `verifyHmac(record, secret, sigHex?)` — shared-secret HMAC-SHA256 (detached or embedded `signature`)
- `generateKeypair()` → `{ publicKey, privateKey }` PEM
- `signAsym(record, privateKeyPem)` / `verifyAsym(record, publicKeyPem, sigHex?)` — ed25519 (deterministic, RFC 8032)

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
capgrant request <action> <resource> --subject <id> --reason "<why>" [--requested-by <id>] [--registry <path>] [--json]
capgrant approve <request-id> --approver <id> --ttl <dur> [--registry <path>] [--json]
capgrant deny <request-id> --approver <id> [--reason "<why>"] [--registry <path>] [--json]
capgrant pending [--subject <id>] [--registry <path>] [--json]
capgrant hook install|run [--registry <path>] [--json]
capgrant validate <file> [--json]
```

- **`grant`** — issue a scoped, expiring grant: the subject may perform each `<action>` on each `<resource>` until it expires. Repeat `--cap` for multiple capabilities. The record is validated before it's written. Exit `0` on write.
- **`check <action> <resource>`** — the pre-action gate: does a live grant for `--subject` authorize this? Exit `0` = allowed, `1` = denied (with a specific reason — empty registry, no grant for the subject, out of scope, expired, or revoked).
- **`list`** — active grants (who holds what, expiring when). `--all` also shows revoked/expired grants labeled with their effective status; `--subject` filters to one holder.
- **`delegate`** — mint a narrower sub-grant from a delegable parent (full id or unambiguous prefix). Every capability must fall inside the parent's authority and it cannot outlive the parent. Exit `1` on any escalation.
- **`revoke <id> --reason`** — withdraw a grant by appending a revocation; **cascades** to any grant delegated from it. A no-op with a note if already revoked (still exit `0`).
- **`audit <actions.json>`** — replay a JSON array of `{ action, resource, subject, at? }` and score how many stayed in scope (each `at` is that action's `now`, so a grant that was live *then* counts even if it has since expired). Exit `0` = all in scope, `1` = at least one violation.
- **`request <action> <resource>`** — raise a **human-in-the-loop approval request** for an action no live grant covers. Its status starts `pending`; `--requested-by` defaults to the subject. Exit `0` on write.
- **`approve <request-id> --approver --ttl <dur>`** — approve a pending request (full id or unambiguous prefix), minting a **just-in-time grant** that expires `--ttl` after the decision. Exit `0` on write.
- **`deny <request-id> --approver [--reason]`** — deny a pending request; nothing is minted. Exit `0` on write.
- **`pending`** — list approval requests still awaiting a decision (`--subject` filters to one holder).
- **`validate <file>`** — validate a grant, revocation, approval_request, decision, or registry JSON file (auto-detected). Exit `1` if invalid.

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

## Human-in-the-loop approval

A grant answers *"what is this agent **pre**-authorized to do."* But real fleets hit actions no live grant covers — and a flat `DENY` there is exactly the "agent permission fatigue" that stalls autonomy. capgrant closes the loop: instead of denying, the agent raises an **approval request** to a human, and the human's **decision** to approve **mints a scoped, expiring grant for exactly that action** — the *just-in-time* grant. Authority is now either granted ahead of time **or** requested → approved just in time, over the same append-only log, with the same content-hash ids and pure, clock-injected fold.

Two new record types join the registry:

- **`approval_request`** — `{ subject, action, resource, reason, requested_by, created, status:'pending' }`. Some agent wants to perform `action` on `resource` and needs a human to say yes.
- **`decision`** — `{ request_id, decision:'approve'|'deny', approver, at, reason?, grant_ttl_seconds? }`. An `approve` mints a grant for the request's subject/action/resource that expires `grant_ttl_seconds` after the decision's `at`, **parented to the request** so its provenance is the approval.

`resolveRecords` folds both: a request's status derives to `approved` / `denied` / `pending` from its latest decision, and an approved request **yields a live grant that participates in `check` / `audit` exactly like any grant** (it's minted at read time, never appended — the log stays append-only). `check` gained an additive `needs_approval` flag: when no grant covers the request but a matching **pending** request exists, the deny is *soft* (`needs_approval: true`) rather than flat — a signal a human can turn into a grant. `allowed` is unchanged, so the whole feature is backward-compatible.

```js
import { requestApproval, decide, resolveRecords, check } from "@avee1234/capgrant";

// 1. No live grant covers this — the agent asks instead of taking a hard deny.
const req = requestApproval("fs.write", "src/auth/login.ts", {
  subject: "agent-42",
  reason: "hotfix the login redirect",
  requested_by: "agent-42",
  created: "2026-07-14T10:00:00.000Z",
});

// check sees the pending request → soft deny, not a flat deny.
const t1 = Date.parse("2026-07-14T10:01:00Z");
let { grants, requests } = resolveRecords([req], { now: t1 });
check("fs.write", "src/auth/login.ts", grants, { subject: "agent-42", now: t1, requests });
// → { allowed: false, needs_approval: true, reason: "no grant — request approval …" }

// 2. A human approves with a 10-minute TTL → a just-in-time grant is minted on fold.
const dec = decide(req, {
  approver: "abhi",
  decision: "approve",
  at: "2026-07-14T10:02:00.000Z",
  grant_ttl_seconds: 600,
});

const t2 = Date.parse("2026-07-14T10:03:00Z");   // inside the 10-min TTL
({ grants } = resolveRecords([req, dec], { now: t2 }));
check("fs.write", "src/auth/login.ts", grants, { subject: "agent-42", now: t2 });
// → { allowed: true, needs_approval: false, matched_grant: <minted grant>, … }

// …and after the 10-minute TTL that minted grant expires like any TTL grant.
const t3 = Date.parse("2026-07-14T10:20:00Z");
({ grants } = resolveRecords([req, dec], { now: t3 }));
check("fs.write", "src/auth/login.ts", grants, { subject: "agent-42", now: t3 });
// → { allowed: false, needs_approval: false, reason: "denied: … have expired" }
```

On the CLI this is `request` → `approve` / `deny`, with `pending` to list what's waiting:

```bash
capgrant request fs.write src/auth/login.ts --subject agent-42 --reason "hotfix the login redirect"
capgrant pending                                   # what's awaiting a human
capgrant approve <request-id> --approver abhi --ttl 10m   # mints the just-in-time grant
capgrant deny <request-id> --approver abhi --reason "not this file"
```

The approval flow is harness-neutral: Claude Code, Codex, Cursor, or Google Antigravity can all raise a request an operator approves — the request and the minted grant are just records in the shared registry.

## Signed grants

The content-hash `id` makes a record self-verifying **within** one trust domain — a tampered line no longer matches its id and is dropped on read. But an id is *integrity*, not *authorship*: anyone can recompute it. When a grant or revocation crosses a trust boundary — one team's registry consumed by another, a grant minted by a service you don't share a filesystem with — you want to prove **who** stood behind it. `src/sign.js` adds two optional, layered schemes over the same canonical, id-excluded pre-image the hash is built from (with any `signature` field stripped first, so a signature is never part of its own pre-image and an **embedded** signature verifies identically to a **detached** one).

```js
import { signHmac, verifyHmac, generateKeypair, signAsym, verifyAsym } from "@avee1234/capgrant";

// HMAC — shared secret, cheapest.
const sig = signHmac(grant, process.env.CAPGRANT_SECRET);       // hex, deterministic
verifyHmac(grant, process.env.CAPGRANT_SECRET, sig);            // → true (detached)
verifyHmac({ ...grant, signature: sig }, process.env.CAPGRANT_SECRET); // → true (embedded)

// ed25519 — asymmetric, no shared secret; the holder of the private key signs.
const { publicKey, privateKey } = generateKeypair();            // PEM
const asig = signAsym(grant, privateKey);                       // hex, deterministic (RFC 8032)
verifyAsym(grant, publicKey, asig);                             // → true
```

- **HMAC** (`signHmac` / `verifyHmac`) — an HMAC-SHA256 both parties can compute from a shared secret.
- **ed25519** (`generateKeypair` / `signAsym` / `verifyAsym`) — an asymmetric signature: the signer holds the private key, anyone with the public key verifies, no shared secret. Zero-config (ed25519 needs no parameters) and deterministic.
- **Signers throw** on a bad key or record (like the record constructors — you should never emit a broken signature). **Verifiers never throw** — a missing, malformed, or wrong-typed signature or key is simply an *unverified* record (`false`), never an exception, so a verification loop can't be crashed by hostile input.

Both layers are advisory and composable — sign with either, both, or neither; the registry, `check`, and `audit` are unchanged by a `signature` field (it's excluded from the pre-image, so it never perturbs the id or a decision). It's harness-neutral tamper-evidence, not a new gate.

## Install

```bash
npm install @avee1234/capgrant      # library
npx @avee1234/capgrant grant …      # CLI, no install
```

Requires Node ≥ 18. Run the test suite with `node --test`.

Status: **v0.3** — human-in-the-loop approval (request → approve → just-in-time grant), on top of capability constraints + signed grants (HMAC / ed25519); see [`roadmap.md`](roadmap.md). MIT · zero dependencies · harness-neutral.
