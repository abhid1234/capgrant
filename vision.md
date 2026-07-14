# capgrant — vision

## The gap
A fleet of AI coding agents runs with far too much ambient authority. Each agent
can usually write anywhere, run anything, and reach any network endpoint the
process can — because the harness, not the task, defines the blast radius. When
one agent goes off the rails (a bad tool call, a prompt injection, a confused
sub-task), nothing scoped it to the work it was actually asked to do, and nothing
lets you prove afterward that it stayed in bounds.

The ecosystem standardized how agents *call* tools (MCP) and how they *hand off*
tasks (A2A). It has not standardized the **authority** an agent carries: what it
is allowed to do, over what, for how long, and who said so. That is the gap
capgrant fills.

## The idea
capgrant is an open, portable format for **scoped, expiring capability grants**.
An issuer grants a subject agent a set of capabilities — an `action` (dotted,
hierarchical: `fs.write`, `net.fetch`, `proc.exec`, `*`) over a `resource`
pattern (a glob, a host, `*`) — with a TTL. Before it acts, an agent `check`s
whether a live grant authorizes the action. After the fact, an `audit` replays
what the fleet did and scores how much stayed in scope.

Two properties make it a standard, not a product:

- **Advisory + verifiable, not a sandbox.** capgrant does not intercept syscalls
  or replace your OS permissions. It is the shared *format* for expressing and
  auditing intent-scoped authority — the same advisory-first stance as the rest
  of the family. You can wire it into a real gate (the git pre-commit hook does),
  but the format's value is that any harness can read and write it.
- **Least privilege that composes.** Grants delegate — a delegable grant can mint
  a strictly narrower sub-grant for another agent — and revocation cascades down
  the delegation chain. Authority can only narrow as it flows outward, and
  pulling one grant pulls everything derived from it.

## Why now
Multi-agent fleets are becoming normal, and "give every agent everything" does
not survive contact with production. Scoped, portable, auditable authority is the
missing authorization layer — harness-neutral, so a grant issued for one agent
means the same thing to the next.
