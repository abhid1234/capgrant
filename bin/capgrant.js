#!/usr/bin/env node
// capgrant CLI.
//
// Dispatches to subcommands:
//  - `grant --issuer <id> --subject <id> --cap <action:resource> ... --ttl <dur>`:
//       issue a scoped, expiring capability grant (append to the registry).
//  - `check <action> <resource> --subject <id>`: pre-action authorization
//       decision. Exit 0 = allowed, 1 = denied.
//  - `list`: show active grants (who holds what, expiring when).
//  - `revoke <id> --issuer <id> --reason "<why>"`: withdraw a grant (cascades
//       to any delegated children).
//  - `delegate --parent <id> --subject <id> --cap ... --ttl <dur>`: mint a
//       narrower sub-grant from a delegable parent.
//  - `audit <actions.json>`: score whether a batch of actions stayed in scope.
//  - `hook install|run`: git pre-commit adapter — check staged writes.
//  - `request <action> <resource> --subject --reason`: raise a human-in-the-loop
//       approval request for an action no live grant covers.
//  - `approve <request-id> --approver --ttl <dur>`: approve a pending request,
//       minting a scoped, expiring just-in-time grant for it.
//  - `deny <request-id> --approver [--reason]`: deny a pending request.
//  - `pending`: list pending approval requests awaiting a decision.

import { readFileSync } from "node:fs";
import {
  validateGrant,
  validateRegistry,
  validateRevocation,
  validateApprovalRequest,
  validateDecision,
} from "../src/schema.js";
import { makeGrant, delegate, revoke, parseTtl } from "../src/grant.js";
import { requestApproval, decide } from "../src/approval.js";
import { check } from "../src/check.js";
import { audit } from "../src/audit.js";
import {
  loadRegistry,
  appendRecord,
  defaultRegistryPath,
  formatRelative,
  shortId,
} from "../src/registry.js";
import {
  stagedPaths,
  checkStagedWrites,
  installHook,
} from "../src/adapters/git-hook.js";

const USAGE = `capgrant — scoped, expiring capability grants for fleets of AI agents

Usage:
  capgrant grant --issuer <id> --subject <id> --cap <action:resource> [...]
                 [--ttl <dur>] [--delegable] [--registry <path>] [--json]
      Issue a grant: the subject may perform each <action> on each <resource>
      until it expires. Repeat --cap for multiple capabilities. Exit 0 on write.
  capgrant check <action> <resource> --subject <id>
                 [--registry <path>] [--json]
      Decide whether the subject's active grants authorize <action> on
      <resource>. Exit 0 = allowed, 1 = denied.
  capgrant list [--all] [--subject <id>] [--registry <path>] [--json]
      Show active grants: subject, capabilities, expiring when. --all also
      shows revoked/expired grants labeled with their effective status.
  capgrant revoke <id> --issuer <id> --reason "<why>"
                  [--registry <path>] [--json]
      Withdraw a grant (full id or unambiguous prefix). Cascades to any grant
      delegated from it.
  capgrant delegate --parent <id> --issuer <id> --subject <id>
                    --cap <action:resource> [...] --ttl <dur>
                    [--registry <path>] [--json]
      Mint a narrower sub-grant from a delegable parent. Every capability must
      fall inside the parent's authority and it cannot outlive the parent.
  capgrant audit <actions.json> [--registry <path>] [--json]
      Replay a JSON array of {action, resource, subject, at?} and score how many
      stayed in scope. Exit 0 = all in scope, 1 = at least one violation.
  capgrant hook install [--registry <path>]
      Install a git pre-commit hook that checks staged writes against your
      grants. Advisory by default; set CAPGRANT_ENFORCE=1 to block. Idempotent.
  capgrant hook run [--subject <id>] [--registry <path>] [--json]
      What the hook runs: check the staged files as fs.write actions. Exit 0 by
      default even out of scope; CAPGRANT_ENFORCE=1 exits 1 so git aborts.
  capgrant validate <file> [--json]
      Validate a grant, revocation, approval_request, decision, or registry file.
  capgrant request <action> <resource> --subject <id> --reason "<why>"
                   [--requested-by <id>] [--registry <path>] [--json]
      Raise a human-in-the-loop approval request for an action no live grant
      covers. Status starts pending until approved/denied. Exit 0 on write.
  capgrant approve <request-id> --approver <id> --ttl <dur>
                   [--reason "<why>"] [--registry <path>] [--json]
      Approve a pending request (full id or unambiguous prefix), minting a
      scoped just-in-time grant that expires <dur> after now. Exit 0 on write.
  capgrant deny <request-id> --approver <id> [--reason "<why>"]
                [--registry <path>] [--json]
      Deny a pending request. Nothing is minted. Exit 0 on write.
  capgrant pending [--subject <id>] [--registry <path>] [--json]
      List approval requests still awaiting a decision (status pending).

Flags:
  --cap <action:resource>  a capability, e.g. fs.write:src/** or net.fetch:api.github.com
                           (repeatable). Action is dotted-hierarchical; * = all.
  --ttl <dur>              lease length: <n>s|m|h|d or bare seconds (default 30m;
                           for approve it is the minted grant's lifetime)
  --delegable              allow the subject to sub-grant a subset (grant)
  --issuer <id>            who is granting/revoking (env CAPGRANT_ISSUER)
  --subject <id>           the agent the grant/request is for (env CAPGRANT_AGENT)
  --reason <str>           why (required for revoke/request; optional on a decision)
  --requested-by <id>      who raised the request (request; default: the subject)
  --approver <id>          who decides an approval (approve/deny; env CAPGRANT_ISSUER)
  --parent <id>            parent grant id to delegate from (delegate)
  --all                    include revoked/expired grants (list)
  --registry <path>        registry file (default: env CAPGRANT_REGISTRY or
                           .capgrant/registry.jsonl)
  --json                   emit machine-readable output for the active command`;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

// Surface loadRegistry/resolveRecords `notes` (skipped/tampered/expired lines,
// cascade revocations) to stderr as warnings. A dropped line is a corrupt or
// tampered grant, and the warning is the mitigation: without it a vanished grant
// could silently turn an authorized action into an apparent denial (or vice
// versa on a dropped revocation).
function warnNotes(notes) {
  for (const note of notes) process.stderr.write(`warning: ${note}\n`);
}

// Parse a repeated --cap value "action:resource" into { action, resource }.
// The FIRST colon splits action from resource, so a resource may itself contain
// colons (e.g. a URL). A missing colon or an empty half is a hard error.
function parseCap(value) {
  if (typeof value !== "string" || value.indexOf(":") === -1) {
    fail(`error: --cap must be <action:resource> (got: ${value})\n\n` + USAGE);
  }
  const idx = value.indexOf(":");
  const action = value.slice(0, idx).trim();
  const resource = value.slice(idx + 1).trim();
  if (!action || !resource) {
    fail(`error: --cap must have a non-empty action and resource (got: ${value})`);
  }
  return { action, resource };
}

// The clock is read only here; every record constructor stays pure over the
// injected `created`/`at`. Whole-second precision keeps ids stable to the second.
function nowIso() {
  return new Date(Math.floor(Date.now() / 1000) * 1000).toISOString();
}

// --- validate --------------------------------------------------------------

function runValidate(args) {
  const json = args.includes("--json");
  const file = args.find((a) => a !== "--json");
  if (!file) fail("error: `validate` requires a file argument\n\n" + USAGE);

  let raw;
  try {
    raw = readFileSync(file, "utf8");
  } catch {
    fail(`error: cannot read file: ${file}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    fail(`error: ${file} is not valid JSON: ${e.message}`);
  }

  // A registry is an array; a single record is validated by type.
  let result;
  let kind;
  if (Array.isArray(parsed)) {
    result = validateRegistry(parsed);
    kind = "registry";
  } else if (parsed && parsed.type === "revocation") {
    result = validateRevocation(parsed);
    kind = "revocation";
  } else {
    result = validateGrant(parsed);
    kind = "grant";
  }

  if (json) {
    process.stdout.write(JSON.stringify(result) + "\n");
  } else if (result.valid) {
    process.stdout.write(`✓ ${file}: valid ${kind}\n`);
  } else {
    process.stdout.write(
      `✗ ${file}: invalid ${kind} (${result.errors.length} error${result.errors.length === 1 ? "" : "s"})\n`
    );
    for (const e of result.errors) {
      const at = e.path === "" ? "<root>" : e.path;
      process.stdout.write(`  ${at}: ${e.message} [${e.code}]\n`);
    }
  }
  process.exit(result.valid ? 0 : 1);
}

// --- shared flag parsing ---------------------------------------------------

// Parse the common grant/delegate flag set. Positional args are rejected (both
// verbs are fully flag-driven). Returns the raw collected values; each caller
// enforces which are required.
function parseGrantLikeArgs(args) {
  const caps = [];
  let issuer = process.env.CAPGRANT_ISSUER || null;
  let subject = process.env.CAPGRANT_AGENT || null;
  let ttl = null;
  let parent = null;
  let delegable = false;
  let registry = null;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--delegable") delegable = true;
    else if (a === "--cap") {
      const v = args[++i];
      if (v == null) fail("error: --cap requires a value\n\n" + USAGE);
      caps.push(parseCap(v));
    } else if (a === "--issuer") {
      issuer = args[++i];
      if (issuer == null) fail("error: --issuer requires a value\n\n" + USAGE);
    } else if (a === "--subject") {
      subject = args[++i];
      if (subject == null) fail("error: --subject requires a value\n\n" + USAGE);
    } else if (a === "--ttl") {
      ttl = args[++i];
      if (ttl == null) fail("error: --ttl requires a value\n\n" + USAGE);
    } else if (a === "--parent") {
      parent = args[++i];
      if (parent == null) fail("error: --parent requires a value\n\n" + USAGE);
    } else if (a === "--registry") {
      registry = args[++i];
      if (registry == null) fail("error: --registry requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      fail(`error: unexpected argument: ${a}\n\n` + USAGE);
    }
  }
  return { caps, issuer, subject, ttl, parent, delegable, registry, json };
}

// --- grant -----------------------------------------------------------------

function runGrant(args) {
  const { caps, issuer, subject, ttl, delegable, registry, json } =
    parseGrantLikeArgs(args);

  if (caps.length === 0) {
    fail("error: `grant` requires at least one --cap <action:resource>\n\n" + USAGE);
  }
  if (issuer == null || issuer.trim() === "") {
    fail("error: `grant` requires --issuer (or CAPGRANT_ISSUER)\n\n" + USAGE);
  }
  if (subject == null || subject.trim() === "") {
    fail("error: `grant` requires --subject (or CAPGRANT_AGENT)\n\n" + USAGE);
  }
  const ttl_seconds = ttl == null ? 1800 : parseTtl(ttl);
  if (ttl_seconds == null) {
    fail(`error: invalid --ttl: ${ttl} (use <n>s|m|h|d or a positive integer of seconds)`);
  }

  let grant;
  try {
    grant = makeGrant(caps, {
      issuer,
      subject,
      ttl_seconds,
      created: nowIso(),
      delegable,
    });
  } catch (e) {
    fail(`error: ${e.message}`);
  }

  // Gate the write on the validator so a malformed capability is rejected
  // rather than written to the append-only log.
  const result = validateGrant(grant);
  if (!result.valid) {
    process.stdout.write(
      `✗ cannot issue grant (${result.errors.length} error${result.errors.length === 1 ? "" : "s"}):\n`
    );
    for (const e of result.errors) {
      const at = e.path === "" ? "<root>" : e.path;
      process.stdout.write(`  ${at}: ${e.message} [${e.code}]\n`);
    }
    process.exit(1);
  }

  const path = registry || defaultRegistryPath();
  appendRecord(path, grant);

  if (json) {
    process.stdout.write(JSON.stringify(grant) + "\n");
  } else {
    const scope = grant.capabilities.map((c) => `${c.action}:${c.resource}`).join(", ");
    process.stdout.write(
      `granted ${shortId(grant.id)} — ${grant.subject} may ${scope} ` +
        `(expires ${grant.expires})${grant.delegable ? " [delegable]" : ""}\n`
    );
  }
  process.exit(0);
}

// --- delegate --------------------------------------------------------------

function runDelegate(args) {
  const { caps, issuer, subject, ttl, parent, registry, json } =
    parseGrantLikeArgs(args);

  if (parent == null || parent.trim() === "") {
    fail("error: `delegate` requires --parent <grant-id>\n\n" + USAGE);
  }
  if (caps.length === 0) {
    fail("error: `delegate` requires at least one --cap <action:resource>\n\n" + USAGE);
  }
  if (issuer == null || issuer.trim() === "") {
    fail("error: `delegate` requires --issuer (or CAPGRANT_ISSUER)\n\n" + USAGE);
  }
  if (subject == null || subject.trim() === "") {
    fail("error: `delegate` requires --subject (or CAPGRANT_AGENT)\n\n" + USAGE);
  }
  const ttl_seconds = ttl == null ? 1800 : parseTtl(ttl);
  if (ttl_seconds == null) {
    fail(`error: invalid --ttl: ${ttl} (use <n>s|m|h|d or a positive integer of seconds)`);
  }

  const path = registry || defaultRegistryPath();
  const now = Date.now();
  const { grants } = loadRegistry(path, { now });

  // Resolve the parent by exact id or unambiguous prefix.
  const parentGrant = resolveById(grants, parent);

  let sub;
  try {
    sub = delegate(parentGrant, caps, {
      issuer,
      subject,
      ttl_seconds,
      created: nowIso(),
    });
  } catch (e) {
    fail(`error: ${e.message}`);
  }

  appendRecord(path, sub);

  if (json) {
    process.stdout.write(JSON.stringify(sub) + "\n");
  } else {
    const scope = sub.capabilities.map((c) => `${c.action}:${c.resource}`).join(", ");
    process.stdout.write(
      `delegated ${shortId(sub.id)} from ${shortId(parentGrant.id)} — ` +
        `${sub.subject} may ${scope} (expires ${sub.expires})\n`
    );
  }
  process.exit(0);
}

// --- check -----------------------------------------------------------------

function runCheck(args) {
  let subject = process.env.CAPGRANT_AGENT || null;
  let registry = null;
  let json = false;
  const positional = [];

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--subject") {
      subject = args[++i];
      if (subject == null) fail("error: --subject requires a value\n\n" + USAGE);
    } else if (a === "--registry") {
      registry = args[++i];
      if (registry == null) fail("error: --registry requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      positional.push(a);
    }
  }

  const [action, resource] = positional;
  if (!action || !resource) {
    fail("error: `check` requires <action> and <resource>\n\n" + USAGE);
  }

  const path = registry || defaultRegistryPath();
  const now = Date.now();
  const { grants, requests, notes } = loadRegistry(path, { now });
  warnNotes(notes);
  const result = check(action, resource, grants, { subject, now, requests });

  if (json) {
    process.stdout.write(JSON.stringify(result) + "\n");
  } else if (result.allowed) {
    process.stdout.write(`allowed ✓ — ${result.reason}\n`);
  } else if (result.needs_approval) {
    // Softer than a flat deny: a human can approve this into a just-in-time grant.
    process.stdout.write(`needs approval ⏳ — ${result.reason}\n`);
  } else {
    process.stdout.write(`denied ✗ — ${result.reason}\n`);
  }
  process.exit(result.allowed ? 0 : 1);
}

// --- list ------------------------------------------------------------------

function runList(args) {
  let all = false;
  let subject = null;
  let registry = null;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--all") all = true;
    else if (a === "--subject") {
      subject = args[++i];
      if (subject == null) fail("error: --subject requires a value\n\n" + USAGE);
    } else if (a === "--registry") {
      registry = args[++i];
      if (registry == null) fail("error: --registry requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      fail(`error: \`list\` takes no positional arguments (got: ${a})\n\n` + USAGE);
    }
  }

  const path = registry || defaultRegistryPath();
  const now = Date.now();
  const { grants, notes } = loadRegistry(path, { now });
  if (all) warnNotes(notes);

  let rows = all ? grants : grants.filter((g) => g.status === "active");
  if (subject != null) rows = rows.filter((g) => g.subject === subject);

  if (json) {
    process.stdout.write(JSON.stringify(rows) + "\n");
    process.exit(0);
  }
  if (rows.length === 0) {
    process.stdout.write("no active grants\n");
    process.exit(0);
  }
  for (const g of rows) {
    const scope = (g.capabilities || []).map((c) => `${c.action}:${c.resource}`).join(", ");
    const when = g.status === "active" ? `expires ${formatRelative(g.expires, now)}` : g.status;
    process.stdout.write(
      `${g.subject}  [${scope}]  ${when}  ${shortId(g.id)}${g.delegable ? "  (delegable)" : ""}\n`
    );
  }
  process.exit(0);
}

// --- revoke ----------------------------------------------------------------

function runRevoke(args) {
  let id = null;
  let issuer = process.env.CAPGRANT_ISSUER || null;
  let reason = null;
  let registry = null;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--issuer") {
      issuer = args[++i];
      if (issuer == null) fail("error: --issuer requires a value\n\n" + USAGE);
    } else if (a === "--reason") {
      reason = args[++i];
      if (reason == null) fail("error: --reason requires a value\n\n" + USAGE);
    } else if (a === "--registry") {
      registry = args[++i];
      if (registry == null) fail("error: --registry requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else if (id == null) {
      id = a;
    } else {
      fail(`error: \`revoke\` takes a single <id> (extra: ${a})\n\n` + USAGE);
    }
  }

  if (id == null || id.trim() === "") {
    fail("error: `revoke` requires a grant <id>\n\n" + USAGE);
  }
  if (issuer == null || issuer.trim() === "") {
    fail("error: `revoke` requires --issuer (or CAPGRANT_ISSUER)\n\n" + USAGE);
  }
  if (reason == null || reason.trim() === "") {
    fail("error: `revoke` requires a non-empty --reason\n\n" + USAGE);
  }

  const path = registry || defaultRegistryPath();
  const now = Date.now();
  const { grants } = loadRegistry(path, { now });
  const target = resolveById(grants, id);

  if (target.status === "revoked") {
    process.stdout.write(`already revoked — nothing to do (${shortId(target.id)})\n`);
    process.exit(0);
  }

  const record = revoke(target.id, { issuer, reason, at: nowIso() });
  appendRecord(path, record);

  if (json) {
    process.stdout.write(JSON.stringify(record) + "\n");
  } else {
    process.stdout.write(
      `revoked ${shortId(target.id)} (held by ${target.subject}) — "${reason}"\n`
    );
  }
  process.exit(0);
}

// --- audit -----------------------------------------------------------------

function runAudit(args) {
  let registry = null;
  let json = false;
  let file = null;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--registry") {
      registry = args[++i];
      if (registry == null) fail("error: --registry requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else if (file == null) {
      file = a;
    } else {
      fail(`error: \`audit\` takes a single <actions.json> (extra: ${a})\n\n` + USAGE);
    }
  }

  if (!file) {
    fail("error: `audit` requires an <actions.json> file\n\n" + USAGE);
  }

  let actions;
  try {
    actions = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    fail(`error: cannot read ${file} as JSON: ${e.message}`);
  }
  if (!Array.isArray(actions)) {
    fail(`error: ${file} must be a JSON array of {action, resource, subject, at?}`);
  }

  // Load WITHOUT wall-clock expiry: audit reasons about each action's own `at`,
  // so collapsing grants to `expired` up front would misjudge actions that ran
  // while a (now-lapsed) grant was still live.
  const path = registry || defaultRegistryPath();
  const { grants } = loadRegistry(path, { expire: false });
  const result = audit(actions, grants, {});

  if (json) {
    process.stdout.write(JSON.stringify(result) + "\n");
  } else {
    process.stdout.write(
      `in-scope score ${result.score.toFixed(2)} — ` +
        `${result.allowed}/${result.total} action${result.total === 1 ? "" : "s"} authorized\n`
    );
    for (const v of result.violations) {
      process.stdout.write(
        `  ✗ ${v.subject} did ${v.action} on ${v.resource} — ${v.reason}\n`
      );
    }
  }
  process.exit(result.violations.length === 0 ? 0 : 1);
}

// --- hook ------------------------------------------------------------------

function runHookInstall(args) {
  let registry = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--registry") {
      registry = args[++i];
      if (registry == null) fail("error: --registry requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      fail(`error: unexpected argument: ${a}\n\n` + USAGE);
    }
  }

  let result;
  try {
    result = installHook({});
  } catch (e) {
    fail(`error: ${e.message}`);
  }

  process.stdout.write(
    `${result.action} pre-commit hook at ${result.path} — advisory (set CAPGRANT_ENFORCE=1 to block)\n`
  );
  if (registry) {
    process.stdout.write(
      `note: set CAPGRANT_REGISTRY=${registry} in the hook's environment to check that registry\n`
    );
  }
  process.exit(0);
}

function runHookRun(args) {
  let subject = process.env.CAPGRANT_AGENT || null;
  let registry = null;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--subject") {
      subject = args[++i];
      if (subject == null) fail("error: --subject requires a value\n\n" + USAGE);
    } else if (a === "--registry") {
      registry = args[++i];
      if (registry == null) fail("error: --registry requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      fail(`error: unexpected argument: ${a}\n\n` + USAGE);
    }
  }

  const enforce = process.env.CAPGRANT_ENFORCE === "1";
  const paths = stagedPaths();
  const now = Date.now();
  const { clear, violations, notes } = checkStagedWrites(paths, {
    registry,
    subject,
    now,
  });
  warnNotes(notes);

  if (json) {
    process.stdout.write(JSON.stringify({ clear, violations }) + "\n");
  } else if (clear) {
    process.stdout.write("clear ✓ — every staged write is within your grants\n");
  } else {
    const n = violations.length;
    process.stdout.write(
      `⚠ ${n} out-of-scope write${n === 1 ? "" : "s"}:\n`
    );
    for (const v of violations) {
      process.stdout.write(`  ${v.path} — ${v.reason}\n`);
    }
    if (!enforce) {
      process.stdout.write(
        "  (advisory: commit not blocked — set CAPGRANT_ENFORCE=1 to block)\n"
      );
    }
  }

  // Advisory by default: exit 0 even out of scope so git never aborts. Enforce
  // mode makes an out-of-scope write fatal (exit 1), aborting the commit.
  process.exit(enforce && !clear ? 1 : 0);
}

function runHook(args) {
  const sub = args[0];
  if (sub === "install") return runHookInstall(args.slice(1));
  if (sub === "run") return runHookRun(args.slice(1));
  if (sub == null) {
    fail("error: `hook` requires a subcommand: install | run\n\n" + USAGE);
  }
  fail(`error: unknown hook subcommand: ${sub} (expected install | run)\n\n` + USAGE);
}

// --- request (human-in-the-loop) -------------------------------------------

function runRequest(args) {
  let subject = process.env.CAPGRANT_AGENT || null;
  let reason = null;
  let requestedBy = null;
  let registry = null;
  let json = false;
  const positional = [];

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--subject") {
      subject = args[++i];
      if (subject == null) fail("error: --subject requires a value\n\n" + USAGE);
    } else if (a === "--reason") {
      reason = args[++i];
      if (reason == null) fail("error: --reason requires a value\n\n" + USAGE);
    } else if (a === "--requested-by") {
      requestedBy = args[++i];
      if (requestedBy == null) fail("error: --requested-by requires a value\n\n" + USAGE);
    } else if (a === "--registry") {
      registry = args[++i];
      if (registry == null) fail("error: --registry requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      positional.push(a);
    }
  }

  const [action, resource] = positional;
  if (!action || !resource) {
    fail("error: `request` requires <action> and <resource>\n\n" + USAGE);
  }
  if (subject == null || subject.trim() === "") {
    fail("error: `request` requires --subject (or CAPGRANT_AGENT)\n\n" + USAGE);
  }
  if (reason == null || reason.trim() === "") {
    fail("error: `request` requires a non-empty --reason\n\n" + USAGE);
  }
  // requested_by defaults to the subject — an agent typically raises its own
  // request when it hits a wall the grants don't cover.
  const requested_by = requestedBy != null && requestedBy.trim() !== "" ? requestedBy : subject;

  let req;
  try {
    req = requestApproval(action, resource, {
      subject,
      reason,
      requested_by,
      created: nowIso(),
    });
  } catch (e) {
    fail(`error: ${e.message}`);
  }

  // Gate the write on the validator, exactly like `grant`.
  const result = validateApprovalRequest(req);
  if (!result.valid) {
    process.stdout.write(
      `✗ cannot raise request (${result.errors.length} error${result.errors.length === 1 ? "" : "s"}):\n`
    );
    for (const e of result.errors) {
      const at = e.path === "" ? "<root>" : e.path;
      process.stdout.write(`  ${at}: ${e.message} [${e.code}]\n`);
    }
    process.exit(1);
  }

  const path = registry || defaultRegistryPath();
  appendRecord(path, req);

  if (json) {
    process.stdout.write(JSON.stringify(req) + "\n");
  } else {
    process.stdout.write(
      `requested ${shortId(req.id)} — ${req.subject} wants ${req.action} on ${req.resource} ` +
        `(pending approval): "${req.reason}"\n`
    );
  }
  process.exit(0);
}

// --- approve / deny (a decision on a request) ------------------------------

// Shared parse for approve/deny: a single positional <request-id> plus the
// decision flags. `wantTtl` gates whether --ttl is accepted (approve only).
function parseDecideArgs(args, verb) {
  let id = null;
  let approver = process.env.CAPGRANT_ISSUER || null;
  let reason = null;
  let ttl = null;
  let registry = null;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--approver") {
      approver = args[++i];
      if (approver == null) fail("error: --approver requires a value\n\n" + USAGE);
    } else if (a === "--reason") {
      reason = args[++i];
      if (reason == null) fail("error: --reason requires a value\n\n" + USAGE);
    } else if (a === "--ttl") {
      ttl = args[++i];
      if (ttl == null) fail("error: --ttl requires a value\n\n" + USAGE);
    } else if (a === "--registry") {
      registry = args[++i];
      if (registry == null) fail("error: --registry requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else if (id == null) {
      id = a;
    } else {
      fail(`error: \`${verb}\` takes a single <request-id> (extra: ${a})\n\n` + USAGE);
    }
  }
  return { id, approver, reason, ttl, registry, json };
}

function runApprove(args) {
  const { id, approver, reason, ttl, registry, json } = parseDecideArgs(args, "approve");

  if (id == null || id.trim() === "") {
    fail("error: `approve` requires a <request-id>\n\n" + USAGE);
  }
  if (approver == null || approver.trim() === "") {
    fail("error: `approve` requires --approver (or CAPGRANT_ISSUER)\n\n" + USAGE);
  }
  if (ttl == null || ttl.trim() === "") {
    fail("error: `approve` requires --ttl (the minted grant's lifetime)\n\n" + USAGE);
  }
  const grant_ttl_seconds = parseTtl(ttl);
  if (grant_ttl_seconds == null) {
    fail(`error: invalid --ttl: ${ttl} (use <n>s|m|h|d or a positive integer of seconds)`);
  }

  const path = registry || defaultRegistryPath();
  const now = Date.now();
  const { requests } = loadRegistry(path, { now });
  const request = resolveRequestById(requests, id);

  let decision;
  try {
    decision = decide(request, {
      approver,
      decision: "approve",
      at: nowIso(),
      grant_ttl_seconds,
      ...(reason != null && reason.trim() !== "" ? { reason } : {}),
    });
  } catch (e) {
    fail(`error: ${e.message}`);
  }

  // Gate the write on the validator, exactly like `grant`.
  const result = validateDecision(decision);
  if (!result.valid) {
    process.stdout.write(`✗ cannot record decision (${result.errors.length} errors):\n`);
    for (const e of result.errors) {
      process.stdout.write(`  ${e.path || "<root>"}: ${e.message} [${e.code}]\n`);
    }
    process.exit(1);
  }

  appendRecord(path, decision);

  if (json) {
    process.stdout.write(JSON.stringify(decision) + "\n");
  } else {
    process.stdout.write(
      `approved ${shortId(request.id)} — minted a grant for ${request.subject}: ` +
        `${request.action} on ${request.resource} (expires in ${ttl})\n`
    );
  }
  process.exit(0);
}

function runDeny(args) {
  const { id, approver, reason, ttl, registry, json } = parseDecideArgs(args, "deny");

  if (ttl != null) {
    fail("error: `deny` mints nothing, so --ttl is not valid\n\n" + USAGE);
  }
  if (id == null || id.trim() === "") {
    fail("error: `deny` requires a <request-id>\n\n" + USAGE);
  }
  if (approver == null || approver.trim() === "") {
    fail("error: `deny` requires --approver (or CAPGRANT_ISSUER)\n\n" + USAGE);
  }

  const path = registry || defaultRegistryPath();
  const now = Date.now();
  const { requests } = loadRegistry(path, { now });
  const request = resolveRequestById(requests, id);

  let decision;
  try {
    decision = decide(request, {
      approver,
      decision: "deny",
      at: nowIso(),
      ...(reason != null && reason.trim() !== "" ? { reason } : {}),
    });
  } catch (e) {
    fail(`error: ${e.message}`);
  }

  appendRecord(path, decision);

  if (json) {
    process.stdout.write(JSON.stringify(decision) + "\n");
  } else {
    process.stdout.write(
      `denied ${shortId(request.id)} — ${request.subject}'s ${request.action} on ` +
        `${request.resource} was refused${reason ? ` ("${reason}")` : ""}\n`
    );
  }
  process.exit(0);
}

// --- pending ---------------------------------------------------------------

function runPending(args) {
  let subject = null;
  let registry = null;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--subject") {
      subject = args[++i];
      if (subject == null) fail("error: --subject requires a value\n\n" + USAGE);
    } else if (a === "--registry") {
      registry = args[++i];
      if (registry == null) fail("error: --registry requires a value\n\n" + USAGE);
    } else if (a.startsWith("--")) {
      fail(`error: unknown flag: ${a}\n\n` + USAGE);
    } else {
      fail(`error: \`pending\` takes no positional arguments (got: ${a})\n\n` + USAGE);
    }
  }

  const path = registry || defaultRegistryPath();
  const now = Date.now();
  const { requests, notes } = loadRegistry(path, { now });
  warnNotes(notes);

  let rows = requests.filter((r) => r.status === "pending");
  if (subject != null) rows = rows.filter((r) => r.subject === subject);

  if (json) {
    process.stdout.write(JSON.stringify(rows) + "\n");
    process.exit(0);
  }
  if (rows.length === 0) {
    process.stdout.write("no pending requests\n");
    process.exit(0);
  }
  for (const r of rows) {
    process.stdout.write(
      `${r.subject}  ${r.action} on ${r.resource}  — "${r.reason}"  ` +
        `(by ${r.requested_by})  ${shortId(r.id)}\n`
    );
  }
  process.exit(0);
}

// --- shared helpers --------------------------------------------------------

// Resolve an approval_request by exact id or unambiguous id prefix; fail() with
// a clear message on no match or an ambiguous prefix (mirrors resolveById).
function resolveRequestById(requests, id) {
  let target = requests.find((r) => r.id === id);
  if (!target) {
    const matches = requests.filter((r) => r.id.startsWith(id));
    if (matches.length > 1) {
      fail(`error: ambiguous id prefix "${id}" matches ${matches.length} requests`);
    }
    target = matches[0];
  }
  if (!target) {
    fail(`error: no approval request with id "${id}"`);
  }
  return target;
}

// Resolve a grant by exact id or unambiguous id prefix; fail() with a clear
// message on no match or an ambiguous prefix.
function resolveById(grants, id) {
  let target = grants.find((g) => g.id === id);
  if (!target) {
    const matches = grants.filter((g) => g.id.startsWith(id));
    if (matches.length > 1) {
      fail(`error: ambiguous id prefix "${id}" matches ${matches.length} grants`);
    }
    target = matches[0];
  }
  if (!target) {
    fail(`error: no grant with id "${id}"`);
  }
  return target;
}

// --- main router -----------------------------------------------------------

function main(argv) {
  const args = argv.slice(2);
  const command = args[0];

  if (command === "grant") return runGrant(args.slice(1));
  if (command === "delegate") return runDelegate(args.slice(1));
  if (command === "check") return runCheck(args.slice(1));
  if (command === "list") return runList(args.slice(1));
  if (command === "revoke") return runRevoke(args.slice(1));
  if (command === "audit") return runAudit(args.slice(1));
  if (command === "hook") return runHook(args.slice(1));
  if (command === "validate") return runValidate(args.slice(1));
  if (command === "request") return runRequest(args.slice(1));
  if (command === "approve") return runApprove(args.slice(1));
  if (command === "deny") return runDeny(args.slice(1));
  if (command === "pending") return runPending(args.slice(1));

  fail(USAGE);
}

main(process.argv);
