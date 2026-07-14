// capgrant — the append-only registry store.
//
// A registry is an append-only JSONL file (one JSON record per line). This
// module is the single home for the store: a small set of *pure* functions
// (canonical serialization, content-hash ids, log resolution) plus a thin I/O
// layer (`appendRecord`, `loadRegistry`) that keeps every filesystem access in
// one place. The design is deliberately lock-free — writes are single-line
// `O_APPEND` writes, reads fold the whole log into the current grant set, and
// every record self-identifies by a content hash, so concurrent or duplicated
// appends resolve cleanly instead of conflicting. Node's built-in `crypto` is
// the only "dependency"; there are zero runtime packages.

import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

// --- pure core -------------------------------------------------------------

// canonicalize(record) → deterministic JSON string with sorted keys and no
// incidental whitespace, over the record EXCLUDING its own `id`. Recurses so key
// ordering can never perturb the digest at any depth. Used only as the hash
// pre-image, so it need not round-trip to a value.
export function canonicalize(record) {
  const { id: _id, ...rest } = record;
  return stableStringify(rest);
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return (
      "{" +
      keys.map((k) => JSON.stringify(k) + ":" + stableStringify(value[k])).join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

// computeRecordId(record) → the sha256 content hash of the record (its `id`
// excluded). Deterministic and content-addressed: identical content ⇒ identical
// id, so a duplicated append is idempotent on read and a tampered line no longer
// matches its own id. Both `makeGrant` and `revoke` use this one helper, so a
// record's `id` IS its content hash across every record type.
export function computeRecordId(record) {
  return createHash("sha256").update(canonicalize(record)).digest("hex");
}

// shortId(id) → first 8 hex chars, the compact id `list` shows and `revoke`
// accepts as a prefix.
export function shortId(id) {
  return typeof id === "string" ? id.slice(0, 8) : String(id);
}

// formatRelative(expires, now) → a short human relative expiry: "in 40s",
// "in 12m", "in 3h", or "expired" (also "unknown" for an unparseable value).
export function formatRelative(expires, now = Date.now()) {
  const ms = Date.parse(expires);
  if (Number.isNaN(ms)) return "unknown";
  const delta = ms - now;
  if (delta <= 0) return "expired";
  const s = Math.round(delta / 1000);
  if (s < 60) return `in ${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `in ${m}m`;
  return `in ${Math.round(m / 60)}h`;
}

// listActive(grants) → the subset whose effective status is "active". Pure
// selector kept here for direct unit testing.
export function listActive(grants) {
  return grants.filter((g) => g.status === "active");
}

// resolveRecords(records, { now, expire }) → { grants, notes }
//
// Folds an already-parsed append log (order = append order) into the current
// grant set. Pure and total: `now` (epoch ms) is injected so expiry is
// deterministic, and no bad field value throws. Nothing is written back — every
// derived status is computed here at read time.
//
//   1. Integrity filter — drop any record whose `id` doesn't equal its own
//      content hash (tamper/corruption), with a note. One bad line never
//      discards the rest of the registry.
//   2. Fold grants — latest grant record per `id` wins (content-addressed, so
//      normally identical; tolerant of a re-append → idempotent). `revocation`
//      records are collected separately.
//   3. Apply revocations — a `revocation` moves its `grant_id` to status
//      "revoked"; an unknown `grant_id` is noted and ignored.
//   4. CASCADE — any grant whose `parent` chain leads to a revoked grant is
//      itself revoked (a delegated child cannot outlive a revoked parent), each
//      cascade recorded as a note. Fixed-point so a chain of any depth resolves.
//   5. Derive TTL expiry — an `active` grant whose `expires <= now` becomes
//      effective status "expired" (derived, with a note). Skipped when `expire`
//      is false, so the stored active/revoked state is returned unchanged —
//      `audit` needs this because it reasons about time itself via each action's
//      own `at`.
//
// Returns the grants sorted by `expires` ascending plus the collected notes.
export function resolveRecords(records, opts = {}) {
  const { now = Date.now(), expire = true } = opts;
  const notes = [];

  // 1. Integrity filter (also drops non-objects, which can't self-hash).
  const valid = [];
  records.forEach((r, i) => {
    if (r === null || typeof r !== "object" || Array.isArray(r)) {
      notes.push(`skipped record ${i}: not an object`);
      return;
    }
    if (r.id !== computeRecordId(r)) {
      notes.push(`skipped record ${i}: id/content mismatch`);
      return;
    }
    valid.push(r);
  });

  // 2. Fold grants / collect revocations (a record is a revocation iff
  //    type === "revocation"; a grant iff no type or type === "grant"; anything
  //    else is forward-compat noise, skipped).
  const grants = new Map();
  const revocations = [];
  for (const r of valid) {
    const type = r.type == null ? "grant" : r.type;
    if (type === "grant") {
      grants.set(r.id, { ...r });
    } else if (type === "revocation") {
      revocations.push(r);
    } else {
      notes.push(`skipped record ${shortId(r.id)}: unknown type "${r.type}"`);
    }
  }

  // 3. Apply direct revocations.
  for (const rev of revocations) {
    const grant = grants.get(rev.grant_id);
    if (!grant) {
      notes.push(`revocation for unknown grant_id ${shortId(rev.grant_id)} ignored`);
      continue;
    }
    grant.status = "revoked";
    grant.revoked_by = rev.issuer;
    grant.revoked_at = rev.at;
    grant.revoked_reason = rev.reason;
  }

  // 4. Cascade revocation down delegation chains to a fixed point: a grant with
  //    a revoked parent is itself revoked (marked as a cascade, so the note and
  //    the reason distinguish it from a direct revocation).
  let changed = true;
  while (changed) {
    changed = false;
    for (const grant of grants.values()) {
      if (grant.status === "revoked") continue;
      if (grant.parent == null) continue;
      const parent = grants.get(grant.parent);
      if (parent && parent.status === "revoked") {
        grant.status = "revoked";
        grant.revoked_by = parent.revoked_by;
        grant.revoked_at = parent.revoked_at;
        grant.revoked_reason = `cascade: parent ${shortId(grant.parent)} revoked`;
        notes.push(
          `grant ${shortId(grant.id)} revoked via cascade from parent ${shortId(grant.parent)}`
        );
        changed = true;
      }
    }
  }

  // 5. Derive TTL expiry (a grant exactly at expires === now counts as expired).
  //    Revoked grants keep their revoked status — revocation dominates expiry.
  for (const grant of expire ? grants.values() : []) {
    if (grant.status === "active" && grant.expires != null) {
      const exp = Date.parse(grant.expires);
      if (!Number.isNaN(exp) && exp <= now) {
        grant.status = "expired";
        notes.push(`grant ${shortId(grant.id)} expired at ${grant.expires}`);
      }
    }
  }

  const resolved = [...grants.values()].sort(byExpires);
  return { grants: resolved, notes };
}

// Sort by `expires` ascending; unparseable/absent expiries sort last, stably.
function byExpires(a, b) {
  const ea = Date.parse(a.expires);
  const eb = Date.parse(b.expires);
  const na = Number.isNaN(ea);
  const nb = Number.isNaN(eb);
  if (na && nb) return 0;
  if (na) return 1;
  if (nb) return -1;
  return ea - eb;
}

// --- I/O layer -------------------------------------------------------------

// defaultRegistryPath(cwd) → the ONE place the default registry location is
// defined; every verb calls it. `CAPGRANT_REGISTRY` overrides, else a
// git-tracked `.capgrant/registry.jsonl` at the repo root.
export function defaultRegistryPath(cwd = process.cwd()) {
  return process.env.CAPGRANT_REGISTRY || join(cwd, ".capgrant", "registry.jsonl");
}

// appendRecord(path, record) → the stored record (with its content-hash `id`).
// Assigns `id` if absent, creates the parent directory, then appends exactly one
// JSON line terminated by "\n" with the `"a"` flag (O_APPEND). Existing lines are
// never rewritten — this is the whole safety story.
export function appendRecord(path, record) {
  const stored = record.id ? record : { ...record, id: computeRecordId(record) };
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(stored) + "\n");
  return stored;
}

// loadRegistry(path, { now, expire }) → { grants, notes }
//
// Reads the JSONL file (missing file → empty registry, no throw), parses each
// non-blank line tolerantly (a line that won't parse is dropped with a note,
// never aborting the load), and returns the resolved current registry via
// `resolveRecords`. `expire` (default true) forwards to `resolveRecords`; pass
// false to skip wall-clock TTL decay and see the stored active/revoked state.
export function loadRegistry(path, opts = {}) {
  const { now = Date.now(), expire = true } = opts;

  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (e) {
    if (e && e.code === "ENOENT") return { grants: [], notes: [] };
    throw e;
  }

  const parsed = [];
  const parseNotes = [];
  raw.split("\n").forEach((line, i) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      parsed.push(JSON.parse(trimmed));
    } catch {
      parseNotes.push(`skipped unparseable line ${i + 1}`);
    }
  });

  const resolved = resolveRecords(parsed, { now, expire });
  return { grants: resolved.grants, notes: [...parseNotes, ...resolved.notes] };
}
