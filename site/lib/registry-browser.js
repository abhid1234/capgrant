// capgrant — browser port of the append-only registry store.
//
// The PURE core of src/registry.js copied VERBATIM — `canonicalize`,
// `stableStringify`, `shortId`, `formatRelative`, `listActive`, and the full
// `resolveRecords` FOLD + CASCADE-REVOKE logic. The only change from the Node
// source is `computeRecordId`: Node's synchronous `createHash("sha256")` is
// swapped for the browser's async `crypto.subtle.digest('SHA-256', …)`, which
// forces `computeRecordId` (and therefore `resolveRecords`, which calls it in
// its integrity filter) to be async. Every other line of the decision logic is
// unchanged. The `node:fs` / `node:path` I/O layer (appendRecord / loadRegistry
// / defaultRegistryPath) is intentionally dropped — the playground holds the
// append log in memory instead.

// --- pure core -------------------------------------------------------------

// canonicalize(record) → deterministic JSON string with sorted keys and no
// incidental whitespace, over the record EXCLUDING its own `id`. Recurses so key
// ordering can never perturb the digest at any depth. Used only as the hash
// pre-image, so it need not round-trip to a value. [VERBATIM]
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
// matches its own id. [ASYNC ADAPTATION — the ONLY change from the Node source:
// `createHash("sha256").update(…).digest("hex")` → WebCrypto SHA-256 → hex.]
export async function computeRecordId(record) {
  const bytes = new TextEncoder().encode(canonicalize(record));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// shortId(id) → first 8 hex chars, the compact id `list` shows and `revoke`
// accepts as a prefix. [VERBATIM]
export function shortId(id) {
  return typeof id === "string" ? id.slice(0, 8) : String(id);
}

// formatRelative(expires, now) → a short human relative expiry: "in 40s",
// "in 12m", "in 3h", or "expired" (also "unknown" for an unparseable value).
// [VERBATIM]
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
// selector kept here for direct unit testing. [VERBATIM]
export function listActive(grants) {
  return grants.filter((g) => g.status === "active");
}

// resolveRecords(records, { now, expire }) → { grants, notes }
//
// Folds an already-parsed append log (order = append order) into the current
// grant set. [The FOLD + CASCADE-REVOKE logic below is VERBATIM from the Node
// source; only the integrity-filter loop is `for … of` + `await` instead of a
// synchronous `forEach`, because `computeRecordId` is now async, which makes the
// whole function async. Every step — integrity filter, grant fold, direct
// revocations, fixed-point cascade, TTL derivation, byExpires sort — is
// unchanged.]
//
//   1. Integrity filter — drop any record whose `id` doesn't equal its own
//      content hash (tamper/corruption), with a note. One bad line never
//      discards the rest of the registry.
//   2. Fold grants — latest grant record per `id` wins. `revocation` records are
//      collected separately.
//   3. Apply revocations — a `revocation` moves its `grant_id` to "revoked".
//   4. CASCADE — any grant whose `parent` chain leads to a revoked grant is
//      itself revoked. Fixed-point so a chain of any depth resolves.
//   5. Derive TTL expiry — an `active` grant whose `expires <= now` becomes
//      "expired" (skipped when `expire` is false).
export async function resolveRecords(records, opts = {}) {
  const { now = Date.now(), expire = true } = opts;
  const notes = [];

  // 1. Integrity filter (also drops non-objects, which can't self-hash).
  const valid = [];
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r === null || typeof r !== "object" || Array.isArray(r)) {
      notes.push(`skipped record ${i}: not an object`);
      continue;
    }
    if (r.id !== (await computeRecordId(r))) {
      notes.push(`skipped record ${i}: id/content mismatch`);
      continue;
    }
    valid.push(r);
  }

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
// [VERBATIM]
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
