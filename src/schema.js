// capgrant — grant + registry schema and validators.
//
// Pure, zero-dependency validators for the open capability-grant shapes: a
// `grant` (an issuer authorizing a subject agent to perform scoped actions on
// scoped resources until an expiry), a `capability` (one `{action, resource}`
// leaf of a grant), a `revocation` (an issuer withdrawing a grant), and a
// registry (an array of either record type). Nothing throws on bad input; every
// validator returns `{ valid, errors }` and collects EVERY violation (no
// short-circuit) so a harness or human can fix everything in one pass.
//
// Error = { path: string, code: string, message: string }
//   path — dot/bracket path to the offending value ("capabilities[0].action",
//          "[2].ttl_seconds", or "" for the whole object).
//   code — a stable machine-readable code from ERROR_CODES.
//   message — one-line human explanation.

export const STATUSES = ["active", "revoked", "expired"];

export const RECORD_TYPES = ["grant", "revocation", "approval_request", "decision"];

// The exact set of allowed top-level grant fields, in canonical order. `parent`
// is optional (present only on a delegated sub-grant); every other field is
// required.
export const GRANT_FIELDS = [
  "id",
  "type",
  "issuer",
  "subject",
  "capabilities",
  "ttl_seconds",
  "created",
  "expires",
  "delegable",
  "parent",
  "status",
];

// A grant field is required unless it is `parent` (optional) — `id`/`type`/etc.
// must all be present for a well-formed grant.
const GRANT_REQUIRED = GRANT_FIELDS.filter((f) => f !== "parent");

// The allowed fields of a single capability leaf. `constraints` is optional.
export const CAPABILITY_FIELDS = ["action", "resource", "constraints"];
const CAPABILITY_REQUIRED = ["action", "resource"];

// The allowed fields of a revocation record (all required). Kept module-local;
// not part of the documented export surface.
const REVOCATION_FIELDS = ["id", "type", "grant_id", "issuer", "reason", "at"];

// The allowed fields of an approval_request record (all required) and a decision
// record (`reason` + `grant_ttl_seconds` optional). Kept module-local, like the
// revocation fields.
const APPROVAL_REQUEST_FIELDS = [
  "id",
  "type",
  "subject",
  "action",
  "resource",
  "reason",
  "requested_by",
  "created",
  "status",
];
const DECISION_FIELDS = [
  "id",
  "type",
  "request_id",
  "decision",
  "approver",
  "reason",
  "at",
  "grant_ttl_seconds",
];
const DECISION_REQUIRED = DECISION_FIELDS.filter(
  (f) => f !== "reason" && f !== "grant_ttl_seconds"
);

// The status an approval_request can carry: it is stored "pending" and derived
// to "approved"/"denied" once a decision folds in.
const REQUEST_STATUSES = ["pending", "approved", "denied"];

// The two decisions a decision record can express.
const DECISIONS = ["approve", "deny"];

export const ERROR_CODES = {
  MISSING_FIELD: "MISSING_FIELD",
  UNKNOWN_FIELD: "UNKNOWN_FIELD",
  WRONG_TYPE: "WRONG_TYPE",
  NOT_OBJECT: "NOT_OBJECT",
  NOT_ARRAY: "NOT_ARRAY",
  EMPTY_STRING: "EMPTY_STRING",
  EMPTY_ARRAY: "EMPTY_ARRAY",
  INVALID_ENUM: "INVALID_ENUM",
  NOT_POSITIVE_INT: "NOT_POSITIVE_INT",
  INVALID_ISO8601: "INVALID_ISO8601",
  EXPIRES_MISMATCH: "EXPIRES_MISMATCH",
  INVALID_ACTION: "INVALID_ACTION",
  DUPLICATE_ID: "DUPLICATE_ID",
};

// Strict ISO-8601 UTC: YYYY-MM-DDTHH:MM:SS(.sss)?Z. The regex gates the format
// (UTC `Z` only, no offsets); Date.parse gates real-calendar validity so
// impossible dates like 2026-13-40T00:00:00Z are rejected.
const ISO8601_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

// A dotted, hierarchical action: one or more `[a-z0-9_-]+` segments joined by
// `.` (e.g. `fs`, `fs.write`, `net.fetch`), OR the wildcard `*` (all actions).
const DOTTED_ACTION = /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/;

export function isIso8601Utc(s) {
  if (typeof s !== "string" || !ISO8601_UTC.test(s)) return false;
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) return false;
  // Date.parse silently rolls over impossible calendar dates (e.g.
  // 2026-02-30 → Mar 2) instead of returning NaN, so a format-valid but
  // nonexistent date would slip through. Round-trip and require the calendar
  // day to match the input.
  return new Date(ms).toISOString().slice(0, 10) === s.slice(0, 10);
}

// isDottedAction(s) → true for a hierarchical action string or the `*` wildcard.
export function isDottedAction(s) {
  return typeof s === "string" && (s === "*" || DOTTED_ACTION.test(s));
}

function err(path, code, message) {
  return { path, code, message };
}

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim().length > 0;
}

// Validate a single string field that is already known to be present.
function checkStringField(errors, obj, field, prefix = "") {
  const v = obj[field];
  const path = prefix + field;
  if (typeof v !== "string") {
    errors.push(err(path, ERROR_CODES.WRONG_TYPE, `${field} must be a string`));
  } else if (v.trim().length === 0) {
    errors.push(err(path, ERROR_CODES.EMPTY_STRING, `${field} must not be empty`));
  }
}

// validateCapability(obj, prefix) → { valid, errors }
//
// A capability is a `{ action, resource, constraints? }` leaf: `action` is a
// dotted/hierarchical action (or `*`), `resource` is a non-empty pattern string,
// and `constraints` — when present — is a free-form object (reserved for future
// conditions like rate/quota). `prefix` re-roots the error paths when this is
// called from within a grant (e.g. "capabilities[0].").
export function validateCapability(obj, prefix = "") {
  if (!isPlainObject(obj)) {
    return {
      valid: false,
      errors: [err(prefix.replace(/\.$/, ""), ERROR_CODES.NOT_OBJECT, "capability must be a JSON object")],
    };
  }

  const errors = [];

  for (const field of CAPABILITY_REQUIRED) {
    if (!(field in obj)) {
      errors.push(err(prefix + field, ERROR_CODES.MISSING_FIELD, `${field} is required`));
    }
  }
  for (const key of Object.keys(obj)) {
    if (!CAPABILITY_FIELDS.includes(key)) {
      errors.push(err(prefix + key, ERROR_CODES.UNKNOWN_FIELD, `unknown field: ${key}`));
    }
  }

  if ("action" in obj) {
    if (typeof obj.action !== "string") {
      errors.push(err(prefix + "action", ERROR_CODES.WRONG_TYPE, "action must be a string"));
    } else if (obj.action.length === 0) {
      errors.push(err(prefix + "action", ERROR_CODES.EMPTY_STRING, "action must not be empty"));
    } else if (!isDottedAction(obj.action)) {
      errors.push(
        err(
          prefix + "action",
          ERROR_CODES.INVALID_ACTION,
          "action must be dotted lowercase segments (e.g. fs.write) or *"
        )
      );
    }
  }

  if ("resource" in obj) checkStringField(errors, obj, "resource", prefix);

  if ("constraints" in obj && !isPlainObject(obj.constraints)) {
    errors.push(
      err(prefix + "constraints", ERROR_CODES.WRONG_TYPE, "constraints must be a JSON object")
    );
  }

  return { valid: errors.length === 0, errors };
}

// validateGrant(obj) → { valid, errors }
export function validateGrant(obj) {
  if (!isPlainObject(obj)) {
    return {
      valid: false,
      errors: [err("", ERROR_CODES.NOT_OBJECT, "grant must be a JSON object")],
    };
  }

  const errors = [];

  // Required fields (everything except optional `parent`).
  for (const field of GRANT_REQUIRED) {
    if (!(field in obj)) {
      errors.push(err(field, ERROR_CODES.MISSING_FIELD, `${field} is required`));
    }
  }
  // Unknown top-level fields.
  for (const key of Object.keys(obj)) {
    if (!GRANT_FIELDS.includes(key)) {
      errors.push(err(key, ERROR_CODES.UNKNOWN_FIELD, `unknown field: ${key}`));
    }
  }

  if ("id" in obj) checkStringField(errors, obj, "id");
  if ("issuer" in obj) checkStringField(errors, obj, "issuer");
  if ("subject" in obj) checkStringField(errors, obj, "subject");

  if ("type" in obj && obj.type !== "grant") {
    errors.push(err("type", ERROR_CODES.INVALID_ENUM, 'type must be "grant"'));
  }

  if ("capabilities" in obj) {
    const caps = obj.capabilities;
    if (!Array.isArray(caps)) {
      errors.push(err("capabilities", ERROR_CODES.WRONG_TYPE, "capabilities must be an array"));
    } else if (caps.length === 0) {
      errors.push(
        err("capabilities", ERROR_CODES.EMPTY_ARRAY, "capabilities must have at least one entry")
      );
    } else {
      caps.forEach((cap, i) => {
        const res = validateCapability(cap, `capabilities[${i}].`);
        for (const e of res.errors) errors.push(e);
      });
    }
  }

  if ("ttl_seconds" in obj) {
    const t = obj.ttl_seconds;
    if (typeof t !== "number" || !Number.isInteger(t) || t <= 0) {
      errors.push(
        err("ttl_seconds", ERROR_CODES.NOT_POSITIVE_INT, "ttl_seconds must be an integer > 0")
      );
    }
  }

  if ("created" in obj && !isIso8601Utc(obj.created)) {
    errors.push(err("created", ERROR_CODES.INVALID_ISO8601, "created must be ISO 8601 UTC (…Z)"));
  }
  if ("expires" in obj && !isIso8601Utc(obj.expires)) {
    errors.push(err("expires", ERROR_CODES.INVALID_ISO8601, "expires must be ISO 8601 UTC (…Z)"));
  }

  if ("delegable" in obj && typeof obj.delegable !== "boolean") {
    errors.push(err("delegable", ERROR_CODES.WRONG_TYPE, "delegable must be a boolean"));
  }

  if ("parent" in obj) checkStringField(errors, obj, "parent");

  if ("status" in obj && !STATUSES.includes(obj.status)) {
    errors.push(
      err("status", ERROR_CODES.INVALID_ENUM, `status must be one of: ${STATUSES.join(", ")}`)
    );
  }

  // Cross-field: expires === created + ttl_seconds (only when all three are
  // individually valid, so a mismatch is never piled on top of a format error).
  if (
    isIso8601Utc(obj.created) &&
    isIso8601Utc(obj.expires) &&
    typeof obj.ttl_seconds === "number" &&
    Number.isInteger(obj.ttl_seconds) &&
    obj.ttl_seconds > 0
  ) {
    if (Date.parse(obj.expires) !== Date.parse(obj.created) + obj.ttl_seconds * 1000) {
      errors.push(
        err("expires", ERROR_CODES.EXPIRES_MISMATCH, "expires must equal created + ttl_seconds")
      );
    }
  }

  return { valid: errors.length === 0, errors };
}

// validateRevocation(obj) → { valid, errors }
export function validateRevocation(obj) {
  if (!isPlainObject(obj)) {
    return {
      valid: false,
      errors: [err("", ERROR_CODES.NOT_OBJECT, "revocation must be a JSON object")],
    };
  }

  const errors = [];

  for (const field of REVOCATION_FIELDS) {
    if (!(field in obj)) {
      errors.push(err(field, ERROR_CODES.MISSING_FIELD, `${field} is required`));
    }
  }
  for (const key of Object.keys(obj)) {
    if (!REVOCATION_FIELDS.includes(key)) {
      errors.push(err(key, ERROR_CODES.UNKNOWN_FIELD, `unknown field: ${key}`));
    }
  }

  if ("id" in obj) checkStringField(errors, obj, "id");
  if ("grant_id" in obj) checkStringField(errors, obj, "grant_id");
  if ("issuer" in obj) checkStringField(errors, obj, "issuer");
  if ("reason" in obj) checkStringField(errors, obj, "reason");

  if ("type" in obj && obj.type !== "revocation") {
    errors.push(err("type", ERROR_CODES.INVALID_ENUM, 'type must be "revocation"'));
  }
  if ("at" in obj && !isIso8601Utc(obj.at)) {
    errors.push(err("at", ERROR_CODES.INVALID_ISO8601, "at must be ISO 8601 UTC (…Z)"));
  }

  return { valid: errors.length === 0, errors };
}

// validateApprovalRequest(obj) → { valid, errors }
//
// An approval_request: some subject wants to perform `action` on `resource` and
// needs a human to say yes. `action` is a dotted/hierarchical action (or `*`),
// `resource`/`reason`/`requested_by` are non-empty strings, `created` is
// ISO-8601 UTC, and `status` is one of pending/approved/denied (stored
// "pending"; the resolver derives the rest).
export function validateApprovalRequest(obj) {
  if (!isPlainObject(obj)) {
    return {
      valid: false,
      errors: [err("", ERROR_CODES.NOT_OBJECT, "approval_request must be a JSON object")],
    };
  }

  const errors = [];

  for (const field of APPROVAL_REQUEST_FIELDS) {
    if (!(field in obj)) {
      errors.push(err(field, ERROR_CODES.MISSING_FIELD, `${field} is required`));
    }
  }
  for (const key of Object.keys(obj)) {
    if (!APPROVAL_REQUEST_FIELDS.includes(key)) {
      errors.push(err(key, ERROR_CODES.UNKNOWN_FIELD, `unknown field: ${key}`));
    }
  }

  if ("id" in obj) checkStringField(errors, obj, "id");
  if ("subject" in obj) checkStringField(errors, obj, "subject");
  if ("resource" in obj) checkStringField(errors, obj, "resource");
  if ("reason" in obj) checkStringField(errors, obj, "reason");
  if ("requested_by" in obj) checkStringField(errors, obj, "requested_by");

  if ("type" in obj && obj.type !== "approval_request") {
    errors.push(err("type", ERROR_CODES.INVALID_ENUM, 'type must be "approval_request"'));
  }

  if ("action" in obj) {
    if (typeof obj.action !== "string") {
      errors.push(err("action", ERROR_CODES.WRONG_TYPE, "action must be a string"));
    } else if (obj.action.length === 0) {
      errors.push(err("action", ERROR_CODES.EMPTY_STRING, "action must not be empty"));
    } else if (!isDottedAction(obj.action)) {
      errors.push(
        err(
          "action",
          ERROR_CODES.INVALID_ACTION,
          "action must be dotted lowercase segments (e.g. fs.write) or *"
        )
      );
    }
  }

  if ("created" in obj && !isIso8601Utc(obj.created)) {
    errors.push(err("created", ERROR_CODES.INVALID_ISO8601, "created must be ISO 8601 UTC (…Z)"));
  }

  if ("status" in obj && !REQUEST_STATUSES.includes(obj.status)) {
    errors.push(
      err("status", ERROR_CODES.INVALID_ENUM, `status must be one of: ${REQUEST_STATUSES.join(", ")}`)
    );
  }

  return { valid: errors.length === 0, errors };
}

// validateDecision(obj) → { valid, errors }
//
// A decision resolves an approval_request: `decision` is approve|deny, `approver`
// / `request_id` are non-empty strings, `at` is ISO-8601 UTC, `reason` is an
// optional non-empty string, and `grant_ttl_seconds` — when present — is a
// positive integer (the TTL of the grant an approve mints).
export function validateDecision(obj) {
  if (!isPlainObject(obj)) {
    return {
      valid: false,
      errors: [err("", ERROR_CODES.NOT_OBJECT, "decision must be a JSON object")],
    };
  }

  const errors = [];

  for (const field of DECISION_REQUIRED) {
    if (!(field in obj)) {
      errors.push(err(field, ERROR_CODES.MISSING_FIELD, `${field} is required`));
    }
  }
  for (const key of Object.keys(obj)) {
    if (!DECISION_FIELDS.includes(key)) {
      errors.push(err(key, ERROR_CODES.UNKNOWN_FIELD, `unknown field: ${key}`));
    }
  }

  if ("id" in obj) checkStringField(errors, obj, "id");
  if ("request_id" in obj) checkStringField(errors, obj, "request_id");
  if ("approver" in obj) checkStringField(errors, obj, "approver");
  if ("reason" in obj) checkStringField(errors, obj, "reason");

  if ("type" in obj && obj.type !== "decision") {
    errors.push(err("type", ERROR_CODES.INVALID_ENUM, 'type must be "decision"'));
  }
  if ("decision" in obj && !DECISIONS.includes(obj.decision)) {
    errors.push(
      err("decision", ERROR_CODES.INVALID_ENUM, `decision must be one of: ${DECISIONS.join(", ")}`)
    );
  }
  if ("at" in obj && !isIso8601Utc(obj.at)) {
    errors.push(err("at", ERROR_CODES.INVALID_ISO8601, "at must be ISO 8601 UTC (…Z)"));
  }
  if ("grant_ttl_seconds" in obj) {
    const t = obj.grant_ttl_seconds;
    if (typeof t !== "number" || !Number.isInteger(t) || t <= 0) {
      errors.push(
        err(
          "grant_ttl_seconds",
          ERROR_CODES.NOT_POSITIVE_INT,
          "grant_ttl_seconds must be an integer > 0"
        )
      );
    }
  }

  return { valid: errors.length === 0, errors };
}

// Dispatch one registry record to the validator for its `type`; a record with
// no/unknown type is validated as a grant, the default record.
function validateByType(record) {
  const type = isPlainObject(record) ? record.type : undefined;
  if (type === "revocation") return validateRevocation(record);
  if (type === "approval_request") return validateApprovalRequest(record);
  if (type === "decision") return validateDecision(record);
  return validateGrant(record);
}

// validateRegistry(arr) → { valid, errors }
//
// An array of records, each a `grant`, a `revocation`, an `approval_request`, or
// a `decision` (dispatched on `type`; a record with no/unknown type is validated
// as a grant, the default record).
export function validateRegistry(arr) {
  if (!Array.isArray(arr)) {
    return {
      valid: false,
      errors: [err("", ERROR_CODES.NOT_ARRAY, "registry must be a JSON array")],
    };
  }

  const errors = [];

  arr.forEach((record, i) => {
    const result = validateByType(record);
    for (const e of result.errors) {
      const path = e.path === "" ? `[${i}]` : `[${i}].${e.path}`;
      errors.push(err(path, e.code, e.message));
    }
  });

  // Duplicate id detection among structurally-valid records.
  const seen = new Set();
  arr.forEach((record, i) => {
    if (isPlainObject(record) && isNonEmptyString(record.id)) {
      if (seen.has(record.id)) {
        errors.push(err(`[${i}].id`, ERROR_CODES.DUPLICATE_ID, `duplicate id: ${record.id}`));
      } else {
        seen.add(record.id);
      }
    }
  });

  return { valid: errors.length === 0, errors };
}
