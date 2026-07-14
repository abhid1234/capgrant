import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateGrant,
  validateCapability,
  validateRevocation,
  validateRegistry,
  isIso8601Utc,
  isDottedAction,
  GRANT_FIELDS,
  CAPABILITY_FIELDS,
  STATUSES,
  RECORD_TYPES,
  ERROR_CODES,
} from "../src/schema.js";

// A canonical fully-valid grant. created + 1800s == expires.
function validGrant(overrides = {}) {
  return {
    id: "abc123",
    type: "grant",
    issuer: "alice",
    subject: "agent-A",
    capabilities: [{ action: "fs.write", resource: "src/**" }],
    ttl_seconds: 1800,
    created: "2026-07-11T12:00:00Z",
    expires: "2026-07-11T12:30:00Z",
    delegable: false,
    status: "active",
    ...overrides,
  };
}

function validRevocation(overrides = {}) {
  return {
    id: "rev123",
    type: "revocation",
    grant_id: "abc123",
    issuer: "alice",
    reason: "superseded",
    at: "2026-07-11T12:15:00Z",
    ...overrides,
  };
}

function codes(result) {
  return result.errors.map((e) => e.code);
}
function codeAt(result, path) {
  return result.errors.filter((e) => e.path === path).map((e) => e.code);
}

// The required grant fields are every field except optional `parent`.
const GRANT_REQUIRED = GRANT_FIELDS.filter((f) => f !== "parent");

// --- constants -------------------------------------------------------------

test("exported constant shapes", () => {
  assert.deepEqual(STATUSES, ["active", "revoked", "expired"]);
  assert.deepEqual(RECORD_TYPES, ["grant", "revocation"]);
  assert.ok(GRANT_FIELDS.includes("capabilities"));
  assert.ok(GRANT_FIELDS.includes("parent"));
  assert.deepEqual(CAPABILITY_FIELDS, ["action", "resource", "constraints"]);
  // Every documented error code is present.
  for (const c of [
    "MISSING_FIELD",
    "UNKNOWN_FIELD",
    "WRONG_TYPE",
    "NOT_OBJECT",
    "NOT_ARRAY",
    "EMPTY_STRING",
    "EMPTY_ARRAY",
    "INVALID_ENUM",
    "NOT_POSITIVE_INT",
    "INVALID_ISO8601",
    "EXPIRES_MISMATCH",
    "INVALID_ACTION",
    "DUPLICATE_ID",
  ]) {
    assert.equal(ERROR_CODES[c], c, `ERROR_CODES.${c}`);
  }
});

// --- validateGrant ---------------------------------------------------------

test("fully-valid grant → valid, no errors", () => {
  assert.deepEqual(validateGrant(validGrant()), { valid: true, errors: [] });
});

test("a valid delegated grant (with parent) → valid", () => {
  assert.deepEqual(
    validateGrant(validGrant({ parent: "parent-id-hash" })),
    { valid: true, errors: [] }
  );
});

test("each required field missing → exactly one MISSING_FIELD at that path", () => {
  for (const field of GRANT_REQUIRED) {
    const grant = validGrant();
    delete grant[field];
    const result = validateGrant(grant);
    assert.equal(result.valid, false, `${field} missing should be invalid`);
    assert.deepEqual(
      codeAt(result, field),
      ["MISSING_FIELD"],
      `${field} missing → one MISSING_FIELD at ${field}`
    );
  }
});

test("parent is optional — omitting it is not a MISSING_FIELD", () => {
  const grant = validGrant();
  assert.ok(!("parent" in grant));
  assert.equal(validateGrant(grant).valid, true);
});

test("wrong types per field", () => {
  assert.deepEqual(codeAt(validateGrant(validGrant({ id: 42 })), "id"), ["WRONG_TYPE"]);
  assert.deepEqual(codeAt(validateGrant(validGrant({ issuer: 1 })), "issuer"), ["WRONG_TYPE"]);
  assert.deepEqual(codeAt(validateGrant(validGrant({ subject: {} })), "subject"), ["WRONG_TYPE"]);
  assert.deepEqual(codeAt(validateGrant(validGrant({ capabilities: "fs" })), "capabilities"), [
    "WRONG_TYPE",
  ]);
  assert.deepEqual(codeAt(validateGrant(validGrant({ delegable: "yes" })), "delegable"), [
    "WRONG_TYPE",
  ]);
  assert.deepEqual(codeAt(validateGrant(validGrant({ ttl_seconds: "1800" })), "ttl_seconds"), [
    "NOT_POSITIVE_INT",
  ]);
});

test("empty / whitespace strings → EMPTY_STRING", () => {
  assert.deepEqual(codeAt(validateGrant(validGrant({ id: "" })), "id"), ["EMPTY_STRING"]);
  assert.deepEqual(codeAt(validateGrant(validGrant({ issuer: "  " })), "issuer"), ["EMPTY_STRING"]);
  assert.deepEqual(codeAt(validateGrant(validGrant({ subject: "" })), "subject"), ["EMPTY_STRING"]);
  assert.deepEqual(codeAt(validateGrant(validGrant({ parent: "" })), "parent"), ["EMPTY_STRING"]);
});

test("type must be exactly \"grant\" → INVALID_ENUM otherwise", () => {
  assert.deepEqual(codeAt(validateGrant(validGrant({ type: "revocation" })), "type"), [
    "INVALID_ENUM",
  ]);
  assert.deepEqual(codeAt(validateGrant(validGrant({ type: "frob" })), "type"), ["INVALID_ENUM"]);
});

test("status must be a valid enum", () => {
  assert.deepEqual(codeAt(validateGrant(validGrant({ status: "done" })), "status"), [
    "INVALID_ENUM",
  ]);
  for (const s of STATUSES) {
    // status "revoked"/"expired" are structurally valid grant states.
    assert.equal(validateGrant(validGrant({ status: s })).valid, true, `status ${s}`);
  }
});

test("capabilities: empty array → EMPTY_ARRAY", () => {
  assert.deepEqual(codeAt(validateGrant(validGrant({ capabilities: [] })), "capabilities"), [
    "EMPTY_ARRAY",
  ]);
});

test("capabilities: element errors re-rooted at capabilities[i]", () => {
  const bad = validGrant({
    capabilities: [{ action: "fs.write", resource: "src/**" }, { action: "NOPE", resource: "x" }],
  });
  assert.deepEqual(codeAt(validateGrant(bad), "capabilities[1].action"), ["INVALID_ACTION"]);
});

test("capabilities: a missing required sub-field surfaces at capabilities[i].field", () => {
  const bad = validGrant({ capabilities: [{ action: "fs.write" }] });
  assert.deepEqual(codeAt(validateGrant(bad), "capabilities[0].resource"), ["MISSING_FIELD"]);
});

test("ttl_seconds must be a positive integer", () => {
  for (const t of [0, -1, 1.5, "1800", null]) {
    const result = validateGrant(validGrant({ ttl_seconds: t }));
    assert.deepEqual(codeAt(result, "ttl_seconds"), ["NOT_POSITIVE_INT"], `ttl=${t}`);
  }
});

test("created / expires must be ISO 8601 UTC → INVALID_ISO8601", () => {
  assert.ok(codeAt(validateGrant(validGrant({ created: "not-a-date" })), "created").includes("INVALID_ISO8601"));
  assert.ok(
    codeAt(validateGrant(validGrant({ created: "2026-07-11T12:00:00+00:00" })), "created").includes(
      "INVALID_ISO8601"
    )
  );
  assert.ok(
    codeAt(validateGrant(validGrant({ created: "2026-02-30T00:00:00Z" })), "created").includes(
      "INVALID_ISO8601"
    )
  );
  assert.ok(
    codeAt(validateGrant(validGrant({ expires: "2026-04-31T00:00:00Z" })), "expires").includes(
      "INVALID_ISO8601"
    )
  );
});

test("expires must equal created + ttl_seconds → EXPIRES_MISMATCH", () => {
  const result = validateGrant(
    validGrant({ created: "2026-07-11T12:00:00Z", ttl_seconds: 1800, expires: "2026-07-11T13:00:00Z" })
  );
  assert.deepEqual(codeAt(result, "expires"), ["EXPIRES_MISMATCH"]);
});

test("exact expires match passes, including sub-second created", () => {
  const result = validateGrant(
    validGrant({
      created: "2026-07-11T12:00:00.500Z",
      ttl_seconds: 60,
      expires: "2026-07-11T12:01:00.500Z",
    })
  );
  assert.equal(result.valid, true);
});

test("EXPIRES_MISMATCH is not piled onto a format error", () => {
  const result = validateGrant(validGrant({ created: "nope" }));
  assert.ok(codes(result).includes("INVALID_ISO8601"));
  assert.ok(!codes(result).includes("EXPIRES_MISMATCH"));
});

test("unknown top-level field → UNKNOWN_FIELD at that key", () => {
  assert.deepEqual(codeAt(validateGrant(validGrant({ foo: "bar" })), "foo"), ["UNKNOWN_FIELD"]);
});

test("non-object grant → single NOT_OBJECT at root", () => {
  for (const bad of [null, [], 42, "x", undefined]) {
    const result = validateGrant(bad);
    assert.deepEqual(codes(result), ["NOT_OBJECT"]);
    assert.equal(result.errors[0].path, "");
  }
});

test("multiple simultaneous grant violations are all reported (no short-circuit)", () => {
  const result = validateGrant({
    id: "",
    type: "nope",
    issuer: "",
    subject: "a",
    capabilities: [],
    ttl_seconds: -1,
    created: "bad",
    expires: "bad",
    delegable: "no",
    status: "huh",
    extra: 1,
  });
  const c = codes(result);
  assert.ok(c.includes("EMPTY_STRING")); // id / issuer
  assert.ok(c.includes("INVALID_ENUM")); // type / status
  assert.ok(c.includes("EMPTY_ARRAY")); // capabilities
  assert.ok(c.includes("NOT_POSITIVE_INT")); // ttl_seconds
  assert.ok(c.includes("INVALID_ISO8601")); // created / expires
  assert.ok(c.includes("WRONG_TYPE")); // delegable
  assert.ok(c.includes("UNKNOWN_FIELD")); // extra
  assert.ok(result.errors.length >= 7);
});

// --- validateCapability ----------------------------------------------------

test("valid capability → valid, no errors", () => {
  assert.deepEqual(validateCapability({ action: "fs.write", resource: "src/**" }), {
    valid: true,
    errors: [],
  });
});

test("capability with an optional constraints object → valid", () => {
  assert.equal(
    validateCapability({ action: "net.fetch", resource: "api.github.com", constraints: { rate: 5 } })
      .valid,
    true
  );
});

test("capability missing required fields → MISSING_FIELD", () => {
  assert.deepEqual(codeAt(validateCapability({ resource: "x" }), "action"), ["MISSING_FIELD"]);
  assert.deepEqual(codeAt(validateCapability({ action: "fs" }), "resource"), ["MISSING_FIELD"]);
});

test("capability action must be a dotted action or * → INVALID_ACTION", () => {
  assert.deepEqual(codeAt(validateCapability({ action: "FS.write", resource: "x" }), "action"), [
    "INVALID_ACTION",
  ]);
  assert.deepEqual(codeAt(validateCapability({ action: "fs write", resource: "x" }), "action"), [
    "INVALID_ACTION",
  ]);
  assert.equal(validateCapability({ action: "*", resource: "*" }).valid, true);
});

test("capability empty action → EMPTY_STRING; empty resource → EMPTY_STRING", () => {
  assert.deepEqual(codeAt(validateCapability({ action: "", resource: "x" }), "action"), [
    "EMPTY_STRING",
  ]);
  assert.deepEqual(codeAt(validateCapability({ action: "fs", resource: "  " }), "resource"), [
    "EMPTY_STRING",
  ]);
});

test("capability wrong-type action / resource / constraints → WRONG_TYPE", () => {
  assert.deepEqual(codeAt(validateCapability({ action: 5, resource: "x" }), "action"), [
    "WRONG_TYPE",
  ]);
  assert.deepEqual(codeAt(validateCapability({ action: "fs", resource: 9 }), "resource"), [
    "WRONG_TYPE",
  ]);
  assert.deepEqual(
    codeAt(validateCapability({ action: "fs", resource: "x", constraints: "no" }), "constraints"),
    ["WRONG_TYPE"]
  );
});

test("capability unknown field → UNKNOWN_FIELD", () => {
  assert.deepEqual(codeAt(validateCapability({ action: "fs", resource: "x", foo: 1 }), "foo"), [
    "UNKNOWN_FIELD",
  ]);
});

test("non-object capability → single NOT_OBJECT", () => {
  for (const bad of [null, [], 42, "x"]) {
    assert.deepEqual(codes(validateCapability(bad)), ["NOT_OBJECT"]);
  }
});

test("capability error prefix re-roots the path", () => {
  const res = validateCapability({ resource: "x" }, "capabilities[2].");
  assert.deepEqual(codeAt(res, "capabilities[2].action"), ["MISSING_FIELD"]);
});

// --- validateRevocation ----------------------------------------------------

test("valid revocation → valid, no errors", () => {
  assert.deepEqual(validateRevocation(validRevocation()), { valid: true, errors: [] });
});

test("revocation required fields missing → MISSING_FIELD", () => {
  for (const field of ["id", "type", "grant_id", "issuer", "reason", "at"]) {
    const rev = validRevocation();
    delete rev[field];
    assert.deepEqual(codeAt(validateRevocation(rev), field), ["MISSING_FIELD"], field);
  }
});

test("revocation type must be \"revocation\"; at must be ISO UTC", () => {
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ type: "grant" })), "type"), [
    "INVALID_ENUM",
  ]);
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ at: "bad" })), "at"), [
    "INVALID_ISO8601",
  ]);
});

test("revocation empty strings + unknown field", () => {
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ reason: "" })), "reason"), [
    "EMPTY_STRING",
  ]);
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ grant_id: "  " })), "grant_id"), [
    "EMPTY_STRING",
  ]);
  assert.deepEqual(codeAt(validateRevocation(validRevocation({ extra: 1 })), "extra"), [
    "UNKNOWN_FIELD",
  ]);
});

test("non-object revocation → single NOT_OBJECT", () => {
  assert.deepEqual(codes(validateRevocation(null)), ["NOT_OBJECT"]);
});

// --- validateRegistry ------------------------------------------------------

test("valid array of unique-id records → valid", () => {
  const reg = [validGrant({ id: "one" }), validRevocation({ id: "two" })];
  assert.deepEqual(validateRegistry(reg), { valid: true, errors: [] });
});

test("empty array is a valid registry", () => {
  assert.deepEqual(validateRegistry([]), { valid: true, errors: [] });
});

test("non-array input → single NOT_ARRAY", () => {
  for (const bad of [null, {}, 42, "x"]) {
    assert.deepEqual(codes(validateRegistry(bad)), ["NOT_ARRAY"]);
  }
});

test("registry dispatches on type: a revocation element is validated as a revocation", () => {
  // Missing grant_id on a revocation element surfaces via the revocation validator.
  const reg = [validGrant({ id: "one" }), validRevocation({ id: "two", grant_id: undefined })];
  delete reg[1].grant_id;
  assert.deepEqual(codeAt(validateRegistry(reg), "[1].grant_id"), ["MISSING_FIELD"]);
});

test("registry element error path is prefixed with [i]", () => {
  const reg = [validGrant({ id: "one" }), validGrant({ id: "two", issuer: "" })];
  assert.deepEqual(codeAt(validateRegistry(reg), "[1].issuer"), ["EMPTY_STRING"]);
});

test("whole-element NOT_OBJECT path is [i]", () => {
  const result = validateRegistry([validGrant(), 42]);
  assert.deepEqual(codeAt(result, "[1]"), ["NOT_OBJECT"]);
});

test("duplicate id across elements → DUPLICATE_ID at the later occurrence", () => {
  const reg = [validGrant({ id: "dup" }), validGrant({ id: "dup" })];
  const result = validateRegistry(reg);
  assert.deepEqual(codeAt(result, "[1].id"), ["DUPLICATE_ID"]);
  assert.equal(codeAt(result, "[0].id").length, 0);
});

// --- isDottedAction --------------------------------------------------------

test("isDottedAction accepts dotted lowercase segments and *", () => {
  for (const ok of ["fs", "fs.write", "net.fetch", "proc.exec", "a-b_c", "x1.y2.z3", "*"]) {
    assert.equal(isDottedAction(ok), true, ok);
  }
});

test("isDottedAction rejects uppercase, spaces, empty, dotted edges, non-strings", () => {
  for (const bad of [
    "FS",
    "Fs.write",
    "fs write",
    "",
    ".fs",
    "fs.",
    "fs..write",
    "fs.*",
    "a/b",
    42,
    null,
    undefined,
  ]) {
    assert.equal(isDottedAction(bad), false, String(bad));
  }
});

// --- isIso8601Utc ----------------------------------------------------------

test("isIso8601Utc accepts UTC Z timestamps (with/without ms)", () => {
  assert.equal(isIso8601Utc("2026-07-11T12:00:00Z"), true);
  assert.equal(isIso8601Utc("2026-07-11T12:00:00.123Z"), true);
});

test("isIso8601Utc rejects offsets, impossible dates, non-UTC, non-strings", () => {
  assert.equal(isIso8601Utc("2026-07-11T12:00:00+00:00"), false);
  assert.equal(isIso8601Utc("2026-07-11T12:00:00-05:00"), false);
  assert.equal(isIso8601Utc("2026-13-40T00:00:00Z"), false);
  assert.equal(isIso8601Utc("2026-02-30T00:00:00Z"), false);
  assert.equal(isIso8601Utc("2026-04-31T00:00:00Z"), false);
  assert.equal(isIso8601Utc("2026-07-11 12:00:00Z"), false);
  assert.equal(isIso8601Utc("2026-07-11T12:00:00"), false);
  assert.equal(isIso8601Utc(42), false);
  assert.equal(isIso8601Utc(null), false);
});
