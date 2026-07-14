// capgrant — public entry point (package `main`).
// Re-exports the pure schema/validator API (grant/revocation + HITL approval_request/decision).
// Re-exports the zero-dep glob-overlap engine (`globsOverlap`).
// Re-exports the pure capability-matching API (`actionImplies` / `resourceMatches` / `capabilityCovers`).
// Re-exports the capability-constraint engine (`constraintViolation` / `constraintsSubsume` / `capabilityCoverage` / `resourceDepth` / `CONSTRAINT_KEYS`).
// Re-exports the `makeGrant` / `delegate` / `revoke` / `parseTtl` record-constructor API.
// Re-exports the append-only registry store (`loadRegistry`, `appendRecord`, cascade-aware `resolveRecords`, …).
// Re-exports the pure `check` pre-action authorization decision (now `needs_approval`-aware).
// Re-exports the pure `audit` after-the-fact in-scope scorer.
// Re-exports the human-in-the-loop approval constructors (`requestApproval` / `decide`).
// Re-exports the signed-grant tamper-evidence API (HMAC + ed25519: `signHmac` / `verifyHmac` / `generateKeypair` / `signAsym` / `verifyAsym`).
// Re-exports the git pre-commit adapter (`checkStagedWrites`, `installHook`, …).

export {
  validateGrant,
  validateCapability,
  validateRevocation,
  validateApprovalRequest,
  validateDecision,
  validateRegistry,
  isIso8601Utc,
  isDottedAction,
  GRANT_FIELDS,
  CAPABILITY_FIELDS,
  STATUSES,
  RECORD_TYPES,
  ERROR_CODES,
} from "./schema.js";
export { globsOverlap } from "./glob.js";
export {
  actionImplies,
  resourceMatches,
  capabilityCovers,
  capabilityCoverage,
  constraintViolation,
  constraintsSubsume,
  resourceDepth,
  CONSTRAINT_KEYS,
} from "./capability.js";
export { makeGrant, delegate, revoke, parseTtl } from "./grant.js";
export { requestApproval, decide } from "./approval.js";
export {
  canonicalize,
  computeRecordId,
  resolveRecords,
  loadRegistry,
  appendRecord,
  defaultRegistryPath,
  listActive,
  formatRelative,
  shortId,
} from "./registry.js";
export { check } from "./check.js";
export { audit } from "./audit.js";
export { signHmac, verifyHmac, generateKeypair, signAsym, verifyAsym } from "./sign.js";
export {
  stagedPaths,
  checkStagedWrites,
  hookPath,
  renderHookBlock,
  installHook,
} from "./adapters/git-hook.js";
