// capgrant — public entry point (package `main`).
// Re-exports the pure schema/validator API.
// Re-exports the zero-dep glob-overlap engine (`globsOverlap`).
// Re-exports the pure capability-matching API (`actionImplies` / `resourceMatches` / `capabilityCovers`).
// Re-exports the `makeGrant` / `delegate` / `revoke` / `parseTtl` record-constructor API.
// Re-exports the append-only registry store (`loadRegistry`, `appendRecord`, cascade-aware `resolveRecords`, …).
// Re-exports the pure `check` pre-action authorization decision.
// Re-exports the pure `audit` after-the-fact in-scope scorer.
// Re-exports the git pre-commit adapter (`checkStagedWrites`, `installHook`, …).

export {
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
} from "./schema.js";
export { globsOverlap } from "./glob.js";
export { actionImplies, resourceMatches, capabilityCovers } from "./capability.js";
export { makeGrant, delegate, revoke, parseTtl } from "./grant.js";
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
export {
  stagedPaths,
  checkStagedWrites,
  hookPath,
  renderHookBlock,
  installHook,
} from "./adapters/git-hook.js";
