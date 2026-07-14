// capgrant — registry.js resolution shim for the browser.
//
// The VERBATIM `check.js` / `audit.js` copied from src/ import `shortId` (and
// friends) from "./registry.js". The real src/registry.js pulls in `node:crypto`
// / `node:fs` / `node:path`, which don't exist in the browser, so this shim
// re-exports the browser port instead. That keeps check.js and audit.js truly
// byte-for-byte identical to the published library while the crypto/id layer is
// the async WebCrypto port in registry-browser.js.
export * from "./registry-browser.js";
