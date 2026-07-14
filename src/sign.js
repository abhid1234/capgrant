// capgrant — signed grants (HMAC + ed25519 tamper-evidence, pure + zero-dep).
//
// The registry's content-hash `id` already makes a record self-verifying WITHIN
// one trust domain — a tampered line no longer matches its own id and is dropped
// on read. But an id is not a SIGNATURE: anyone can recompute it, so it proves
// integrity, not authorship. When a grant (or revocation) crosses a trust
// boundary — one team's registry consumed by another, a grant minted by a
// service you don't share a filesystem with — you want to prove WHO stood behind
// it. This module adds two optional, layered tamper-evidence schemes over the
// same canonical pre-image the id is built from:
//
//   HMAC     — a shared-secret MAC (`signHmac`/`verifyHmac`). Cheapest; both
//              parties must hold the same secret.
//   ed25519  — an asymmetric signature (`generateKeypair`/`signAsym`/
//              `verifyAsym`). The signer holds the private key; anyone with the
//              public key can verify, no shared secret.
//
// Both are computed over `canonicalize(record)` with any `signature` field
// stripped first — so a record's signature is never part of its own pre-image,
// and an embedded signature verifies identically to a detached one. Everything
// is pure and deterministic (ed25519 per RFC 8032 is deterministic, so a given
// record+key always yields the same hex). Node's built-in `crypto` is the only
// "dependency"; there are zero runtime packages. SIGNERS THROW on a bad key
// (like the record constructors — you should never emit a broken signature);
// VERIFIERS NEVER THROW — a missing, malformed, or wrong-typed signature or key
// is simply an unverified record (`false`), never an exception.

import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  timingSafeEqual,
} from "node:crypto";
import { canonicalize } from "./registry.js";

function fail(msg) {
  throw new Error(`capgrant: ${msg}`);
}

// The signing pre-image: the same canonical, id-excluded serialization the
// content-hash id is built from, with any `signature` field stripped first so a
// signature is never computed over itself. Reused by every signer and verifier,
// so HMAC and ed25519 sign byte-for-byte the same bytes.
function preimage(record) {
  const { signature: _sig, ...rest } = record;
  return canonicalize(rest);
}

// Constant-time hex-string compare that never throws: unequal lengths (or a
// non-hex input) are an immediate, non-timing-sensitive `false`.
function hexEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length === 0 || a.length !== b.length) return false;
  let ba;
  let bb;
  try {
    ba = Buffer.from(a, "hex");
    bb = Buffer.from(b, "hex");
  } catch {
    return false;
  }
  // A non-hex char makes Buffer.from silently short — guard on decoded length.
  if (ba.length !== bb.length || ba.length === 0) return false;
  return timingSafeEqual(ba, bb);
}

function requireRecord(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    fail("record must be a JSON object");
  }
}

function requireSecret(secret) {
  if ((typeof secret !== "string" || secret.length === 0) && !Buffer.isBuffer(secret)) {
    fail("secret must be a non-empty string or Buffer");
  }
}

// --- HMAC ------------------------------------------------------------------

// signHmac(record, secret) → hex HMAC-SHA256 over the record's canonical
// pre-image (id- and signature-excluded). Deterministic. Throws on a missing
// record or an empty/invalid secret.
export function signHmac(record, secret) {
  requireRecord(record);
  requireSecret(secret);
  return createHmac("sha256", secret).update(preimage(record)).digest("hex");
}

// verifyHmac(record, secret, sigHex?) → boolean. Recomputes the MAC and compares
// (constant-time) against the DETACHED `sigHex` if given, else the record's
// EMBEDDED `signature` field. Never throws — a bad secret, a missing/malformed
// signature, or a non-object record all return `false`.
export function verifyHmac(record, secret, sigHex) {
  try {
    if (!record || typeof record !== "object" || Array.isArray(record)) return false;
    if ((typeof secret !== "string" || secret.length === 0) && !Buffer.isBuffer(secret)) {
      return false;
    }
    const provided = sigHex != null ? sigHex : record.signature;
    const expected = createHmac("sha256", secret).update(preimage(record)).digest("hex");
    return hexEqual(expected, provided);
  } catch {
    return false;
  }
}

// --- ed25519 ---------------------------------------------------------------

// generateKeypair() → { publicKey, privateKey } as PEM strings (SPKI public,
// PKCS#8 private). ed25519 needs no parameters — zero-config, zero-dep.
export function generateKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

// signAsym(record, privateKeyPem) → hex ed25519 signature over the record's
// canonical pre-image. Deterministic (RFC 8032). Throws on a missing record or
// a private key that isn't a valid PEM.
export function signAsym(record, privateKeyPem) {
  requireRecord(record);
  if (typeof privateKeyPem !== "string" || privateKeyPem.trim().length === 0) {
    fail("privateKey must be a non-empty PEM string");
  }
  let key;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch {
    fail("privateKey is not a valid PEM key");
  }
  // ed25519 is a one-shot algorithm: the digest argument must be null.
  return cryptoSign(null, Buffer.from(preimage(record)), key).toString("hex");
}

// verifyAsym(record, publicKeyPem, sigHex?) → boolean. Verifies the DETACHED
// `sigHex` if given, else the record's EMBEDDED `signature`, against the public
// key. Never throws — a malformed key, a non-hex/empty signature, or a
// non-object record all return `false`.
export function verifyAsym(record, publicKeyPem, sigHex) {
  try {
    if (!record || typeof record !== "object" || Array.isArray(record)) return false;
    const provided = sigHex != null ? sigHex : record.signature;
    if (typeof provided !== "string" || provided.length === 0 || !/^[0-9a-fA-F]+$/.test(provided)) {
      return false;
    }
    const sigBuf = Buffer.from(provided, "hex");
    if (sigBuf.length === 0) return false;
    const key = createPublicKey(publicKeyPem);
    return cryptoVerify(null, Buffer.from(preimage(record)), key, sigBuf);
  } catch {
    return false;
  }
}
