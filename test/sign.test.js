import { test } from "node:test";
import assert from "node:assert/strict";
import {
  signHmac,
  verifyHmac,
  generateKeypair,
  signAsym,
  verifyAsym,
} from "../src/sign.js";
import { makeGrant } from "../src/grant.js";

// A real grant record to sign (built by the constructor, so it carries a
// content-hash id — the signers must ignore it via canonicalize).
function record() {
  return makeGrant([{ action: "fs.write", resource: "src/**" }], {
    issuer: "alice",
    subject: "agent-A",
    ttl_seconds: 1800,
    created: "2026-01-01T00:00:00Z",
  });
}

const SECRET = "correct horse battery staple";

// --- HMAC ------------------------------------------------------------------

test("HMAC round-trips: sign then verify (detached)", () => {
  const r = record();
  const sig = signHmac(r, SECRET);
  assert.match(sig, /^[0-9a-f]{64}$/); // hex sha256
  assert.equal(verifyHmac(r, SECRET, sig), true);
});

test("HMAC verifies an EMBEDDED signature field", () => {
  const r = record();
  const signed = { ...r, signature: signHmac(r, SECRET) };
  // no detached sig passed → falls back to the embedded `signature`
  assert.equal(verifyHmac(signed, SECRET), true);
});

test("HMAC embedded and detached signatures are identical (signature excluded from preimage)", () => {
  const r = record();
  const detached = signHmac(r, SECRET);
  const signed = { ...r, signature: detached };
  // signing the record WITH an embedded signature yields the same MAC
  assert.equal(signHmac(signed, SECRET), detached);
});

test("HMAC is deterministic", () => {
  const r = record();
  assert.equal(signHmac(r, SECRET), signHmac(r, SECRET));
});

test("HMAC rejects the wrong secret", () => {
  const r = record();
  const sig = signHmac(r, SECRET);
  assert.equal(verifyHmac(r, "wrong-secret", sig), false);
});

test("HMAC rejects a tampered record", () => {
  const r = record();
  const sig = signHmac(r, SECRET);
  const tampered = { ...r, subject: "attacker" };
  assert.equal(verifyHmac(tampered, SECRET, sig), false);
});

test("HMAC verify never throws on a missing/malformed signature", () => {
  const r = record();
  assert.equal(verifyHmac(r, SECRET), false); // no embedded sig, none passed
  assert.equal(verifyHmac(r, SECRET, "not-hex-zz"), false);
  assert.equal(verifyHmac(r, SECRET, ""), false);
  assert.equal(verifyHmac(r, SECRET, "abcd"), false); // wrong length
  assert.equal(verifyHmac(null, SECRET, "abcd"), false);
  assert.equal(verifyHmac(r, "", "abcd"), false); // empty secret
});

test("signHmac throws on a bad record or secret (like the constructors)", () => {
  assert.throws(() => signHmac(null, SECRET), /capgrant:/);
  assert.throws(() => signHmac(42, SECRET), /capgrant:/);
  assert.throws(() => signHmac(record(), ""), /capgrant:/);
  assert.throws(() => signHmac(record(), 123), /capgrant:/);
});

// --- ed25519 ---------------------------------------------------------------

test("generateKeypair returns PEM public/private keys", () => {
  const { publicKey, privateKey } = generateKeypair();
  assert.match(publicKey, /-----BEGIN PUBLIC KEY-----/);
  assert.match(privateKey, /-----BEGIN PRIVATE KEY-----/);
});

test("ed25519 round-trips: sign then verify (detached)", () => {
  const r = record();
  const { publicKey, privateKey } = generateKeypair();
  const sig = signAsym(r, privateKey);
  assert.match(sig, /^[0-9a-f]+$/);
  assert.equal(verifyAsym(r, publicKey, sig), true);
});

test("ed25519 verifies an EMBEDDED signature field", () => {
  const r = record();
  const { publicKey, privateKey } = generateKeypair();
  const signed = { ...r, signature: signAsym(r, privateKey) };
  assert.equal(verifyAsym(signed, publicKey), true);
});

test("ed25519 embedded and detached signatures are identical (signature excluded)", () => {
  const r = record();
  const { privateKey } = generateKeypair();
  const detached = signAsym(r, privateKey);
  const signed = { ...r, signature: detached };
  assert.equal(signAsym(signed, privateKey), detached);
});

test("ed25519 is deterministic (RFC 8032)", () => {
  const r = record();
  const { privateKey } = generateKeypair();
  assert.equal(signAsym(r, privateKey), signAsym(r, privateKey));
});

test("ed25519 rejects the wrong public key", () => {
  const r = record();
  const a = generateKeypair();
  const b = generateKeypair();
  const sig = signAsym(r, a.privateKey);
  assert.equal(verifyAsym(r, b.publicKey, sig), false);
});

test("ed25519 rejects a tampered record", () => {
  const r = record();
  const { publicKey, privateKey } = generateKeypair();
  const sig = signAsym(r, privateKey);
  const tampered = { ...r, ttl_seconds: 999999 };
  assert.equal(verifyAsym(tampered, publicKey, sig), false);
});

test("ed25519 verify never throws on a malformed signature or key", () => {
  const r = record();
  const { publicKey, privateKey } = generateKeypair();
  const sig = signAsym(r, privateKey);
  assert.equal(verifyAsym(r, publicKey), false); // no embedded sig, none passed
  assert.equal(verifyAsym(r, publicKey, "not-hex-zz"), false);
  assert.equal(verifyAsym(r, publicKey, ""), false);
  assert.equal(verifyAsym(r, "not-a-key", sig), false);
  assert.equal(verifyAsym(null, publicKey, sig), false);
});

test("signAsym throws on a bad record or private key", () => {
  const { privateKey } = generateKeypair();
  assert.throws(() => signAsym(null, privateKey), /capgrant:/);
  assert.throws(() => signAsym(record(), "not-a-pem"), /capgrant:/);
  assert.throws(() => signAsym(record(), ""), /capgrant:/);
});

// --- layering: HMAC and ed25519 are independent ----------------------------

test("HMAC and ed25519 sign the same pre-image but don't cross-verify", () => {
  const r = record();
  const { publicKey } = generateKeypair();
  const hmacSig = signHmac(r, SECRET);
  // an HMAC hex is not a valid ed25519 signature for this key
  assert.equal(verifyAsym(r, publicKey, hmacSig), false);
});
