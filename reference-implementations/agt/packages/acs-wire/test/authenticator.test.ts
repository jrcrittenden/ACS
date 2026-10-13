import { describe, expect, it } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmacAuthenticator, jcsCanonicalise, NULL_AUTHENTICATOR, readHmacKey, readHmacSecret } from "../src/index.ts";

const KEY = Buffer.alloc(32, 7);
const keyIdOf = (envelope: { params: Record<string, unknown> }) => (envelope.params.signature as { key_id: string }).key_id;
const request = () => ({
  jsonrpc: "2.0",
  method: "steps/toolCallRequest",
  id: 1,
  params: { acs_version: "0.1.0", request_id: "r", metadata: { agent_id: "a", session_id: crypto.randomUUID() as string }, payload: { b: 1, a: [2] } },
});

describe("jcsCanonicalise", () => {
  it("sorts keys at every depth and drops whitespace", () => {
    expect(jcsCanonicalise({ b: { d: 1, c: [true, null] }, a: "x" })).toBe('{"a":"x","b":{"c":[true,null],"d":1}}');
  });
});

describe("createHmacAuthenticator", () => {
  const auth = createHmacAuthenticator([{ keyId: "k1", secret: KEY }]);

  it("verifies what it signed, under the configured key_id", () => {
    const signed = auth.signRequest(request());
    expect(keyIdOf(signed)).toBe("k1");
    expect(auth.verifyRequest(signed)).toEqual({
      valid: true,
      key: { keyId: "k1", sessionId: signed.params.metadata.session_id },
    });
  });

  it("rejects a tampered request, a missing signature, and a foreign key", () => {
    const signed = auth.signRequest(request());
    expect(auth.verifyRequest({ ...signed, method: "x" })).toEqual({ valid: false, reason: "signature mismatch" });
    expect(auth.verifyRequest(request())).toEqual({ valid: false, reason: "signature required but not present" });
    const foreign = createHmacAuthenticator([{ keyId: "k1", secret: Buffer.alloc(32, 8) }]).signRequest(request());
    expect(auth.verifyRequest(foreign).valid).toBe(false);
  });

  it("refuses a key_id it has no secret for, without trying another (§10)", () => {
    // Signed with the configured secret under an unknown label.
    const relabelled = createHmacAuthenticator([{ keyId: "k9", secret: KEY }]).signRequest(request());
    expect(auth.verifyRequest(relabelled)).toEqual({ valid: false, reason: "signature key_id names no configured secret" });
  });

  it("verifies every configured key, and signs with the first, so a rotation can overlap", () => {
    const rotating = createHmacAuthenticator([
      { keyId: "new", secret: Buffer.alloc(32, 9) },
      { keyId: "old", secret: KEY },
    ]);
    const oldHost = createHmacAuthenticator([{ keyId: "old", secret: KEY }]);
    const req = oldHost.signRequest(request());
    const verified = rotating.verifyRequest(req);
    expect(verified).toMatchObject({ valid: true, key: { keyId: "old" } });
    const answer = rotating.signResponse({ jsonrpc: "2.0", id: 1, result: { decision: "allow" } }, (verified as { key: { keyId: string; sessionId: string } }).key);
    expect(oldHost.verifyResponse(answer as Record<string, unknown>, req)).toMatchObject({ valid: true });
    expect(keyIdOf(rotating.signRequest(request()))).toBe("new");
  });

  it("refuses an empty, duplicated or short key", () => {
    expect(() => createHmacAuthenticator([])).toThrow(/at least one key/);
    expect(() => createHmacAuthenticator([{ keyId: "", secret: KEY }])).toThrow(/must not be empty/);
    expect(() => createHmacAuthenticator([{ keyId: "a", secret: KEY }, { keyId: "a", secret: KEY }])).toThrow(/twice/);
    expect(() => createHmacAuthenticator([{ keyId: "a", secret: Buffer.alloc(31) }])).toThrow(/at least 32 bytes/);
  });

  it("answers unverifiable input instead of throwing", () => {
    for (const raw of [null, 42, "x", {}, { params: { signature: {} } }]) {
      expect(auth.verifyRequest(raw).valid).toBe(false);
    }
    const longSession = request();
    longSession.params.metadata.session_id = "s".repeat(2048);
    const sig = { algorithm: "HMAC-SHA256", key_id: "k1", value: "AAAA" };
    expect(auth.verifyRequest({ ...longSession, params: { ...longSession.params, signature: sig } })).toEqual({
      valid: false,
      reason: "signature input cannot be canonicalised",
    });
    const hostileAlgorithm = JSON.parse('{"params":{"metadata":{"session_id":"s"},"signature":{"algorithm":{"toString":null},"key_id":"k1","value":"AAAA"}}}');
    expect(auth.verifyRequest(hostileAlgorithm)).toEqual({ valid: false, reason: "unsupported algorithm: object" });
    const deep = JSON.parse(`{"params":{"metadata":{"session_id":"s"},"signature":{"algorithm":"HMAC-SHA256","key_id":"k1","value":"AAAA"},"x":${"[".repeat(200_000)}${"]".repeat(200_000)}}}`);
    expect(auth.verifyRequest(deep)).toEqual({ valid: false, reason: "signature input cannot be canonicalised" });
  });

  it("round-trips a signed result and a signed error through the host's check", () => {
    const req = request();
    const key = { keyId: "k1", sessionId: req.params.metadata.session_id };
    for (const response of [{ jsonrpc: "2.0", id: 1, result: { decision: "allow" } }, { jsonrpc: "2.0", id: 1, error: { code: -32005, message: "m" } }]) {
      const signed = auth.signResponse(response, key) as Record<string, unknown>;
      expect(auth.verifyResponse(signed, req)).toEqual({ valid: true, key });
      expect(auth.verifyResponse({ ...signed, id: 2 }, req)).toEqual({ valid: false, reason: "response signature mismatch" });
    }
    expect(auth.verifyResponse({ jsonrpc: "2.0", id: 1, result: {} }, req)).toEqual({ valid: false, reason: "response signature is missing" });
  });

  it("rejects a response that names a key other than the one this side signed with", () => {
    const req = request();
    const other = createHmacAuthenticator([{ keyId: "k2", secret: KEY }]);
    const signed = other.signResponse({ jsonrpc: "2.0", id: 1, result: { decision: "allow" } }, { keyId: "k2", sessionId: req.params.metadata.session_id });
    expect(auth.verifyResponse(signed as Record<string, unknown>, req)).toEqual({
      valid: false,
      reason: "response signature key_id does not name this side's signing key",
    });
  });
});

describe("NULL_AUTHENTICATOR", () => {
  it("signs nothing, accepts everything, and advertises no algorithm", () => {
    const req = request();
    expect(NULL_AUTHENTICATOR.signRequest(req)).toBe(req);
    expect(NULL_AUTHENTICATOR.verifyRequest(null)).toEqual({ valid: true });
    expect(NULL_AUTHENTICATOR.algorithms).toEqual([]);
  });
});

describe("readHmacSecret", () => {
  const good = KEY.toString("base64");

  it("is undefined only when neither variable is set", () => {
    expect(readHmacSecret({})).toBeUndefined();
    expect(readHmacSecret({ ACS_HMAC_SECRET: good })).toEqual(KEY);
  });

  it("throws on a set-but-unusable value rather than running unsigned", () => {
    expect(() => readHmacSecret({ ACS_HMAC_SECRET: "" })).toThrow(/set but empty/);
    expect(() => readHmacSecret({ ACS_HMAC_SECRET_FILE: "  ", ACS_HMAC_SECRET: good })).toThrow(/ACS_HMAC_SECRET_FILE is set but empty/);
    expect(() => readHmacSecret({ ACS_HMAC_SECRET: `${good}!` })).toThrow(/canonical base64/);
    expect(() => readHmacSecret({ ACS_HMAC_SECRET: Buffer.alloc(16).toString("base64") })).toThrow(/16 bytes/);
    expect(() => readHmacSecret({ ACS_HMAC_SECRET: good }, 64)).toThrow(/at least 64/);
  });

  it("prefers the file, and refuses one another user could read", () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-key-"));
    try {
      const file = join(dir, "hmac.key");
      writeFileSync(file, `${good}\n`, { mode: 0o600 });
      expect(readHmacSecret({ ACS_HMAC_SECRET_FILE: file, ACS_HMAC_SECRET: "ignored" })).toEqual(KEY);
      chmodSync(file, 0o640);
      expect(() => readHmacSecret({ ACS_HMAC_SECRET_FILE: file })).toThrow(/mode 640/);
      chmodSync(file, 0o600);
      const link = join(dir, "link.key");
      symlinkSync(file, link);
      expect(() => readHmacSecret({ ACS_HMAC_SECRET_FILE: link })).toThrow(/symlink/);
      expect(() => readHmacSecret({ ACS_HMAC_SECRET_FILE: join(dir, "missing") })).toThrow(/cannot be read/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("readHmacKey", () => {
  const good = KEY.toString("base64");

  it("reads the secret and its label together, and refuses one without the other", () => {
    expect(readHmacKey({})).toBeUndefined();
    expect(readHmacKey({ ACS_HMAC_SECRET: good, ACS_HMAC_KEY_ID: "2026-10" })).toEqual({ keyId: "2026-10", secret: KEY });
    expect(() => readHmacKey({ ACS_HMAC_SECRET: good })).toThrow(/ACS_HMAC_KEY_ID is required/);
    expect(() => readHmacKey({ ACS_HMAC_SECRET: good, ACS_HMAC_KEY_ID: "" })).toThrow(/ACS_HMAC_KEY_ID is required/);
    expect(() => readHmacKey({ ACS_HMAC_KEY_ID: "2026-10" })).toThrow(/no ACS_HMAC_SECRET/);
  });
});
