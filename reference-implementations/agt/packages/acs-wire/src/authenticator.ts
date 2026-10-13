/**
 * §10 request and response authentication, for both ends of the wire. The
 * Guardian holds a `RequestVerifier`, a host holds a `RequestSigner`, and one
 * `Authenticator` is both, so the two sides compute the same canonical input
 * from the same code. This is the only module that decodes a key, derives a
 * session key, or computes an HMAC.
 *
 * `NULL_AUTHENTICATOR` is the explicitly unsecured mode: it signs nothing,
 * accepts everything and advertises no algorithm, so callers never branch on
 * whether a key is configured.
 */
import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { jcsCanonicalise } from "./jcs.ts";
import { type AcsSignature, SignatureAlgorithm, type SignatureAlgorithmName } from "./protocol.ts";

/** The shortest input keying material this implementation accepts. */
export const MIN_KEY_BYTES = 32;

/** Valid carries the key the signature was made with, when there was one:
 * the configured `key_id` and the session id its HKDF info was. The null
 * authenticator's answer is valid with no `key`. */
export type Verification = { valid: true; key?: SigningKey } | { valid: false; reason: string };

/** What a response is signed with: the `key_id` and session of the request
 * it answers (§10). */
export type SigningKey = { keyId: string; sessionId: string };

/** A deployment's HMAC secret and the label that names it (§10, `key_id` for
 * HMAC). The label comes from configuration, never from the secret or the
 * session. */
export type HmacKey = { keyId: string; secret: Buffer };

/** A request this module can key: its session id is the HKDF info. */
export type SignableRequest = { params: Record<string, unknown> };

export type RequestVerifier = {
  readonly algorithms: readonly SignatureAlgorithmName[];
  /** Total: any parsed body, however malformed, gets an answer, never a throw. */
  verifyRequest(raw: unknown): Verification;
  /** A copy of `response` with a signature on its `result` or `error`,
   * made with the key the request it answers was verified under. */
  signResponse<T extends object>(response: T, key: SigningKey): T;
};

export type RequestSigner = {
  readonly algorithms: readonly SignatureAlgorithmName[];
  /** A copy of `envelope` with `params.signature` set. */
  signRequest<T extends SignableRequest>(envelope: T): T;
  /** Checks the Guardian's signature on the response to `request`. */
  verifyResponse(response: Record<string, unknown>, request: SignableRequest): Verification;
};

export type Authenticator = RequestVerifier & RequestSigner;

export const NULL_AUTHENTICATOR: Authenticator = {
  algorithms: [],
  verifyRequest: () => ({ valid: true }),
  signResponse: response => response,
  signRequest: envelope => envelope,
  verifyResponse: () => ({ valid: true }),
};

/**
 * HMAC-SHA256 with a per-session key HKDF-derived from a configured secret
 * (§10). `keys[0]` signs this side's requests. Every key verifies, looked up
 * by the `key_id` a message names, so a Guardian holding an old and a new
 * secret accepts hosts on either while a rotation is in progress. An unknown
 * `key_id` is refused, never tried against another secret.
 */
export function createHmacAuthenticator(keys: readonly HmacKey[]): Authenticator {
  if (keys.length === 0) throw new HmacSecretError("an HMAC authenticator needs at least one key");
  const secrets = new Map<string, Buffer>();
  for (const { keyId, secret } of keys) {
    if (keyId === "") throw new HmacSecretError("an HMAC key_id must not be empty");
    if (secrets.has(keyId)) throw new HmacSecretError(`HMAC key_id ${keyId} is configured twice`);
    if (secret.length < MIN_KEY_BYTES) {
      throw new HmacSecretError(`HMAC key material for ${keyId} must be at least ${MIN_KEY_BYTES} bytes, got ${secret.length}`);
    }
    secrets.set(keyId, Buffer.from(secret));
  }
  const signingKeyId = keys[0]!.keyId;
  const mac = (key: SigningKey, input: string) => {
    const secret = secrets.get(key.keyId)!;
    const sessionKey = Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), key.sessionId, 32));
    return createHmac("sha256", sessionKey).update(input).digest();
  };

  function check(key: SigningKey, carrier: () => string, value: string): Verification {
    // Both throws are reachable from unauthenticated input: HKDF caps its info
    // (the session id) at 1024 bytes, and canonicalization overflows the stack
    // on deep nesting. Either way the signature cannot be valid.
    let computed: Buffer;
    try {
      computed = mac(key, carrier());
    } catch {
      return { valid: false, reason: "signature input cannot be canonicalised" };
    }
    const supplied = Buffer.from(value, "base64");
    if (supplied.length !== computed.length) return { valid: false, reason: "signature length mismatch" };
    if (!timingSafeEqual(supplied, computed)) return { valid: false, reason: "signature mismatch" };
    return { valid: true, key };
  }

  return {
    algorithms: [SignatureAlgorithm.HMAC_SHA256],

    verifyRequest(raw) {
      const params = field(raw, "params");
      const sessionId = field(field(params, "metadata"), "session_id");
      const signature = field(params, "signature");
      if (typeof signature !== "object" || signature === null) {
        return { valid: false, reason: "signature required but not present" };
      }
      const { algorithm, key_id, value } = signature as Record<string, unknown>;
      if (algorithm !== SignatureAlgorithm.HMAC_SHA256) {
        return { valid: false, reason: `unsupported algorithm: ${describe(algorithm)}` };
      }
      if (typeof sessionId !== "string") {
        return { valid: false, reason: "request metadata carries no string session_id" };
      }
      if (typeof key_id !== "string" || !secrets.has(key_id)) {
        return { valid: false, reason: "signature key_id names no configured secret" };
      }
      if (typeof value !== "string") return { valid: false, reason: "signature value is not a string" };
      return check({ keyId: key_id, sessionId }, () => requestSigningInput(raw as Record<string, unknown>), value);
    },

    signResponse(response, key) {
      const record = response as Record<string, unknown>;
      const carrierKey = "result" in record && record.result !== undefined ? "result" : "error";
      const value = mac(key, responseSigningInput(record)).toString("base64");
      const signature: AcsSignature = { algorithm: SignatureAlgorithm.HMAC_SHA256, value, key_id: key.keyId };
      return { ...response, [carrierKey]: { ...(record[carrierKey] as object), signature } };
    },

    signRequest(envelope) {
      const sessionId = field(field(envelope.params, "metadata"), "session_id");
      if (typeof sessionId !== "string") {
        throw new Error("signRequest: request metadata carries no string session_id");
      }
      const value = mac({ keyId: signingKeyId, sessionId }, requestSigningInput(envelope)).toString("base64");
      const signature: AcsSignature = { algorithm: SignatureAlgorithm.HMAC_SHA256, value, key_id: signingKeyId };
      return { ...envelope, params: { ...envelope.params, signature } };
    },

    verifyResponse(response, request) {
      const sessionId = field(field(request.params, "metadata"), "session_id");
      if (typeof sessionId !== "string") {
        return { valid: false, reason: "request metadata carries no string session_id" };
      }
      const carrier = [response.result, response.error].find(c => typeof c === "object" && c !== null) as
        | Record<string, unknown>
        | undefined;
      if (!carrier) return { valid: false, reason: "response carries no result or error to verify" };
      const signature = carrier.signature;
      if (typeof signature !== "object" || signature === null) {
        return { valid: false, reason: "response signature is missing" };
      }
      const { algorithm, key_id, value } = signature as Record<string, unknown>;
      if (algorithm !== SignatureAlgorithm.HMAC_SHA256) {
        return { valid: false, reason: `unsupported response signature algorithm: ${describe(algorithm)}` };
      }
      // §10: a response is signed with the key of the request it answers,
      // and this side signs every request with `keys[0]`.
      if (key_id !== signingKeyId) {
        return { valid: false, reason: "response signature key_id does not name this side's signing key" };
      }
      if (typeof value !== "string") return { valid: false, reason: "response signature value is not a string" };
      const verified = check({ keyId: signingKeyId, sessionId }, () => responseSigningInput(response), value);
      return verified.valid ? verified : { valid: false, reason: `response ${verified.reason}` };
    },
  };
}

/** The request's canonical signing input: the whole envelope, `params.signature` removed. */
function requestSigningInput(envelope: Record<string, unknown>): string {
  const params = envelope.params as Record<string, unknown> | undefined;
  if (typeof params !== "object" || params === null) return jcsCanonicalise(envelope);
  const { signature: _, ...unsigned } = params;
  return jcsCanonicalise({ ...envelope, params: unsigned });
}

/** The response's canonical signing input: the whole response, the carrier's `signature` removed. */
function responseSigningInput(response: Record<string, unknown>): string {
  for (const key of ["result", "error"] as const) {
    const carrier = response[key];
    if (typeof carrier === "object" && carrier !== null) {
      const { signature: _, ...unsigned } = carrier as Record<string, unknown>;
      return jcsCanonicalise({ ...response, [key]: unsigned });
    }
  }
  return jcsCanonicalise(response);
}

/** A value from untrusted input, safe to put in a reason: `String()` throws
 * on an object whose `toString` is not a function. */
function describe(value: unknown): string {
  return typeof value === "string" ? value : typeof value;
}

function field(value: unknown, key: string): unknown {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>)[key] : undefined;
}

/** The key material is configured but unusable. Thrown, never downgraded to
 * unsigned: running unsigned turns off the only integrity control ACS-Core
 * mandates. */
export class HmacSecretError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HmacSecretError";
  }
}

/**
 * Reads the shared HMAC key material, the one way every process here does.
 *
 * `ACS_HMAC_SECRET_FILE` wins over `ACS_HMAC_SECRET`, as in the Python
 * adapters: a file is not visible in the process environment. The file must
 * not be a symlink, must grant no group or other access, and must be owned
 * by this user. Either source holds strict base64 of at least `minBytes`.
 *
 * Returns undefined only when neither variable is set, which is unsecured
 * mode. A variable that is set but empty, malformed or short throws.
 */
export function readHmacSecret(
  env: Record<string, string | undefined> = process.env,
  minBytes = MIN_KEY_BYTES,
): Buffer | undefined {
  // Set but blank is a broken path, not an absent one: treating it as unset
  // would fall back to ACS_HMAC_SECRET, or to no key at all.
  if (env.ACS_HMAC_SECRET_FILE !== undefined) {
    const path = env.ACS_HMAC_SECRET_FILE.trim();
    if (path === "") throw new HmacSecretError("ACS_HMAC_SECRET_FILE is set but empty");
    return decodeSecret(readSecretFile(path), "ACS_HMAC_SECRET_FILE", minBytes);
  }
  const value = env.ACS_HMAC_SECRET;
  if (value === undefined) return undefined;
  return decodeSecret(value, "ACS_HMAC_SECRET", minBytes);
}

/**
 * Reads the HMAC key: the secret, as `readHmacSecret` reads it, and the
 * `ACS_HMAC_KEY_ID` label that names it (§10). The label has no default.
 * Returns undefined only when neither is set, which is unsecured mode; one
 * without the other throws.
 */
export function readHmacKey(
  env: Record<string, string | undefined> = process.env,
  minBytes = MIN_KEY_BYTES,
): HmacKey | undefined {
  const secret = readHmacSecret(env, minBytes);
  const keyId = env.ACS_HMAC_KEY_ID;
  if (secret === undefined && keyId === undefined) return undefined;
  if (secret === undefined) throw new HmacSecretError("ACS_HMAC_KEY_ID is set but no ACS_HMAC_SECRET or ACS_HMAC_SECRET_FILE names a secret for it");
  if (!keyId) throw new HmacSecretError("ACS_HMAC_KEY_ID is required with an HMAC secret: it is the key_id that names the secret (Specification §10)");
  return { keyId, secret };
}

function readSecretFile(path: string): string {
  let stat;
  try {
    stat = lstatSync(path);
  } catch (error) {
    throw new HmacSecretError(`ACS_HMAC_SECRET_FILE ${path} cannot be read (${(error as Error).message})`);
  }
  if (stat.isSymbolicLink()) throw new HmacSecretError(`ACS_HMAC_SECRET_FILE ${path} is a symlink; refusing to follow it`);
  if ((stat.mode & 0o077) !== 0) {
    throw new HmacSecretError(
      `ACS_HMAC_SECRET_FILE ${path} has mode ${(stat.mode & 0o777).toString(8)}; it must grant no group or other access (chmod 600)`,
    );
  }
  const uid = process.getuid?.();
  if (uid !== undefined && stat.uid !== uid) {
    throw new HmacSecretError(`ACS_HMAC_SECRET_FILE ${path} is owned by uid ${stat.uid}, not this process's uid ${uid}`);
  }
  try {
    return readFileSync(path, "utf8").trim();
  } catch (error) {
    throw new HmacSecretError(`ACS_HMAC_SECRET_FILE ${path} cannot be read (${(error as Error).message})`);
  }
}

function decodeSecret(text: string, source: string, minBytes: number): Buffer {
  if (text === "") throw new HmacSecretError(`${source} is set but empty`);
  // Strict: Buffer.from(..., "base64") skips characters it does not know, so
  // a typo would silently become a different, shorter key.
  const decoded = Buffer.from(text, "base64");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || decoded.toString("base64") !== text) {
    throw new HmacSecretError(`${source} is not canonical base64`);
  }
  if (decoded.length < minBytes) {
    throw new HmacSecretError(`${source} decodes to ${decoded.length} bytes; at least ${minBytes} are required`);
  }
  return decoded;
}
