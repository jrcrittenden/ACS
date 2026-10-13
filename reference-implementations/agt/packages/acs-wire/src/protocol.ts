/**
 * Wire values both ends of an ACS exchange must agree on. Fixed by the
 * specification, or, for the reference codes below, by this implementation's
 * wire, never by a deployment: a deployment's choices (skew window, timeouts,
 * store limits, key length) live in the Guardian's config instead.
 */

/** The one ACS version this implementation speaks. */
export const ACS_VERSION = "0.1.0";

/** §17.1, the ACS error code registry. */
export const AcsError = {
  SESSION_REFUSED: -32000,
  UNSUPPORTED_VERSION: -32001,
  PROVENANCE_REQUIRED: -32002,
  CAPABILITY_NOT_NEGOTIATED: -32003,
  SIGNATURE_INVALID: -32004,
  REPLAY_DETECTED: -32005,
  TIMESTAMP_OUT_OF_WINDOW: -32006,
  CHAIN_MISMATCH: -32007,
} as const;

/** JSON-RPC 2.0's own codes that this implementation sends. */
export const JsonRpcError = {
  PARSE_ERROR: -32700,
} as const;

/**
 * Refusals this Guardian sends from the reserved -32000..-32099 band that
 * §17.1 does not list yet. Discussion #257 proposes registering them; until
 * then a host knows them from here, not from a copied literal.
 */
export const ReferenceRefusal = {
  ENVELOPE_INVALID: -32010,
  METHOD_NOT_DISPATCHED: -32011,
  EVALUATION_FAILED: -32020,
} as const;

/** §10: the signature algorithms this implementation can produce and check. */
export const SignatureAlgorithm = {
  HMAC_SHA256: "HMAC-SHA256",
} as const;
export type SignatureAlgorithmName = (typeof SignatureAlgorithm)[keyof typeof SignatureAlgorithm];

/** §10: the signature object, on a request's `params` or a response's
 * `result`/`error`. `key_id` is the session id the key was derived for. */
export type AcsSignature = { algorithm: string; value: string; key_id: string };
