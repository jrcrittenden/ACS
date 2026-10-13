/**
 * Public surface of acs-wire: what both the Guardian and a host must agree on
 * to talk ACS. Depends on node:crypto and node:fs only, so a host can import it
 * without importing the Guardian.
 */
export {
  ACS_VERSION,
  AcsError,
  JsonRpcError,
  ReferenceRefusal,
  SignatureAlgorithm,
  type AcsSignature,
  type SignatureAlgorithmName,
} from "./protocol.ts";
export { jcsCanonicalise } from "./jcs.ts";
export {
  createHmacAuthenticator,
  HmacSecretError,
  MIN_KEY_BYTES,
  NULL_AUTHENTICATOR,
  readHmacKey,
  readHmacSecret,
  type Authenticator,
  type HmacKey,
  type RequestSigner,
  type RequestVerifier,
  type SignableRequest,
  type SigningKey,
  type Verification,
} from "./authenticator.ts";
