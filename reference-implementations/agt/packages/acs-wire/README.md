# ACS wire

What the Guardian and a host must agree on to talk ACS, in one small package both of them import. §10 requires both sides to compute the same canonical input and the same per-session key. Here they compute it from the same code. Its only dependencies are `node:crypto` and `node:fs`, so a host imports it without importing the Guardian.

## Get started

```ts
import { createHmacAuthenticator, NULL_AUTHENTICATOR, readHmacSecret } from "acs-wire";

const key = readHmacSecret();
const authenticator = key === undefined ? NULL_AUTHENTICATOR : createHmacAuthenticator(key);
```

The Guardian takes the authenticator as a `RequestVerifier`. A host hands it to `createGuardianClient` as a `RequestSigner`. One `Authenticator` plays both roles:

| Role | Methods | Who depends on it |
|---|---|---|
| `RequestVerifier` | `verifyRequest(raw)`, `signResponse(response, keyId)` | The Guardian |
| `RequestSigner` | `signRequest(envelope)`, `verifyResponse(response, request)` | The host's Guardian client |

`verifyRequest` is total. Any parsed body gets an answer, never a throw, so the Guardian can run it once on unauthenticated input and read the answer twice.

`NULL_AUTHENTICATOR` signs nothing, accepts everything and advertises no algorithm. It is the explicitly unsecured mode for in-process tests, and it is not ACS-Core. Callers never branch on whether a key is configured.

## Read the key

`readHmacSecret` is the one way every process here reads key material. `ACS_HMAC_SECRET_FILE` wins over `ACS_HMAC_SECRET`, matching the Python adapters, because a file stays out of the process environment. The file must be owned by the current user, grant no group or other access, and not be a symlink.

Either source holds canonical base64 of at least 32 bytes. A value that is set but empty, malformed or short throws `HmacSecretError`. Running unsigned would turn off the only integrity control ACS-Core mandates, so it never happens by accident. The function returns `undefined` only when neither variable is set.

## Files

| File | What it holds |
|---|---|
| `src/protocol.ts` | Values the spec fixes: `ACS_VERSION`, the §17.1 `AcsError` codes, the signature algorithm names. Also `ReferenceRefusal`, the three codes this Guardian sends that §17.1 does not list yet |
| `src/jcs.ts` | `jcsCanonicalise`, the one RFC 8785 implementation |
| `src/authenticator.ts` | The roles, `createHmacAuthenticator`, `NULL_AUTHENTICATOR`, HKDF derivation and `readHmacSecret` |

Values a deployment chooses, such as the skew window and the store limits, live in the Guardian's `src/config.ts` instead.
