/**
 * What a deployment chooses for this Guardian, as opposed to what the spec
 * fixes (those live in acs-wire's protocol.ts). One source per value, so the
 * ServerHello and the checks that enforce what it declares cannot drift
 * apart.
 */
import { MIN_KEY_BYTES } from "acs-wire";

export type GuardianConfig = {
  /** §10.3: the timestamp window, both declared as `skew_window_ms` and
   * enforced. 5 minutes is the spec's RECOMMENDED default. */
  skewWindowMs: number;
  /** The ServerHello's `timeout_config.default_ms`. handshake.json mandates
   * no number; 5s bounds the latency a synchronous pre-tool-call decision
   * adds without tripping on a momentarily slow Guardian. */
  defaultTimeoutMs: number;
  /** Replay store limits (§10.3). A full store refuses rather than evicts. */
  replayMaxSessions: number;
  replayMaxEntries: number;
  /** One session's share of `replayMaxEntries`, so it cannot fill the store
   * and refuse every other session. */
  replayMaxEntriesPerSession: number;
  /** Sessions whose ClientHello methods are remembered, least recently used
   * evicted first; an evicted session re-handshakes after -32003. */
  maxNegotiatedSessions: number;
  /** The shortest HMAC key material main.ts accepts. */
  minKeyBytes: number;
};

export const DEFAULT_GUARDIAN_CONFIG: GuardianConfig = {
  skewWindowMs: 300_000,
  defaultTimeoutMs: 5000,
  replayMaxSessions: 4096,
  replayMaxEntries: 65_536,
  replayMaxEntriesPerSession: 4096,
  maxNegotiatedSessions: 4096,
  minKeyBytes: MIN_KEY_BYTES,
};
