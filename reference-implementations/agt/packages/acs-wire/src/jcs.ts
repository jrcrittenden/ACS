/**
 * RFC 8785 JSON Canonicalization Scheme. Deterministic serialization:
 * object keys sorted lexicographically at every depth, no whitespace,
 * numbers via ES2015 Number::toString (which JSON.stringify already uses).
 *
 * Recurses once per nesting level, so a deep enough input throws a
 * RangeError. Callers on unauthenticated input must catch it.
 */
export function jcsCanonicalise(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(jcsCanonicalise).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + jcsCanonicalise(obj[k])).join(",") + "}";
}
