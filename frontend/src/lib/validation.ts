/**
 * Input validation helpers shared by the analyse and batch pages.
 *
 * Validation here is deliberately pragmatic: it exists to catch obvious
 * garbage before an OSINT-backed API call is wasted, not to implement
 * a full URL grammar.
 */

/** True when `value` is an http(s) URL with a hostname. */
export function isValidHttpUrl(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 2048) return false;
  if (/[\s]/.test(trimmed)) return false;

  try {
    const url = new URL(trimmed);
    return (url.protocol === "http:" || url.protocol === "https:") &&
      url.hostname.includes(".") &&
      // Hostnames of dots/dashes only (e.g. "http://..") are not real.
      /[a-z0-9]/i.test(url.hostname);
  } catch {
    return false;
  }
}

/** Split raw textarea input into trimmed, non-empty candidate URLs. */
export function splitUrlLines(raw: string): string[] {
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export interface BatchValidation {
  /** Lines that pass URL validation (deduplicated). */
  valid: string[];
  /** Original (pre-dedup) lines that failed validation. */
  invalid: string[];
}

/** Validate a batch of URL lines, deduplicating valid entries. */
export function validateBatch(raw: string): BatchValidation {
  const lines = splitUrlLines(raw);
  const valid = new Set<string>();
  const invalid: string[] = [];

  for (const line of lines.slice(0, 200)) {
    if (isValidHttpUrl(line)) {
      valid.add(line);
    } else {
      invalid.push(line);
    }
  }

  return { valid: [...valid], invalid };
}
