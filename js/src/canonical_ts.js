// @ts-check
/**
 * Canonical timestamp (spec §4.3): RFC 3339 UTC with six fractional digits
 * and `Z`, e.g. 2026-08-21T10:00:00.500000Z. Date has millisecond precision,
 * so the last three digits are always 0.
 * @param {Date} [d]
 * @returns {string}
 */
export function canonicalTS(d = new Date()) {
	return d.toISOString().replace(/Z$/, "000Z");
}
