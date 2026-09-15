/**
 * Pure helpers for the entry editor. They live outside the component so the
 * tricky conversions can be unit-tested without a DOM.
 */

/** Catalog kind → store kind. WiFi/server/database entries are login/ssh
 * variants; keeping the mapping here keeps the selector and the store in sync. */
const CATALOG_KIND: Record<string, string> = {
  wifi: 'login', server: 'ssh', database: 'ssh', identity: 'login', bank: 'card',
}

/** The store kind a catalog template maps to. */
export function templateKind(rawKind: string): string {
  return CATALOG_KIND[rawKind] ?? rawKind
}

/**
 * Value for `<input type="datetime-local">`, i.e. LOCAL time, or '' when the
 * value cannot be used.
 *
 * It must never throw. `expiresAt` used to be filled straight from a catalog
 * template hint ("expiry epoch millis"), and `new Date(hint).toISOString()`
 * raises `RangeError: Invalid time value` — which took down the whole settings
 * slot until the page was reloaded. Anything unparseable now renders empty.
 */
export function localDateTimeValue(value: unknown): string {
  const ms = typeof value === 'number'
    ? value
    : typeof value === 'string' && value.trim() !== '' ? Date.parse(value) : Number.NaN
  if (!Number.isFinite(ms) || ms <= 0) return ''
  const date = new Date(ms)
  if (Number.isNaN(date.getTime())) return ''
  // datetime-local expects local wall-clock time, so shift by the offset
  // before slicing the ISO string (the old code showed UTC and was off by the
  // timezone).
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

/**
 * Which of a template's texts may be used as field hints. The catalog values
 * are descriptions ("PEM private key", "port (e.g. 22)"), never entry values:
 * they are shown as placeholders, and copying them into the form was what
 * corrupted new entries in the first place.
 */
export function templateHints(fields: Record<string, string>): Record<string, string> {
  const hints: Record<string, string> = {}
  for (const [key, value] of Object.entries(fields)) {
    if (typeof value !== 'string' || value.trim() === '') continue
    // `fields` is the arbitrary key/value map itself; a string is not usable.
    if (key === 'fields') continue
    hints[key] = value
  }
  return hints
}
