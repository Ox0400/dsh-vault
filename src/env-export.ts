/**
 * Environment-variable export, shared by the `vault_env` / `vault_export_env`
 * model tools and the `dsh-vault env` CLI. Keeping one implementation means a
 * key name can never differ between the tool and the command line.
 */

/** Secret fields, most-primary first. The first present one is what an entry's
 * `envKey` names; the rest follow as `<envKey>_<SUFFIX>` (or `<TITLE>_<SUFFIX>`
 * when no envKey is set). */
export const ENV_FIELD_ORDER = ['apiKey', 'secret', 'accessToken', 'refreshToken', 'privateKey', 'password', 'cardNumber', 'cardCvv'] as const

/** Field name → env-key suffix, so `title: DASHSCOPE` + `apiKey` renders the
 * vendor-standard `DASHSCOPE_API_KEY` rather than `DASHSCOPE_APIKEY`. */
export const ENV_FIELD_SUFFIX: Record<string, string> = {
  apiKey: 'API_KEY',
  secret: 'SECRET',
  accessToken: 'ACCESS_TOKEN',
  refreshToken: 'REFRESH_TOKEN',
  privateKey: 'PRIVATE_KEY',
  password: 'PASSWORD',
  cardNumber: 'CARD_NUMBER',
  cardCvv: 'CARD_CVV',
  otpSecret: 'OTP_SECRET',
}

/** Shell/POSIX-safe env key from arbitrary text. */
export function envKeyFrom(text: string): string {
  return text.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '')
}

/** Single-quote a value for `sh` (embedded quotes are escaped). */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

/** The part of an entry this module needs. */
export interface EnvExportable {
  id: string
  title: string
  kind?: string
  envKey?: string
  tags?: string[]
  fields?: Record<string, unknown>
  [field: string]: unknown
}

export interface EnvExportOptions {
  /** Only entries of this kind. */
  kind?: string | undefined
  /** Only these entry ids. */
  ids?: string[] | undefined
  /** Prefix for derived names (an explicit `envKey` is never rewritten). */
  prefix?: string | undefined
}

/**
 * Render env-tagged entries as `KEY=VALUE` lines.
 *
 * Naming: derived keys are `<PREFIX><TITLE>_<FIELD_SUFFIX>`, and an entry's
 * `envKey` replaces that name **verbatim** for its primary secret, with
 * secondary secrets and custom fields as `<envKey>_<SUFFIX>`. First entry wins
 * when two entries would produce the same key.
 */
export interface EnvPair {
  /** The environment-variable name this entry would export. */
  key: string
  /** Which entry field the value came from (`fields.foo` for custom fields). */
  field: string
  value: string
}

/**
 * Every KEY/field pair one entry contributes, **regardless of the `env` tag** —
 * the tag only decides whether `envLinesFor` emits them. `dsh-vault get <KEY>`
 * resolves names through this same function, so a key printed by `env` is
 * always retrievable by `get`, and vice versa.
 */
export function envPairsForEntry(entry: EnvExportable, prefix = ''): EnvPair[] {
  const explicit = typeof entry.envKey === 'string' && entry.envKey.length > 0 ? entry.envKey : undefined
  const base = explicit ?? prefix + envKeyFrom(entry.title)
  if (base.length === 0) return []
  const pairs: EnvPair[] = []
  const record = entry as unknown as Record<string, unknown>
  const present = ENV_FIELD_ORDER.filter(field => {
    const value = record[field]
    return typeof value === 'string' && value.length > 0
  })
  present.forEach((field, index) => {
    const value = record[field] as string
    const suffix = ENV_FIELD_SUFFIX[field] ?? envKeyFrom(field)
    // The primary secret takes the bare name when there is an explicit envKey,
    // and the derived <TITLE>_<SUFFIX> form otherwise.
    const key = index === 0 && explicit !== undefined ? explicit : `${base}_${suffix}`
    pairs.push({ key, field, value })
  })
  // Custom fields (region, clientId, scope, …) export under the same base so a
  // template's extra values are reachable from scripts too.
  for (const [field, value] of Object.entries(entry.fields ?? {})) {
    if (typeof value !== 'string' || value.length === 0) continue
    pairs.push({ key: `${base}_${envKeyFrom(field)}`, field: `fields.${field}`, value })
  }
  return pairs
}

export function envLinesFor(entries: Iterable<EnvExportable>, options: EnvExportOptions = {}): string[] {
  const { kind, ids, prefix = '' } = options
  const lines: string[] = []
  const seen = new Set<string>()
  for (const entry of entries) {
    if (kind !== undefined && (entry.kind ?? 'login') !== kind) continue
    if (ids !== undefined && ids.length > 0 && !ids.includes(entry.id)) continue
    if (!(entry.tags ?? []).includes('env')) continue
    for (const pair of envPairsForEntry(entry, prefix)) {
      if (pair.key.length === 0 || seen.has(pair.key)) continue // first entry wins
      seen.add(pair.key)
      lines.push(`${pair.key}=${shellQuote(pair.value)}`)
    }
  }
  return lines
}

/** The entry's main secret, in the same order the env export uses. */
export function primarySecret(entry: EnvExportable): { field: string; value: string } | undefined {
  for (const field of ENV_FIELD_ORDER) {
    const value = (entry as unknown as Record<string, unknown>)[field]
    if (typeof value === 'string' && value.length > 0) return { field, value }
  }
  return undefined
}

/** Mask a secret for display: `sk-l…` → `sk-l***`. */
export function maskSecret(value: string): string {
  return value.length > 4 ? `${value.slice(0, 4)}***` : '***'
}
