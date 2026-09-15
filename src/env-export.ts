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
export function envLinesFor(entries: Iterable<EnvExportable>, options: EnvExportOptions = {}): string[] {
  const { kind, ids, prefix = '' } = options
  const lines: string[] = []
  const seen = new Set<string>()
  for (const entry of entries) {
    if (kind !== undefined && (entry.kind ?? 'login') !== kind) continue
    if (ids !== undefined && ids.length > 0 && !ids.includes(entry.id)) continue
    if (!(entry.tags ?? []).includes('env')) continue

    const explicit = typeof entry.envKey === 'string' && entry.envKey.length > 0 ? entry.envKey : undefined
    const base = explicit ?? prefix + envKeyFrom(entry.title)
    if (base.length === 0) continue

    const record = entry as unknown as Record<string, unknown>
    const push = (key: string, value: string): void => {
      if (key.length === 0 || seen.has(key)) return // first entry wins
      seen.add(key)
      lines.push(`${key}=${shellQuote(value)}`)
    }

    const present = ENV_FIELD_ORDER.filter(field => {
      const value = record[field]
      return typeof value === 'string' && value.length > 0
    })
    present.forEach((field, index) => {
      const value = record[field] as string
      const suffix = ENV_FIELD_SUFFIX[field] ?? envKeyFrom(field)
      // The primary secret takes the bare name when there is an explicit
      // envKey, and the derived <TITLE>_<SUFFIX> form otherwise.
      if (index === 0 && explicit !== undefined) push(explicit, value)
      else push(`${base}_${suffix}`, value)
    })

    // Custom fields (region, clientId, scope, …) export under the same base so
    // a template's extra values are reachable from scripts too.
    for (const [field, value] of Object.entries(entry.fields ?? {})) {
      if (typeof value !== 'string' || value.length === 0) continue
      push(`${base}_${envKeyFrom(field)}`, value)
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
