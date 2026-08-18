/**
 * dsh-vault: an encrypted credential vault for DeepSeek Harness.
 *
 * Stores usernames, emails, phone numbers, passwords, and TOTP secrets as
 * individual entries encrypted with AES-256-GCM under a scrypt-derived key,
 * and exposes them to the model through a small tool set:
 *
 * - `vault_add` / `vault_get` / `vault_update` / `vault_delete` — CRUD
 * - `vault_search` — non-secret summary search across all text fields
 * - `vault_totp` — current 6-digit code for a stored TOTP secret
 * - `vault_generate_password` — cryptographically strong password generator
 *
 * The master password is deployment configuration, never a model argument:
 * it is read from the `masterPassword` config field or, when
 * `masterPasswordEnv` is set, from that environment variable at unlock time.
 *
 * @module dsh-vault
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import Schema from '@deepseek-ai/schemastery'
import { Remote, TypertRemoteService } from '@deepseek-ai/dsh-typert-protocol'
import { readFile, writeFile, mkdir, readdir, unlink, rename as renameFile } from 'node:fs/promises'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { homedir } from 'node:os'
import { existsSync, readdirSync, statSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { openVault, defaultVaultPath, type VaultEntry, type VaultEntryKind, type VaultEntryPatch, type VaultEntrySummary, type VaultStore, type CookieData } from './store.ts'
import { totp, parseTotpSecret, hotp, base32Decode } from './totp.ts'
import { generatePassword, generatePassphrase } from './password.ts'
import { checkPassword } from './breach.ts'
import { readChromeLogins, defaultChromeLoginData, defaultChromeLocalState } from './chrome.ts'
import { readKeychainPasswords, listKeychainEntries } from './keychain.ts'
import { analyzeVault, analyzeEntry } from './watchtower.ts'
import { matchScore, normalizedHost } from './urlmatch.ts'
import { openSession, collectSessionCookies, closeSession, openSessionCount, listSessions, cookieHeader, netscapeJar, parseNetscapeJar, pruneExpiredCookies, countExpiredCookies, countExpiringCookies } from './session.ts'
import { readFirefoxLogins } from './firefox.ts'
import { readKdbx, describeKdbxKdf } from './kdbx.ts'
import { readOnePasswordPux, readPasswordCsv, readEnpassJson, readBitwardenJson, readOnePasswordPif, readKeePassXml, decryptBitwardenExport, buildOnePasswordPux } from './imports.ts'

/** Lossless JSON value (mirrors the harness session's JsonValue; kept local so
 * the published bundle builds without depending on the dsh-session package). */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

export const name = 'dsh-vault'
export const inject = ['tools']

export interface Config {
  /** Master password for the vault. Prefer `masterPasswordEnv` for deployments
   * that do not want the secret in cordis.yml. */
  masterPassword?: string
  /** Name of an environment variable holding the master password. */
  masterPasswordEnv?: string
  /** Vault file path; defaults to `$DSH_HOME/vault/default.json`. */
  path?: string
  /** Vault name used for the default path. */
  name?: string
  /** Access policy for the model tools:
   * - `readonly`: mutations are rejected outright (tools + UI).
   * - `ask` (default): reads are free; each add/update/delete routes through
   *   the harness approval channel, so the user confirms every write
   *   ("prompt before writing").
   * - `auto`: reads and writes both run without a per-call prompt
   *   ("automatic read-write").
   * The Settings UI offers this exact three-way choice. */
  accessMode?: 'readonly' | 'ask' | 'auto'
  /** When true, the system prompt instructs the model to detect credentials
   * in the conversation (API keys, tokens, passwords) and, following user
   * preference, save them with vault_add. Defaults to false — capture is
   * opt-in because auto-writing secrets needs explicit consent. */
  autoCapture?: boolean
  /** Auto-lock: after this many seconds of inactivity the vault re-locks and
   * every read/write requires vault_unlock again. `0`/absent disables. */
  lockTimeoutSeconds?: number
  /** Name of an environment variable holding the export/import password for
   * vault_export / vault_import. When absent, those tools require the master
   * password value to be passed explicitly (not recommended). */
  exportPasswordEnv?: string
  /** Number of encrypted backups to keep; vault_backup prunes older copies.
   * Default 10. */
  backupRetention?: number
}

export const Config: Schema<Config> = Schema.object({
  masterPassword: Schema.string(),
  masterPasswordEnv: Schema.string(),
  path: Schema.string(),
  name: Schema.string(),
  accessMode: Schema.union([
    Schema.const('readonly'),
    Schema.const('ask'),
    Schema.const('auto'),
  ]),
  autoCapture: Schema.boolean(),
  lockTimeoutSeconds: Schema.number(),
  exportPasswordEnv: Schema.string(),
  backupRetention: Schema.number().description('How many encrypted backups to keep (default 10; vault_backup prunes older copies).'),
})

/** Built-in field templates per credential kind. */
const TEMPLATES: Record<string, Record<string, string>> = {
  login: { username: 'account username', email: 'account email', password: 'account password' },
  ssh: { host: 'server host', port: 'port (e.g. 22)', username: 'login user', password: 'password or passphrase', privateKey: 'PEM private key' },
  'api-key': { apiKey: 'the API key', url: 'API base URL', username: 'owner/account (optional)' },
  oauth: { accessToken: 'access token', refreshToken: 'refresh token', expiresAt: 'expiry epoch millis', clientId: 'client id (via fields)', scope: 'granted scopes (via fields)', tokenUrl: 'token endpoint (via fields)' },
  secret: { secret: 'the shared secret', notes: 'what it is for' },
  card: { cardNumber: 'card number', cardExpiry: 'expiry (MM/YY)', cardCvv: 'CVV', cardHolder: 'card holder name' },
  wifi: { username: 'network name (SSID)', password: 'Wi-Fi password', host: 'security type (WPA2/WPA3/open, via fields)' },
  server: { host: 'server address', port: 'port (e.g. 22/3306/5432)', username: 'login user', password: 'password or key passphrase', privateKey: 'PEM private key (optional)' },
  database: { host: 'database host', port: 'port (e.g. 3306/5432/6379)', username: 'database user', password: 'database password', url: 'connection URL (optional)' },
  identity: { username: 'full name', email: 'email address', phone: 'phone number', url: 'ID number (via fields)' },
  bank: { cardHolder: 'account holder', cardNumber: 'account number', cardExpiry: 'routing number (via fields)', url: 'bank website' },
  custom: { fields: 'arbitrary key/value pairs' },
}

/** Resolve the newest Firefox profile directory with a logins.json. */
function defaultFirefoxProfileDir(): string {
  const base = join(homedir(), 'Library/Application Support/Firefox/Profiles')
  try {
    const dirs = readdirSync(base)
    const withLogins = dirs.filter(d => existsSync(join(base, d, 'logins.json')))
    if (withLogins.length === 0) throw new Error('no Firefox profile with logins.json found')
    // Prefer "*.default-release", then newest mtime.
    withLogins.sort((a, b) => {
      const aRelease = a.includes('default-release') ? 1 : 0
      const bRelease = b.includes('default-release') ? 1 : 0
      if (aRelease !== bRelease) return bRelease - aRelease
      return statSync(join(base, b)).mtimeMs - statSync(join(base, a)).mtimeMs
    })
    return join(base, withLogins[0]!)
  } catch (error) {
    throw new Error(`Firefox profile not found: ${(error as Error).message}`)
  }
}

export async function apply(ctx: Context, config: Config): Promise<void> {
  const masterPassword = resolveMasterPassword(config)
  const WRITE_TOOLS = new Set(['vault_add', 'vault_update', 'vault_delete'])
  const lockTimeoutSeconds = config.lockTimeoutSeconds ?? 0

  /** Shared access policy; resolved once, mutated by the UI via setAccessMode. */
  const policy = await sharedAccessPolicy(config)

  /** Audit events: other plugins / session logging can subscribe. Payload is
   * non-secret (tool name + entry id/title only). */
  const emitAudit = (kind: 'read' | 'write', tool: string, entryId?: string, title?: string): void => {
    try {
      ;(ctx as unknown as { emit: (name: string, payload: unknown) => void }).emit(`vault/${kind}`, { tool, entryId, title, at: Date.now() })
    } catch {
      // A throwing listener must never break the vault operation.
    }
  }

  /** Reject mutations when the vault is in readonly mode. */
  function assertWritable(action: string): void {
    if (policy.mode === 'readonly') {
      throw new Error(`vault: ${action} is disabled in readonly mode (set accessMode to "ask" or "auto" to enable)`)
    }
  }

  /**
   * Route writes through the harness approval channel in `ask` mode: the user
   * confirms every add/update/delete ("prompt before writing"). `auto` allows
   * without a prompt; `readonly` denies in assertWritable. This listener must
   * call `next()` (waterfall event).
   */
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec?.name === undefined) return next()
    if (policy.mode === 'ask' && WRITE_TOOLS.has(exec.name)) {
      return { kind: 'ask', reason: `dsh-vault: ${exec.name} requires your confirmation in "ask" (prompt-before-write) mode` }
    }
    // High-sensitivity reads: reading a `high` entry's secrets (vault_get by
    // id) requires confirmation in BOTH ask and auto modes — sensitive reads
    // are always gated, unlike ordinary writes.
    if (policy.mode !== 'readonly' && exec.name === 'vault_get') {
      const id = (exec.arguments as { id?: string } | undefined)?.id
      if (id !== undefined) {
        try {
          const store = await ensureStore()
          const entry = store.get(id)
          if (entry?.sensitivity === 'high') {
            return { kind: 'ask', reason: `dsh-vault: reading high-sensitivity entry "${entry.title}" requires your confirmation` }
          }
        } catch {
          // If the vault is locked etc., let the tool itself report it.
        }
      }
    }
    return next()
  })

  /** Ensure the shared store is open (lazily on first use, so a missing
   * master password fails at the first tool call with a clear message). */
  async function ensureStore(): Promise<VaultStore> {
    const store = await sharedVaultStore(masterPassword, config)
    // Install the auto-lock policy once per store instance: a persisted
    // policy value (set from the Settings UI) wins, otherwise fall back to
    // the configured lockTimeoutSeconds.
    const seconds = policy.autoLockSeconds ?? lockTimeoutSeconds
    if (seconds > 0) store.setAutoLock(seconds * 1000)
    return store
  }

  /** Guard every tool: enforce auto-lock (relock when idle, refuse when
   * locked) and touch the activity timestamp. */
  async function guardStore(): Promise<VaultStore> {
    const store = await ensureStore()
    if (store.expired) {
      store.lock()
      throw new Error('vault is locked (idle timeout) — call vault_unlock to re-open it')
    }
    if (store.isLocked) {
      throw new Error('vault is locked — call vault_unlock to re-open it')
    }
    store.touch()
    return store
  }

  /** Read a full entry (with secrets) by id (respects locking). */
  async function readEntry(id: string): Promise<VaultEntry | undefined> {
    const s = await guardStore()
    return s.get(id)
  }

  // System prompt guidance: tells the model how the vault works, what the
  // current access mode allows, and — when autoCapture is enabled — to detect
  // credentials in the conversation and offer to save them via vault_add.
  const systemPrompt = ctx.get('systemPrompt')
  systemPrompt?.section({
    name: 'dsh-vault',
    order: 150,
    text: () => {
      const lines = [
        '## Encrypted credential vault (dsh-vault)',
        policy.mode === 'readonly'
          ? 'Access mode: READONLY — you may search/read/generate codes but MUST NOT add, update, or delete entries.'
          : policy.mode === 'ask'
            ? 'Access mode: ASK (prompt-before-write) — reads are free; every add/update/delete will ask the user for confirmation through the approval channel.'
            : 'Access mode: AUTO (automatic read-write) — you may add, update, delete, search, and read entries without a per-call prompt.',
        'Credentials are encrypted at rest (AES-256-GCM) under a master password the user configured; never ask for that password.',
        'Use vault_search to find entries by title/username/host and vault_get (by id) to read full credentials when the task needs them.',
        'Do not repeat secrets in the conversation when a credential was obtained via vault_get.',
      ]
      if (policy.autoCapture) {
        lines.push(
          'Auto-capture is ON: when the user shares an API key, token, password, or other credential in conversation',
          '(e.g. "my npm token is npm_…", "use this GitHub PAT"), offer to store it with vault_add under a clear title.',
          'Capture user preference: if they agree (or have previously agreed to auto-save), call vault_add immediately;',
          'if they decline or it is unclear, do NOT store it. Never auto-save credentials that were not explicitly shared.',
        )
      } else {
        lines.push(
          'Auto-capture is OFF: do not save credentials from the conversation unless the user explicitly asks you to.',
        )
      }
      return lines.join('\n')
    },
  })

  ctx.tools.register(defineTool({
    name: 'vault_add',
    description: 'Add a new credential entry to the encrypted vault. '
      + 'Stores login credentials (username/email/phone/password), SSH connections (host/port/privateKey), '
      + 'API keys (apiKey/secret), OAuth tokens (accessToken/refreshToken/expiresAt), TOTP secrets, or any combination, '
      + 'under a human title. The entry is encrypted at rest with AES-256-GCM; only its summary (no secrets) is returned. '
      + 'Use the returned entry id in later vault_get/vault_update/vault_delete calls.',
    parameters: {
      title: { type: 'string', required: true, description: 'Human title, e.g. "GitHub personal" or "prod-db ssh".' },
      kind: {
        type: 'string',
        description: 'Entry category: login (default), ssh, api-key, secret, oauth, cookie, card, or custom.',
        enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'],
      },
      sensitivity: { type: 'string', enum: ['normal', 'high'], description: 'Sensitivity tier; "high" entries require confirmation when read in ask mode.' },
      rotationDays: { type: 'integer', description: 'Rotation interval in days; vault_rotation reports when it elapses.' },
      icon: { type: 'string', description: 'Optional emoji/icon shown in the UI (e.g. "🚀").' },
      color: { type: 'string', description: 'Optional accent color (e.g. "red", "#ff0000").' },
      username: { type: 'string', description: 'Account username/login.' },
      email: { type: 'string', description: 'Account email.' },
      phone: { type: 'string', description: 'Account phone number.' },
      password: { type: 'string', description: 'The password to store.' },
      host: { type: 'string', description: 'SSH host or service hostname.' },
      port: { type: 'string', description: 'SSH/service port, e.g. "22" or "3306".' },
      privateKey: { type: 'string', description: 'SSH private key (PEM).' },
      apiKey: { type: 'string', description: 'API key.' },
      secret: { type: 'string', description: 'Generic secret (client secret, shared secret, …).' },
      accessToken: { type: 'string', description: 'OAuth access token.' },
      refreshToken: { type: 'string', description: 'OAuth refresh token.' },
      expiresAt: { type: 'integer', description: 'Token/credential expiry epoch millis.' },
      otpSecret: { type: 'string', description: 'TOTP secret: bare Base32 or an otpauth:// URI.' },
      cardNumber: { type: 'string', description: 'Bank/credit card number (kind card).' },
      cardExpiry: { type: 'string', description: 'Card expiry as MM/YY or MM/YYYY (kind card).' },
      cardCvv: { type: 'string', description: 'Card CVV/CVC (kind card).' },
      cardHolder: { type: 'string', description: 'Card holder name (kind card).' },
      url: { type: 'string', description: 'Associated URL (login page or service home).' },
      notes: { type: 'string', description: 'Free-form notes.' },
      tags: { type: 'array', description: 'Searchable tags (array).', items: { type: 'string' } },
      tagsCsv: { type: 'string', description: 'Tags as a comma/semicolon-separated string (alternative to tags).' },
      fields: {
        type: 'object',
        additionalProperties: true,
        properties: {},
        description: 'Arbitrary additional key/value fields, e.g. {"region": "us-east-1"}.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          id: { type: 'string', required: true },
          title: { type: 'string', required: true },
          message: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: `${value.message} (id: ${value.id})` }],
    },
    async execute(args) {
      assertWritable('vault_add')
      if (!args.title.trim()) throw new Error('vault_add: title must not be empty')
      const s = await guardStore()
      const entry = await s.add({
        title: args.title.trim(),
        ...(args.kind !== undefined ? { kind: args.kind } : {}),
        ...(args.sensitivity !== undefined ? { sensitivity: args.sensitivity } : {}),
        ...(args.rotationDays !== undefined ? { rotationDays: args.rotationDays } : {}),
        ...(args.icon !== undefined ? { icon: args.icon } : {}),
        ...(args.color !== undefined ? { color: args.color } : {}),
        ...(args.username !== undefined ? { username: args.username } : {}),
        ...(args.email !== undefined ? { email: args.email } : {}),
        ...(args.phone !== undefined ? { phone: args.phone } : {}),
        ...(args.password !== undefined ? { password: args.password } : {}),
        ...(args.host !== undefined ? { host: args.host } : {}),
        ...(args.port !== undefined ? { port: args.port } : {}),
        ...(args.privateKey !== undefined ? { privateKey: args.privateKey } : {}),
        ...(args.apiKey !== undefined ? { apiKey: args.apiKey } : {}),
        ...(args.secret !== undefined ? { secret: args.secret } : {}),
        ...(args.accessToken !== undefined ? { accessToken: args.accessToken } : {}),
        ...(args.refreshToken !== undefined ? { refreshToken: args.refreshToken } : {}),
        ...(args.expiresAt !== undefined ? { expiresAt: args.expiresAt } : {}),
        ...(args.otpSecret !== undefined ? { otpSecret: args.otpSecret } : {}),
        ...(args.cardNumber !== undefined ? { cardNumber: args.cardNumber } : {}),
        ...(args.cardExpiry !== undefined ? { cardExpiry: args.cardExpiry } : {}),
        ...(args.cardCvv !== undefined ? { cardCvv: args.cardCvv } : {}),
        ...(args.cardHolder !== undefined ? { cardHolder: args.cardHolder } : {}),
        ...(args.url !== undefined ? { url: args.url } : {}),
        ...(args.notes !== undefined ? { notes: args.notes } : {}),
        ...(args.tags !== undefined || args.tagsCsv !== undefined
          ? { tags: normalizeTags(args.tagsCsv ?? args.tags) }
          : {}),
        ...(args.fields !== undefined ? { fields: args.fields } : {}),
      })
      emitAudit('write', 'vault_add', entry.id, entry.title)
      const warning = args.password !== undefined && estimateStrength(args.password).score < 40
        ? ' (warning: password looks weak — run vault_strength to check)'
        : ''
      return { id: entry.id, title: entry.title, message: 'added credential entry' + warning }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_get',
    description: 'Read one credential entry from the vault by its id, including the stored password and TOTP secret. '
      + 'Secrets are returned only to this tool call; prefer vault_search for non-secret summaries.',
    parameters: {
      id: { type: 'string', required: true, description: 'The entry id returned by vault_add or vault_search.' },
      fields: { type: 'array', items: { type: 'string' }, description: 'Only return these fields (e.g. ["password", "username"]); omit for all.' },
      includeHistory: { type: 'boolean', description: 'Also return recent mutation history for this entry.' },
      redact: { type: 'boolean', description: 'Return secret fields masked (e.g. "hunter***") instead of plaintext.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          found: { type: 'boolean', required: true },
          entry: { type: 'json' },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.found ? JSON.stringify(value.entry) : 'entry not found' }],
    },
    async execute(args) {
      const entry = await readEntry(args.id)
      if (!entry) return { found: false }
      emitAudit('read', 'vault_get', entry.id, entry.title)
      let full = stripTimestamps(entry) as Record<string, unknown>
      if (args.redact === true) {
        const redacted: Record<string, unknown> = {}
        for (const [k, v] of Object.entries(full)) {
          if (typeof v === 'string' && v.length > 0 && ['password', 'apiKey', 'secret', 'accessToken', 'refreshToken', 'otpSecret', 'privateKey'].includes(k)) {
            redacted[k] = v.length > 8 ? v.slice(0, 4) + '***' : '***'
          } else {
            redacted[k] = v
          }
        }
        full = redacted
      }
      if (args.includeHistory === true) {
        const s = await guardStore()
        full.history = s.getHistory().filter(h => h.id === entry.id).slice(0, 10) as unknown as JsonValue
      }
      if (Array.isArray(args.fields) && args.fields.length > 0) {
        const picked: Record<string, unknown> = {}
        for (const f of args.fields) {
          if (typeof f === 'string' && f in full) picked[f] = full[f]
        }
        return { found: true, entry: picked as unknown as JsonValue }
      }
      return { found: true, entry: full as unknown as JsonValue }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_search',
    description: 'Search the encrypted vault across titles, categories, usernames, emails, phone numbers, hosts, ports, '
      + 'URLs, notes, tags, and custom field values. '
      + 'Returns non-secret summaries (id, title, kind, username, email, phone, host, port, url, tags) — never passwords, '
      + 'keys, tokens, or TOTP secrets. Use vault_get with a result id to read the full entry.',
    parameters: {
      query: { type: 'string', description: 'Search text; matches case-insensitively. Omit to list all (optionally filtered by kind).' },
      kind: { type: 'string', description: 'Only return entries of this kind (login/ssh/api-key/secret/oauth/cookie/card/custom).', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'] },
      favoriteOnly: { type: 'boolean', description: 'Only return pinned (favorite) entries.' },
      tag: { type: 'string', description: 'Only return entries carrying this tag.' },
      regex: { type: 'boolean', description: 'Treat query as a regular expression (case-insensitive).' },
      sortBy: { type: 'string', enum: ['alpha', 'recent', 'favorite', 'smart'], description: 'Sort: alphabetical (default), by updatedAt desc, favorites first, or smart (favorites → recently used → alphabetical).' },
      createdAfter: { type: 'integer', description: 'Only entries created after this epoch millis.' },
      createdBefore: { type: 'integer', description: 'Only entries created before this epoch millis.' },
      limit: { type: 'number', description: 'Maximum results (default 20).' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          results: {
            type: 'array',
            required: true,
            items: { type: 'json' },
          },
          total: { type: 'integer', required: true },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.total === 0
          ? 'no matching entries'
          : JSON.stringify(value.results),
      }],
    },
    async execute(args) {
      const s = await guardStore()
      const limit = validateLimit(args.limit, 'vault_search')
      const results = args.regex === true
        ? s.searchRegex(args.query ?? '', limit)
        : s.search(args.query ?? '', limit)
      const kind = args.kind
      let filtered = kind === undefined ? results : results.filter(r => (r.kind ?? 'login') === kind)
      if (args.favoriteOnly === true) filtered = filtered.filter(r => (r as VaultEntrySummary & { favorite?: boolean }).favorite)
      if (args.tag !== undefined) {
        const tag = String(args.tag).trim()
        if (tag.length > 0) filtered = filtered.filter(r => (r.tags ?? []).includes(tag))
      }
      if (args.createdAfter !== undefined) {
        const store2 = await guardStore()
        const ids = new Set(store2.list().filter(e => e.createdAt > args.createdAfter!).map(e => e.id))
        filtered = filtered.filter(r => ids.has(r.id))
      }
      if (args.createdBefore !== undefined) {
        const store2 = await guardStore()
        const ids = new Set(store2.list().filter(e => e.createdAt < args.createdBefore!).map(e => e.id))
        filtered = filtered.filter(r => ids.has(r.id))
      }
      if (args.sortBy === 'recent') {
        filtered = [...filtered].sort((a, b) => {
          const au = (a as VaultEntrySummary & { updatedAt?: number }).updatedAt ?? 0
          const bu = (b as VaultEntrySummary & { updatedAt?: number }).updatedAt ?? 0
          return bu - au
        })
      } else if (args.sortBy === 'favorite') {
        filtered = [...filtered].sort((a, b) => {
          const af = (a as VaultEntrySummary & { favorite?: boolean }).favorite === true ? 0 : 1
          const bf = (b as VaultEntrySummary & { favorite?: boolean }).favorite === true ? 0 : 1
          return af - bf || a.title.localeCompare(b.title)
        })
      } else if (args.sortBy === 'smart') {
        filtered = [...filtered].sort((a, b) => {
          const af = (a as VaultEntrySummary & { favorite?: boolean }).favorite === true ? 0 : 1
          const bf = (b as VaultEntrySummary & { favorite?: boolean }).favorite === true ? 0 : 1
          if (af !== bf) return af - bf
          const au = (a as VaultEntrySummary & { updatedAt?: number }).updatedAt ?? 0
          const bu = (b as VaultEntrySummary & { updatedAt?: number }).updatedAt ?? 0
          return bu - au || a.title.localeCompare(b.title)
        })
      }
      return { results: filtered, total: filtered.length }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_update',
    description: 'Update fields of an existing vault entry by id. Only the provided fields change; secrets and other '
      + 'fields are preserved. Pass an empty-string value to clear a field. Returns the updated entry summary.',
    parameters: {
      id: { type: 'string', required: true, description: 'The entry id to update.' },
      title: { type: 'string', description: 'New title.' },
      kind: {
        type: 'string',
        description: 'New category.',
        enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'],
      },
      username: { type: 'string', description: 'New username.' },
      email: { type: 'string', description: 'New email.' },
      phone: { type: 'string', description: 'New phone number.' },
      password: { type: 'string', description: 'New password.' },
      host: { type: 'string', description: 'New SSH host or hostname.' },
      port: { type: 'string', description: 'New port.' },
      privateKey: { type: 'string', description: 'New SSH private key.' },
      apiKey: { type: 'string', description: 'New API key.' },
      secret: { type: 'string', description: 'New secret.' },
      accessToken: { type: 'string', description: 'New OAuth access token.' },
      refreshToken: { type: 'string', description: 'New OAuth refresh token.' },
      expiresAt: { type: 'integer', description: 'New expiry epoch millis.' },
      sensitivity: { type: 'string', enum: ['normal', 'high'], description: 'Sensitivity tier; "high" entries require confirmation when read in ask mode.' },
      rotationDays: { type: 'integer', description: 'Rotation interval in days; vault_rotation reports when it elapses.' },
      icon: { type: 'string', description: 'Optional emoji/icon shown in the UI (e.g. "🚀").' },
      color: { type: 'string', description: 'Optional accent color (e.g. "red", "#ff0000").' },
      favorite: { type: 'boolean', description: 'Pin/unpin the entry (favorites rank first in search).' },
      resetRotation: { type: 'boolean', description: 'Reset the rotation timer now (sets updatedAt to now).' },
      otpSecret: { type: 'string', description: 'New TOTP secret.' },
      cardNumber: { type: 'string', description: 'New card number.' },
      cardExpiry: { type: 'string', description: 'New card expiry (MM/YY).' },
      cardCvv: { type: 'string', description: 'New card CVV.' },
      cardHolder: { type: 'string', description: 'New card holder.' },
      url: { type: 'string', description: 'New URL.' },
      notes: { type: 'string', description: 'New notes.' },
      tags: { type: 'array', description: 'New tags.', items: { type: 'string' } },
      fields: {
        type: 'object',
        additionalProperties: true,
        properties: {},
        description: 'Replace the arbitrary key/value fields.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          found: { type: 'boolean', required: true },
          entry: { type: 'json' },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.found ? 'entry updated' : 'entry not found' }],
    },
    async execute(args) {
      assertWritable('vault_update')
      const s = await guardStore()
      const patch: VaultEntryPatch = {}
      for (const key of [
        'title', 'kind', 'sensitivity', 'favorite', 'rotationDays', 'username', 'email', 'phone', 'password', 'host', 'port', 'privateKey',
        'apiKey', 'secret', 'accessToken', 'refreshToken', 'expiresAt', 'otpSecret', 'url', 'notes', 'tags', 'fields',
      ] as const) {
        const value = args[key]
        if (value !== undefined) {
          ;(patch as Record<string, unknown>)[key] = key === 'fields' ? cleanFieldsValue(value) ?? {} : value
        }
      }
      const updated = args.resetRotation === true
        ? await s.update(args.id, patch).then(async u => { if (u) await s.markUsed(args.id); return u })
        : await s.update(args.id, patch)
      if (!updated) return { found: false }
      emitAudit('write', 'vault_update', updated.id, updated.title)
      return { found: true, entry: toSummaryJson(updated) }
      void cleanFieldsValue
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_delete',
    description: 'Delete a vault entry by id. Returns whether the entry existed. This cannot be undone.',
    parameters: {
      id: { type: 'string', required: true, description: 'The entry id to delete.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          deleted: { type: 'boolean', required: true },
          message: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.message }],
    },
    async execute(args) {
      assertWritable('vault_delete')
      const s = await guardStore()
      const deleted = await s.delete(args.id)
      if (deleted) emitAudit('write', 'vault_delete', args.id)
      return { deleted, message: deleted ? 'entry deleted' : 'entry not found' }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_totp',
    description: 'Generate the current time-based one-time password (TOTP) for a secret stored in the vault or for a '
      + 'bare Base32 secret / otpauth:// URI passed directly. Useful for two-factor authentication codes. '
      + 'The code is valid only for the current 30-second window.',
    parameters: {
      id: { type: 'string', description: 'Vault entry id whose otpSecret to use. Provide exactly one of id or secret.' },
      secret: { type: 'string', description: 'Bare Base32 secret or otpauth:// URI. Provide exactly one of id or secret.' },
      period: { type: 'integer', description: 'Time step in seconds (default 30). Ignored when the secret is an otpauth URI that declares its own period.' },
      digits: { type: 'integer', description: 'Code length (default 6; 6–10). Ignored when the secret is an otpauth URI that declares its own digits.' },
      counter: { type: 'integer', description: 'HOTP counter (RFC 4226). When provided, generates a counter-based code instead of time-based TOTP.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          code: { type: 'string', required: true },
          label: { type: 'string', description: 'Entry title or issuer when known.' },
          secondsRemaining: { type: 'integer', required: true },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: `TOTP code${value.label ? ` for ${value.label}` : ''}: ${value.code} (${value.secondsRemaining}s left)`,
      }],
    },
    async execute(args) {
      if ((args.id === undefined) === (args.secret === undefined)) {
        throw new Error('vault_totp: provide exactly one of id or secret')
      }
      let secret: string
      let label: string | undefined
      if (args.id !== undefined) {
        const entry = await readEntry(args.id)
        if (!entry?.otpSecret) {
          throw new Error(`vault_totp: entry ${args.id} has no otpSecret`)
        }
        secret = entry.otpSecret
        label = entry.title
      } else {
        secret = args.secret!
      }
      const nowMs = Date.now()
      const period = args.period ?? 30
      const digits = args.digits ?? 6
      if (!Number.isInteger(period) || period < 5 || period > 3600) {
        throw new Error('vault_totp: period must be an integer 5–3600')
      }
      if (!Number.isInteger(digits) || digits < 6 || digits > 10) {
        throw new Error('vault_totp: digits must be an integer 6–10')
      }
      if (args.counter !== undefined) {
        if (!Number.isInteger(args.counter) || args.counter < 0) {
          throw new Error('vault_totp: counter must be a non-negative integer')
        }
        const parsed = parseTotpSecret(secret)
        const code = hotp(base32Decode(parsed.secret), args.counter, digits)
        return { code, ...(label !== undefined ? { label } : {}), secondsRemaining: -1 }
      }
      const code = totpWith(secret, nowMs, period, digits)
      const secondsRemaining = period - Math.floor(nowMs / 1000) % period
      return { code, ...(label !== undefined ? { label } : {}), secondsRemaining }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_generate_password',
    description: 'Generate a cryptographically strong random password (configurable length/classes) or a '
      + 'memorable passphrase (passphrase: true, EFF-style word list). Use when a user needs a new password; '
      + 'the generated value is returned and is not stored automatically — call vault_add or vault_update to persist it.',
    parameters: {
      length: { type: 'integer', description: 'Total length (default 20, min = number of selected classes).' },
      lowercase: { type: 'boolean', description: 'Include lowercase (default true).' },
      uppercase: { type: 'boolean', description: 'Include uppercase (default true).' },
      digits: { type: 'boolean', description: 'Include digits (default true).' },
      symbols: { type: 'boolean', description: 'Include symbols (default true).' },
      excludeAmbiguous: { type: 'boolean', description: 'Exclude 0/O/1/l/I (default false).' },
      group: { type: 'integer', description: 'Insert "-" every N characters (e.g. 3 → vK7-mQ2-zt9).' },
      prefix: { type: 'string', description: 'Fixed prefix prepended to the random core (site requirements).' },
      suffix: { type: 'string', description: 'Fixed suffix appended to the random core (site requirements).' },
      passphrase: { type: 'boolean', description: 'Generate a memorable passphrase instead of a random password (ignores length/classes/group).' },
      pin: { type: 'boolean', description: 'Generate a numeric PIN (digits only, default length 6, ambiguous digits excluded).' },
      words: { type: 'integer', description: 'Number of words for passphrase mode (default 4, 2–12).' },
      separator: { type: 'string', description: 'Separator between passphrase words (default "-").' },
      wordDigits: { type: 'boolean', description: 'Append two random digits in passphrase mode (default true).' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          password: { type: 'string', required: true },
          length: { type: 'integer', required: true },
          strength: { type: 'json' },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.password }],
    },
    async execute(args) {
      if (args.pin === true) {
        const password = generatePassword({
          length: args.length ?? 6,
          lowercase: false,
          uppercase: false,
          digits: true,
          symbols: false,
          excludeAmbiguous: true,
        })
        return { password, length: password.length, strength: estimateStrength(password) }
      }
      if (args.passphrase === true) {
        const password = generatePassphrase({
          ...(args.words !== undefined ? { words: args.words } : {}),
          ...(args.separator !== undefined ? { separator: args.separator } : {}),
          ...(args.wordDigits !== undefined ? { wordDigits: args.wordDigits } : {}),
        })
        return { password, length: password.length, strength: estimateStrength(password) }
      }
      const password = generatePassword({
        ...(args.length !== undefined ? { length: args.length } : {}),
        ...(args.lowercase !== undefined ? { lowercase: args.lowercase } : {}),
        ...(args.uppercase !== undefined ? { uppercase: args.uppercase } : {}),
        ...(args.digits !== undefined ? { digits: args.digits } : {}),
        ...(args.symbols !== undefined ? { symbols: args.symbols } : {}),
        ...(args.excludeAmbiguous !== undefined ? { excludeAmbiguous: args.excludeAmbiguous } : {}),
        ...(args.group !== undefined ? { group: args.group } : {}),
        ...(args.prefix !== undefined ? { prefix: args.prefix } : {}),
        ...(args.suffix !== undefined ? { suffix: args.suffix } : {}),
      })
      return { password, length: password.length, strength: estimateStrength(password) }
    },
  }))

  // ── vault_lock / vault_unlock: explicit lock & unlock ──────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_lock',
    description: 'Lock the vault immediately: wipe the derived key from memory so every '
      + 'subsequent read/write requires vault_unlock. Use when leaving the machine.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { locked: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.locked ? 'vault locked' : 'vault not unlocked' }] },
    async execute() {
      const s = await ensureStore()
      const was = s.isLocked
      s.lock()
      return { locked: !was }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_unlock',
    description: 'Unlock the vault with the master password (the deployment owns the password; '
      + 'the model never supplies it). Needed after an explicit vault_lock or an auto-lock idle timeout.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { unlocked: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.unlocked ? 'vault unlocked' : 'vault already unlocked' }] },
    async execute() {
      const s = await ensureStore()
      if (!s.isLocked) return { unlocked: false }
      try {
        await s.unlock()
      } catch {
        // unlock() re-derives with the configured master password; a failure
        // here means the deployment's password changed out from under us.
        throw new Error('vault_unlock: could not re-derive the vault key — the configured master password may have changed; check masterPassword/masterPasswordEnv')
      }
      return { unlocked: true }
    },
  }))

  // ── vault_totp_uri: build an otpauth:// provisioning URI ────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_totp_uri',
    description: 'Build an otpauth://totp/ provisioning URI for a stored otpSecret (or a bare secret), '
      + 'so the user can scan it into an authenticator app. Returns the URI string.',
    parameters: {
      id: { type: 'string', description: 'Vault entry id whose otpSecret to use. Provide exactly one of id or secret.' },
      secret: { type: 'string', description: 'Bare Base32 secret. Provide exactly one of id or secret.' },
      label: { type: 'string', description: 'Account label in the URI (default: entry title or "dsh-vault").' },
      issuer: { type: 'string', description: 'Issuer name (default: "dsh-vault").' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { uri: { type: 'string', required: true }, qr: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.uri }] },
    async execute(args) {
      if ((args.id === undefined) === (args.secret === undefined)) {
        throw new Error('vault_totp_uri: provide exactly one of id or secret')
      }
      let secret: string
      let label = args.label
      if (args.id !== undefined) {
        const entry = await readEntry(args.id)
        if (!entry?.otpSecret) throw new Error(`vault_totp_uri: entry ${args.id} has no otpSecret`)
        secret = entry.otpSecret
        label = label ?? entry.title
      } else {
        secret = args.secret!
        label = label ?? 'dsh-vault'
      }
      const issuer = args.issuer ?? 'dsh-vault'
      const encodedLabel = encodeURIComponent(`${issuer}:${label ?? ''}`).replace(/%3A/g, ':')
      const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: '6', period: '30' })
      const uri = `otpauth://totp/${encodedLabel}?${params.toString()}`
      // The URI encodes a QR payload; render it as a QR (e.g. via a QR lib)
      // or paste it into an authenticator manually.
      return { uri, qr: `scan or enter this otpauth URI in your authenticator app:\n${uri}` }
    },
  }))

  // ── vault_clipboard: return a secret for copy with a caution notice ─────────
  ctx.tools.register(defineTool({
    name: 'vault_clipboard',
    description: 'Fetch one entry secret field for direct copy (username/password/apiKey/...). '
      + 'Returns the value plus a caution note: prefer handing the value to a clipboard/paste action '
      + 'rather than echoing it into the conversation, and do not repeat it in chat afterwards.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
      field: { type: 'string', required: true, description: 'Field to copy: username, password, apiKey, secret, accessToken, refreshToken, otpSecret, privateKey, cardNumber, cardCvv.' },
      masked: { type: 'boolean', description: 'Return the value masked (e.g. hunter***) instead of plaintext.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { value: { type: 'string', required: true }, caution: { type: 'string', required: true }, autoClearSeconds: { type: 'integer', required: true } } },
      render: (_a, v) => [{ type: 'text', text: `copied value (auto-clears in ${v.autoClearSeconds}s, do not echo) — ${v.caution}` }],
    },
    async execute(args) {
      const entry = await readEntry(args.id)
      if (!entry) throw new Error(`vault_clipboard: entry ${args.id} not found`)
      const value = entry[args.field as keyof VaultEntry]
      if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`vault_clipboard: entry ${args.id} has no ${args.field}`)
      }
      const outValue = args.masked === true ? value.slice(0, 6) + '***' : value
      return { value: outValue, caution: 'value returned for copy; do not repeat it in the conversation', autoClearSeconds: 30 }
    },
  }))

  // ── vault_notes: append/replace an entry's notes ────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_notes',
    description: 'Append to or replace the free-form notes of an entry (a convenient shortcut for '
      + 'vault_update). Returns the updated entry summary.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
      text: { type: 'string', required: true, description: 'Notes text. Pass an empty string to clear notes.' },
      append: { type: 'boolean', description: 'Append to existing notes instead of replacing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { updated: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.updated ? 'notes updated' : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_notes')
      const s = await guardStore()
      const current = s.get(args.id)
      if (!current) return { updated: false }
      const text = args.text
      const notes = args.append && current.notes !== undefined && text.length > 0
        ? current.notes + '\n' + text
        : text
      const updated = await s.update(args.id, { notes })
      return { updated: updated !== undefined }
    },
  }))

  // ── vault_attach: attach a file to an entry ────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_attach',
    description: 'Attach a file to an entry (1Password/KeePass-style). The file is read from disk '
      + 'and stored base64 inside the encrypted entry, so attachments are encrypted at rest. Useful '
      + 'for private keys, certificates, config files, recovery codes, etc. Attachments are exposed '
      + 'to search (names only). Returns the attachment name and size.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
      path: { type: 'string', required: true, description: 'Absolute path of the file to attach.' },
      name: { type: 'string', description: 'Attachment name (default: the file base name).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { attached: { type: 'boolean', required: true }, name: { type: 'string' }, size: { type: 'integer' }, attachments: { type: 'integer' } } }, render: (_a, v) => [{ type: 'text', text: v.attached ? `attached "${v.name}" (${v.size} bytes, ${v.attachments} total)` : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_attach')
      const s = await guardStore()
      const entry = s.get(args.id)
      if (!entry) return { attached: false }
      const data = await readFile(args.path)
      const name = typeof args.name === 'string' && args.name.trim().length > 0
        ? args.name.trim() : basename(args.path)
      const attachments = { ...(entry.attachments ?? {}) }
      attachments[name] = {
        data: data.toString('base64'),
        name,
        size: data.length,
      }
      await s.update(args.id, { attachments })
      emitAudit('write', 'vault_attach', entry.id, entry.title)
      return { attached: true, name, size: data.length, attachments: Object.keys(attachments).length }
    },
  }))

  // ── vault_attachments: list an entry's attachments ─────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_attachments',
    description: 'List the files attached to an entry (names and sizes only — never the content). '
      + 'Use vault_attachment with the entry id and a name to read the content, or vault_detach to '
      + 'remove one.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { attachments: { type: 'array', required: true, items: { type: 'json' } }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `${v.count} attachment(s)` }] },
    async execute(args) {
      const s = await guardStore()
      const entry = s.get(args.id)
      const list = entry?.attachments === undefined ? [] : Object.entries(entry.attachments).map(([name, a]) => ({ name, size: a.size, ...(a.mime !== undefined ? { mime: a.mime } : {}) }))
      return { attachments: list as unknown as JsonValue[], count: list.length }
    },
  }))

  // ── vault_attachment: read an attachment's content ─────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_attachment',
    description: 'Read the content of one attached file: returns the base64 data, decoded bytes '
      + 'count, and MIME type. Prefer decoding the base64 to the target format (e.g. write to a '
      + 'file) — the content is sensitive, handle it as a secret.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
      name: { type: 'string', required: true, description: 'Attachment name (see vault_attachments).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { found: { type: 'boolean', required: true }, data: { type: 'string' }, size: { type: 'integer' }, mime: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.found ? `attachment (${v.size} bytes, base64 below)` : 'attachment not found' }] },
    async execute(args) {
      const s = await guardStore()
      const entry = s.get(args.id)
      const att = entry?.attachments?.[args.name]
      if (att === undefined) return { found: false }
      return {
        found: true,
        data: att.data,
        size: att.size,
        ...(att.mime !== undefined ? { mime: att.mime } : {}),
      }
    },
  }))

  // ── vault_detach: remove an attachment ─────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_detach',
    description: 'Remove one attached file from an entry.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
      name: { type: 'string', required: true, description: 'Attachment name to remove.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { detached: { type: 'boolean', required: true }, remaining: { type: 'integer' } } }, render: (_a, v) => [{ type: 'text', text: v.detached ? `detached (${v.remaining} remaining)` : 'attachment not found' }] },
    async execute(args) {
      assertWritable('vault_detach')
      const s = await guardStore()
      const entry = s.get(args.id)
      if (!entry || entry.attachments?.[args.name] === undefined) return { detached: false }
      const attachments = { ...entry.attachments }
      delete attachments[args.name]
      await s.update(args.id, { attachments })
      emitAudit('write', 'vault_detach', entry.id, entry.title)
      return { detached: true, remaining: Object.keys(attachments).length }
    },
  }))

  // ── vault_recovery_code: generate a one-time recovery code ────────────────
  ctx.tools.register(defineTool({
    name: 'vault_recovery_code',
    description: 'Generate a one-time vault recovery code (1Password/Bitwarden recovery-code style): '
      + 'a high-entropy code shown ONCE and printed to the caller — store it somewhere safe (e.g. a '
      + 'printed backup). Only its SHA-256 hash is persisted, never the plaintext. Use '
      + 'vault_verify_recovery to prove possession of the code later (e.g. when the master password '
      + 'is lost) and vault_recovery_status to check whether one is set. Re-running regenerates '
      + '(the old code becomes invalid).',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { code: { type: 'string', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: `recovery code (show once, store it safely): ${v.code}\n${v.note}` }] },
    async execute() {
      assertWritable('vault_recovery_code')
      await guardStore()
      // 32 chars from a URL-safe alphabet (~192 bits of entropy).
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
      const bytes = randomBytes(32)
      let code = ''
      for (let i = 0; i < 32; i++) code += alphabet[bytes[i]! % alphabet.length]
      const hash = createHash('sha256').update(code).digest('hex')
      const meta = await readMeta(config)
      meta.recoveryHash = hash
      meta.recoveryIssuedAt = Date.now()
      await writeMeta(config, meta)
      return {
        code,
        note: 'Shown only once. Only its hash is stored — if you lose it, generate a new one.',
      }
    },
  }))

  // ── vault_verify_recovery: prove possession of the recovery code ──────────
  ctx.tools.register(defineTool({
    name: 'vault_verify_recovery',
    description: 'Verify a recovery code against the stored hash (proves you hold the code issued by '
      + 'vault_recovery_code — e.g. as a second factor when the master password is unavailable). '
      + 'Returns whether it matches; the code itself is never stored or returned.',
    parameters: { code: { type: 'string', required: true, description: 'The recovery code to verify.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { verified: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.verified ? 'recovery code verified' : 'recovery code does not match' }] },
    async execute(args) {
      const meta = await readMeta(config)
      if (meta.recoveryHash === undefined) return { verified: false }
      const hash = createHash('sha256').update(args.code.trim()).digest('hex')
      return { verified: hash === meta.recoveryHash }
    },
  }))

  // ── vault_recovery_status: whether a recovery code is set ─────────────────
  ctx.tools.register(defineTool({
    name: 'vault_recovery_status',
    description: 'Report whether a one-time recovery code has been issued (vault_recovery_code) and '
      + 'when. Never returns the code itself.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { set: { type: 'boolean', required: true }, issuedAt: { type: 'integer' } } }, render: (_a, v) => [{ type: 'text', text: v.set ? `recovery code set (${new Date(v.issuedAt ?? 0).toLocaleString()})` : 'no recovery code set' }] },
    async execute() {
      const meta = await readMeta(config)
      return {
        set: meta.recoveryHash !== undefined,
        ...(meta.recoveryIssuedAt !== undefined ? { issuedAt: meta.recoveryIssuedAt } : {}),
      }
    },
  }))

  // ── vault_expiry: set/update an entry's expiry ──────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_expiry',
    description: 'Set or update the expiry (epoch millis) of an entry; pass expiresAt as 0 to clear it. '
      + 'vault_rotation reports entries whose expiry is near or past.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
      expiresAt: { type: 'integer', description: 'Expiry epoch millis, or 0 to clear. Provide exactly one of expiresAt or expiresInDays.' },
      expiresInDays: { type: 'integer', description: 'Set expiry N days from now (convenience). Provide exactly one of expiresAt or expiresInDays.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { updated: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.updated ? 'expiry updated' : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_expiry')
      const s = await guardStore()
      if (args.expiresAt === undefined && args.expiresInDays === undefined) {
        throw new Error('vault_expiry: provide expiresAt or expiresInDays')
      }
      if (args.expiresAt !== undefined && args.expiresInDays !== undefined) {
        throw new Error('vault_expiry: provide exactly one of expiresAt or expiresInDays')
      }
      const expiresAt = args.expiresInDays !== undefined
        ? Date.now() + args.expiresInDays * 86_400_000
        : args.expiresAt!
      const updated = await s.update(args.id, { expiresAt })
      return { updated: updated !== undefined }
    },
  }))

  // ── vault_changes: recent activity (created/updated/deleted) ────────────────
  ctx.tools.register(defineTool({
    name: 'vault_changes',
    description: 'List vault activity within a time window (default 24h): entries created, updated, or '
      + 'soft-deleted, newest first. No secrets — a lightweight audit view.',
    parameters: {
      hours: { type: 'number', description: 'Look-back window in hours (default 24).' },
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'], description: 'Only report changes for entries of this kind.' },
      limit: { type: 'number', description: 'Max events (default 50, 1–500).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { changes: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.changes) }] },
    async execute(args) {
      const s = await guardStore()
      const hours = args.hours === undefined ? 24 : args.hours
      if (!Number.isFinite(hours) || hours <= 0 || hours > 8760) {
        throw new Error('vault_changes: hours must be a positive number ≤ 8760')
      }
      const changes = s.changes(hours * 60 * 60 * 1000)
      const filtered = args.kind === undefined
        ? changes
        : changes.filter(c => (c.kind ?? 'login') === args.kind)
      const limit = args.limit === undefined ? 50 : args.limit
      if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
        throw new Error('vault_changes: limit must be an integer 1–500')
      }
      return { changes: filtered.slice(0, limit) }
    },
  }))

  // ── vault_find: fuzzy, normalization-agnostic lookup ─────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_find',
    description: 'Fuzzy-find entries: matches are case-insensitive and ignore punctuation/whitespace '
      + '(e.g. "db.internal", "dbinternal", "DB Internal" all match host "db.internal"). Returns '
      + 'secret-free summaries, best matches first.',
    parameters: {
      text: { type: 'string', required: true, description: 'Free text to match across title/username/email/host/url/tags.' },
      limit: { type: 'number', description: 'Max results (default 10).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { results: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.results) }] },
    async execute(args) {
      const s = await guardStore()
      const needle = args.text.toLowerCase().replace(/[^a-z0-9]+/g, '')
      if (needle.length === 0) return { results: [] }
      const scored: Array<{ entry: VaultEntrySummary; score: number }> = []
      for (const entry of s.list()) {
        const hay = [entry.title, entry.username, entry.email, entry.host, entry.url, ...(entry.tags ?? [])]
          .filter(Boolean).join(' ').toLowerCase().replace(/[^a-z0-9]+/g, '')
        if (hay.includes(needle)) {
          // Score: exact title match > title contains > field contains.
          const titleNorm = (entry.title ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '')
          const score = titleNorm === needle ? 0 : titleNorm.includes(needle) ? 1 : 2
          scored.push({ entry, score })
        }
      }
      scored.sort((a, b) => a.score - b.score)
      return { results: scored.slice(0, validateLimit(args.limit, 'vault_find')).map(x => ({ ...(toSummaryJson(x.entry) as Record<string, unknown>), score: x.score })) }
    },
  }))

  // ── vault_verify: integrity/completeness check of one entry ─────────────────
  ctx.tools.register(defineTool({
    name: 'vault_verify',
    description: 'Verify one entry (or every entry with all: true) for completeness and plausibility: '
      + 'required fields per kind, valid port/expiry, and that required secrets are present. No secrets in the report.',
    parameters: {
      id: { type: 'string', description: 'Entry id to verify (omit when all is true).' },
      all: { type: 'boolean', description: 'Verify every active entry and return a per-entry audit.' },
      limit: { type: 'integer', description: 'Max entries audited with all: true (default 500, 1–5000).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, issues: { type: 'array', required: true, items: { type: 'string' } }, audited: { type: 'integer' }, withIssues: { type: 'integer' }, perEntry: { type: 'array', items: { type: 'json' } }, summary: { type: 'json' }, highSensitivity: { type: 'integer' } } }, render: (_a, v) => [{ type: 'text', text: v.audited !== undefined ? `audited ${v.audited} entries, ${v.withIssues} with issues` : (v.ok ? 'entry looks complete' : `issues: ${v.issues.join('; ')}`) }] },
    async execute(args) {
      const s = await guardStore()
      if (args.all === true) {
        const limit = args.limit === undefined ? 500 : args.limit
        if (!Number.isInteger(limit) || limit < 1 || limit > 5000) {
          throw new Error('vault_verify: limit must be an integer 1–5000')
        }
        const perEntry: Array<{ id: string; title: string; ok: boolean; issues: string[] }> = []
        for (const e of s.list().slice(0, limit)) {
          const issues: string[] = []
          if (e.port !== undefined && !/^\d{1,5}$/.test(String(e.port))) issues.push('port is not numeric')
          if (e.port !== undefined && /^\d{1,5}$/.test(String(e.port)) && Number(e.port) > 65535) issues.push('port out of range')
          if (e.expiresAt !== undefined && e.expiresAt < Date.now()) issues.push('expired')
          const kind = e.kind ?? 'login'
          if (e.password !== undefined && (kind === 'login' || kind === 'ssh') && e.otpSecret === undefined) {
            issues.push('no 2FA (add a TOTP secret)')
          }
          switch (kind) {
            case 'ssh':
              if (!e.host) issues.push('ssh: missing host')
              if (!e.password && !e.privateKey) issues.push('ssh: missing password/privateKey')
              break
            case 'api-key':
              if (!e.apiKey && !e.secret) issues.push('api-key: missing apiKey/secret')
              break
            case 'oauth':
              if (!e.accessToken) issues.push('oauth: missing accessToken')
              break
            case 'cookie':
              if (!Array.isArray(e.cookies) || e.cookies.length === 0) issues.push('cookie: no cookies stored')
              else if (e.cookies.some(c => c.value.length === 0)) issues.push('cookie: empty cookie value')
              break
            case 'card':
              if (!e.cardNumber) issues.push('card: missing card number')
              if (!e.cardExpiry) issues.push('card: missing expiry')
              if (!e.cardCvv) issues.push('card: missing CVV')
              if (e.cardNumber !== undefined && !/^[0-9]{13,19}$/.test(e.cardNumber.replace(/[\s-]/g, ''))) issues.push('card: card number does not look valid')
              break
          }
          perEntry.push({ id: e.id, title: e.title, ok: issues.length === 0, issues })
        }
        const withIssues = perEntry.filter(p => !p.ok).length
        const summary: Record<string, number> = {}
        for (const p of perEntry) {
          for (const issue of p.issues) summary[issue] = (summary[issue] ?? 0) + 1
        }
        const highSensitivity = s.list().filter(e => e.sensitivity === 'high').length
        return { ok: withIssues === 0, issues: [], audited: perEntry.length, withIssues, perEntry, summary, highSensitivity }
      }
      if (args.id === undefined) throw new Error('vault_verify: provide id or set all: true')
      const entry = s.get(args.id)
      if (!entry) return { ok: false, issues: ['entry not found'] }
      const issues: string[] = []
      if (!entry.title) issues.push('missing title')
      if (entry.port !== undefined && !/^\d{1,5}$/.test(String(entry.port))) issues.push('port is not numeric')
      if (entry.port !== undefined && /^\d{1,5}$/.test(String(entry.port)) && Number(entry.port) > 65535) issues.push('port out of range')
      if (entry.expiresAt !== undefined && entry.expiresAt < Date.now()) issues.push('expired')
      const singleKind = entry.kind ?? 'login'
      if (entry.password !== undefined && (singleKind === 'login' || singleKind === 'ssh') && entry.otpSecret === undefined) {
        issues.push('no 2FA (add a TOTP secret)')
      }
      switch (singleKind) {
        case 'ssh':
          if (!entry.host) issues.push('ssh: missing host')
          if (!entry.password && !entry.privateKey) issues.push('ssh: missing password/privateKey')
          break
        case 'api-key':
          if (!entry.apiKey && !entry.secret) issues.push('api-key: missing apiKey/secret')
          break
        case 'oauth':
          if (!entry.accessToken) issues.push('oauth: missing accessToken')
          break
        case 'cookie':
          if (!Array.isArray(entry.cookies) || entry.cookies.length === 0) issues.push('cookie: no cookies stored')
          else if (entry.cookies.some(c => c.value.length === 0)) issues.push('cookie: empty cookie value')
          break
        case 'card':
          if (!entry.cardNumber) issues.push('card: missing card number')
          if (!entry.cardExpiry) issues.push('card: missing expiry')
          if (!entry.cardCvv) issues.push('card: missing CVV')
          if (entry.cardNumber !== undefined && !/^[0-9]{13,19}$/.test(entry.cardNumber.replace(/[\s-]/g, ''))) issues.push('card: card number does not look valid')
          break
      }
      return { ok: issues.length === 0, issues }
    },
  }))

  // ── vault_mask: redact likely secrets in free text ──────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_mask',
    description: 'Redact likely credentials in arbitrary text (API keys, tokens, passwords, private keys) '
      + 'so it can be logged or quoted safely. Returns the masked text and a count of redactions.',
    parameters: { text: { type: 'string', required: true, description: 'Text to mask.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { masked: { type: 'string', required: true }, redacted: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.masked }] },
    async execute(args) {
      let count = 0
      const masked = args.text
        .replace(/(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}/g, () => { count++; return '[REDACTED:TOKEN]' })
        .replace(/(npm|npms)_[A-Za-z0-9]{20,}/g, () => { count++; return '[REDACTED:NPM]' })
        .replace(/(sk|pk|rk|ak)_[A-Za-z0-9]{20,}/g, () => { count++; return '[REDACTED:KEY]' })
        .replace(/(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)/g, () => { count++; return '[REDACTED:PRIVATE-KEY]' })
        .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, (m, p1: string) => { count++; return p1 + '[REDACTED:BEARER]' })
      return { masked, redacted: count }
    },
  }))

  // ── vault_history: in-process mutation audit trail ──────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_history',
    description: 'Show recent mutations to the vault (add/update/delete/restore/purge) within this '
      + 'process, newest first. No secrets — an audit trail for "what changed recently".',
    parameters: {
      limit: { type: 'number', description: 'Max entries (default 20).' },
      since: { type: 'integer', description: 'Only events after this epoch millis (optional).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { events: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.events) }] },
    async execute(args) {
      const s = await guardStore()
      const limit = validateLimit(args.limit, 'vault_history')
      let events = s.getHistory()
      if (args.since !== undefined) events = events.filter(e => e.at >= args.since!)
      return { events: events.slice(0, limit) as unknown as JsonValue[] }
    },
  }))

  // ── vault_recent: most recently touched entries ─────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_recent',
    description: 'List the most recently created or updated entries (newest first), as secret-free '
      + 'summaries. Useful to pick up where you left off or surface what changed.',
    parameters: {
      limit: { type: 'number', description: 'Max results (default 10).' },
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'], description: 'Only entries of this kind.' },
      days: { type: 'integer', description: 'Only entries updated within the last N days (1–365).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { entries: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.entries) }] },
    async execute(args) {
      const s = await guardStore()
      let entries = s.recent(validateLimit(args.limit, 'vault_recent'))
      if (args.days !== undefined) {
        if (!Number.isInteger(args.days) || args.days < 1 || args.days > 365) {
          throw new Error('vault_recent: days must be an integer 1–365')
        }
        const since = Date.now() - args.days * 86_400_000
        entries = entries.filter(e => (e.updatedAt ?? 0) >= since)
      }
      const filtered = args.kind === undefined ? entries : entries.filter(e => (e.kind ?? 'login') === args.kind)
      return { entries: filtered }
    },
  }))

  // ── vault_stats: vault overview statistics ───────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_stats',
    description: 'Vault overview: total entries, counts by kind, entries with TOTP, high-sensitivity '
      + 'entries, and expired credentials. No secrets returned. Useful for a quick health glance.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { total: { type: 'integer', required: true }, byKind: { type: 'json', required: true }, byTag: { type: 'json', required: true }, withTotp: { type: 'integer', required: true }, withPrivateKey: { type: 'integer', required: true }, highSensitivity: { type: 'integer', required: true }, expired: { type: 'integer', required: true }, recent7d: { type: 'integer', required: true }, trashCount: { type: 'integer', required: true }, duplicates: { type: 'integer', required: true }, score: { type: 'integer', required: true }, verdict: { type: 'string', required: true }, favoriteCount: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `vault: ${v.total} entries, score ${v.score}/${v.verdict}, ${v.trashCount} trashed, ${v.duplicates} dup groups (${JSON.stringify(v.byKind)})` }] },
    async execute() {
      const s = await guardStore()
      const stats = s.stats()
      const h = s.health()
      return { ...stats, score: h.score, verdict: h.verdict }
    },
  }))

  // ── vault_pin / vault_unpin: favorites ──────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_pin',
    description: 'Pin (favorite) an entry so it ranks first in search and list. Pinned entries show '
      + 'a star in the Settings UI.',
    parameters: { id: { type: 'string', required: true, description: 'Entry id to pin.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { pinned: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.pinned ? 'entry pinned' : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_pin')
      const s = await guardStore()
      const updated = await s.setFavorite(args.id, true)
      return { pinned: updated !== undefined }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_unpin',
    description: 'Unpin an entry (remove its favorite flag).',
    parameters: { id: { type: 'string', required: true, description: 'Entry id to unpin.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { unpinned: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.unpinned ? 'entry unpinned' : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_unpin')
      const s = await guardStore()
      const updated = await s.setFavorite(args.id, false)
      return { unpinned: updated !== undefined }
    },
  }))

  // ── vault_report: human-readable inventory (no secrets) ─────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_report',
    description: 'Generate a human-readable inventory of the vault: title, kind, username/email, host, '
      + 'expiry and pin status per entry — NEVER the secret values. Useful for a printable overview.',
    parameters: {},
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { report: { type: 'string', required: true } } },
      render: (_a, v) => [{ type: 'text', text: v.report }],
    },
    async execute() {
      const s = await guardStore()
      const now = Date.now()
      const lines: string[] = []
      const byKind: Record<string, number> = {}
      let withTotp = 0
      let withPrivateKey = 0
      let highSensitivity = 0
      let expired = 0
      let rotationDue = 0
      for (const e of s.list()) {
        const kind = e.kind ?? 'login'
        byKind[kind] = (byKind[kind] ?? 0) + 1
        if (e.otpSecret !== undefined) withTotp++
        if (e.privateKey !== undefined) withPrivateKey++
        if (e.sensitivity === 'high') highSensitivity++
        if (e.expiresAt !== undefined && e.expiresAt < now) expired++
        if (e.rotationDays !== undefined && e.rotationDays > 0 && (e.updatedAt ?? e.createdAt) + e.rotationDays * 86_400_000 < now) rotationDue++
        const parts = [
          e.favorite ? '★' : '·',
          `[${kind}]`,
          e.title,
          e.username ?? e.email ?? '',
          e.host !== undefined ? `@${e.host}${e.port !== undefined ? `:${e.port}` : ''}` : '',
          e.expiresAt !== undefined ? `exp ${new Date(e.expiresAt).toISOString().slice(0, 10)}` : '',
          e.rotationDays !== undefined && e.rotationDays > 0 ? `rot ${e.rotationDays}d` : '',
          e.otpSecret !== undefined ? 'totp' : '',
          e.sensitivity === 'high' ? 'high' : '',
        ].filter(Boolean)
        lines.push(parts.join(' '))
      }
      const statsLine = `total ${s.list().length} | byKind ${JSON.stringify(byKind)} | totp ${withTotp} | privateKey ${withPrivateKey} | high ${highSensitivity} | expired ${expired} | rotationDue ${rotationDue}`
      const header = `dsh-vault inventory\n${'-'.repeat(40)}`
      const footer = `${'-'.repeat(40)}\n${statsLine}`
      return { report: header + '\n' + lines.join('\n') + '\n' + footer }
    },
  }))

  // ── vault_tags: tag inventory with counts ────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_tags',
    description: 'List every tag used across entries with the number of entries per tag. No secrets.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { tags: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.tags) }] },
    async execute() {
      const s = await guardStore()
      const counts = new Map<string, number>()
      for (const e of s.list()) {
        for (const tag of e.tags ?? []) counts.set(tag, (counts.get(tag) ?? 0) + 1)
      }
      const tags = [...counts.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
      return { tags }
    },
  }))

  // ── vault_apply_tags: bulk tag management across matching entries ──────────
  ctx.tools.register(defineTool({
    name: 'vault_apply_tags',
    description: 'Bulk add, remove, or replace tags on every entry matching a search query. '
      + 'Give at least one of add/remove/replace. Matches titles, usernames, emails, hosts, urls, notes, '
      + 'tags and custom-field values (case-insensitive); empty query = every active entry. No secrets.',
    parameters: {
      query: { type: 'string', description: 'Search text selecting which entries to update. Omit to update all active entries.' },
      add: { type: 'array', items: { type: 'string' }, description: 'Tags to add (union).' },
      remove: { type: 'array', items: { type: 'string' }, description: 'Tags to remove.' },
      replace: { type: 'array', items: { type: 'string' }, description: 'Replace the whole tag list with these tags.' },
      dryRun: { type: 'boolean', description: 'Only report how many entries would change, without writing.' },
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'], description: 'Only apply to entries of this kind.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { matched: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, entries: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: `matched ${v.matched}, updated ${v.updated} entries` }] },
    async execute(args) {
      assertWritable('vault_apply_tags')
      const add = normalizeTags(args.add ?? [])
      const remove = normalizeTags(args.remove ?? [])
      const replace = args.replace !== undefined ? normalizeTags(args.replace) : undefined
      if (add.length === 0 && remove.length === 0 && replace === undefined) {
        throw new Error('vault_apply_tags: provide at least one of add, remove, or replace')
      }
      const s = await guardStore()
      const all = s.list()
      const query = typeof args.query === 'string' ? args.query.trim() : ''
      const kindFiltered = args.kind === undefined ? all : all.filter(e => (e.kind ?? 'login') === args.kind)
      const matched = query.length === 0
        ? kindFiltered
        : kindFiltered.filter(e => {
            const haystack = [e.title, e.username, e.email, e.phone, e.host, e.url, ...(e.tags ?? []), ...Object.values(e.fields ?? {})]
              .filter((v): v is string => v !== undefined)
              .join('\n').toLowerCase()
            return haystack.includes(query.toLowerCase())
          })
      const changed: Array<{ id: string; title: string; tags: string[] }> = []
      let updatedCount = 0
      for (const e of matched) {
        const current = [...(e.tags ?? [])]
        let next: string[]
        if (replace !== undefined) next = [...replace]
        else {
          next = [...current]
          for (const t of add) if (!next.includes(t)) next.push(t)
          next = next.filter(t => !remove.includes(t))
        }
        if (next.length === current.length && next.every((t, i) => t === current[i])) continue
        updatedCount++
        if (!args.dryRun) {
          await s.update(e.id, { tags: next })
          changed.push({ id: e.id, title: e.title, tags: next })
        }
      }
      return { matched: matched.length, updated: updatedCount, entries: changed }
    },
  }))

  // ── vault_bulk_delete: soft-delete entries matching a filter ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_bulk_delete',
    description: 'Soft-delete (move to trash) the entries matching a filter: a search query, a kind, '
      + 'a tag, or an explicit list of ids. Pass confirm: true to actually delete — otherwise it only '
      + 'reports how many would be deleted. Trashed entries can be restored with vault_restore / '
      + 'vault_undelete_all. Returns how many were moved to trash.',
    parameters: {
      query: { type: 'string', description: 'Search text selecting entries (title/username/email/host/url/notes/tags). Omit to match by kind/tag/ids.' },
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'], description: 'Only delete entries of this kind.' },
      tag: { type: 'string', description: 'Only delete entries carrying this tag.' },
      ids: { type: 'array', items: { type: 'string' }, description: 'Explicit entry ids to delete (ignores query/kind/tag when provided).' },
      confirm: { type: 'boolean', description: 'Must be true to move entries to trash (default false = dry run).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { matched: { type: 'integer', required: true }, deleted: { type: 'integer', required: true }, note: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.note }] },
    async execute(args) {
      const s = await guardStore()
      const all = s.list()
      let targets: VaultEntry[]
      if (Array.isArray(args.ids) && args.ids.length > 0) {
        const idSet = new Set(args.ids)
        targets = all.filter(e => idSet.has(e.id))
      } else {
        const query = typeof args.query === 'string' ? args.query.trim() : ''
        let filtered = all
        if (args.kind !== undefined) filtered = filtered.filter(e => (e.kind ?? 'login') === args.kind)
        if (typeof args.tag === 'string' && args.tag.trim().length > 0) {
          const tag = args.tag.trim()
          filtered = filtered.filter(e => (e.tags ?? []).includes(tag))
        }
        if (query.length > 0) {
          filtered = filtered.filter(e => {
            const haystack = [e.title, e.username, e.email, e.phone, e.host, e.url, ...(e.tags ?? [])]
              .filter((v): v is string => v !== undefined)
              .join('\n').toLowerCase()
            return haystack.includes(query.toLowerCase())
          })
        }
        targets = filtered
      }
      if (args.confirm !== true) {
        return { matched: targets.length, deleted: 0, note: `bulk delete dry run: ${targets.length} entry/ies would be moved to trash — pass confirm: true to proceed` }
      }
      assertWritable('vault_bulk_delete')
      let deleted = 0
      for (const e of targets) {
        if (await s.delete(e.id)) deleted++
      }
      return { matched: targets.length, deleted, note: `bulk delete: ${deleted} entry/ies moved to trash (${targets.length} matched)` }
    },
  }))

  // ── vault_generate_username: random username/email suggestion ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_generate_username',
    description: 'Generate a random username or anonymous email suggestion (e.g. "orca_4921" or '
      + '"plover7391@example.com") for accounts that let you pick a name. Uses crypto randomness.',
    parameters: {
      style: { type: 'string', enum: ['username', 'email'], description: 'username (default) or email.' },
      words: { type: 'number', description: 'Number of name parts (default 2).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { value: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.value }] },
    async execute(args) {
      const words = args.words === undefined ? 2 : args.words
      if (!Number.isInteger(words) || words < 1 || words > 4) {
        throw new Error('vault_generate_username: words must be an integer 1–4')
      }
      const style = args.style ?? 'username'
      const value = generateUsername(words)
      return { value: style === 'email' ? `${value}@example.com` : value }
    },
  }))

  // ── vault_rotate_password: generate + store a new password ──────────────────
  ctx.tools.register(defineTool({
    name: 'vault_rotate_password',
    description: 'Generate a new strong password, store it on the entry, and return the new value '
      + 'for the caller to hand to the target service. A one-call convenience for vault_generate_password + vault_update.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
      length: { type: 'integer', description: 'New password length (default 20).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { rotated: { type: 'boolean', required: true }, password: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.rotated ? 'password rotated (new value returned)' : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_rotate_password')
      const s = await guardStore()
      const entry = s.get(args.id)
      if (!entry) return { rotated: false, password: '' }
      const password = generatePassword({ length: args.length ?? 20 })
      await s.update(args.id, { password })
      emitAudit('write', 'vault_rotate_password', entry.id, entry.title)
      return { rotated: true, password }
    },
  }))

  // ── vault_password_history: list an entry's previous passwords ────────────
  ctx.tools.register(defineTool({
    name: 'vault_password_history',
    description: 'List the password history of an entry (1Password/Bitwarden-style): previous '
      + 'passwords with the time each was superseded, newest first, capped at 10. The current '
      + 'password is NOT included (use vault_get for that). Use vault_password_rollback to restore '
      + 'an old password.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { history: { type: 'array', required: true, items: { type: 'json' } }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `${v.count} previous password(s)` }] },
    async execute(args) {
      const s = await guardStore()
      const history = s.passwordHistoryOf(args.id)
      return { history: history as unknown as JsonValue[], count: history.length }
    },
  }))

  // ── vault_password_rollback: restore a previous password ──────────────────
  ctx.tools.register(defineTool({
    name: 'vault_password_rollback',
    description: 'Roll an entry\'s password back to a stored history entry (see vault_password_history '
      + 'for the `at` values). The current password is pushed onto the history first, so the rollback '
      + 'itself is reversible. Returns the restored password.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
      at: { type: 'integer', required: true, description: 'Epoch millis of the history entry to restore (from vault_password_history).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { rolledBack: { type: 'boolean', required: true }, password: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.rolledBack ? 'password rolled back' : 'history entry not found' }] },
    async execute(args) {
      assertWritable('vault_password_rollback')
      const s = await guardStore()
      const entry = s.get(args.id)
      if (!entry) return { rolledBack: false }
      const updated = await s.rollbackPassword(args.id, args.at)
      if (updated === undefined || updated.password === undefined) return { rolledBack: false }
      emitAudit('write', 'vault_password_rollback', entry.id, entry.title)
      return { rolledBack: true, password: updated.password }
    },
  }))

  // ── vault_duplicates: exact-title+kind duplicates ───────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_duplicates',
    description: 'Find duplicate entries: same title+kind (mode: title), same username+secret (mode: '
      + 'content), or both. Returns groups of summaries (no secrets) so the caller can merge or delete them.',
    parameters: {
      mode: { type: 'string', enum: ['title', 'content', 'both'], description: 'both (default): union of title and content groups; title: same title+kind only; content: same username+secret only.' },
      limit: { type: 'integer', description: 'Max groups to return (default 50, 1–500).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { groups: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: `found ${(v.groups as unknown[]).length} duplicate groups` }] },
    async execute(args) {
      const s = await guardStore()
      const byKey = new Map<string, VaultEntrySummary[]>()
      const byContent = new Map<string, VaultEntrySummary[]>()
      for (const e of s.list()) {
        const key = `${e.title.toLowerCase()}::${e.kind ?? 'login'}`
        const list = byKey.get(key) ?? []
        list.push(toSummary(e))
        byKey.set(key, list)
        // Content-based duplicates: same username+password hash → same credential.
        const secret = e.password ?? e.apiKey ?? e.secret ?? e.accessToken
        if (secret !== undefined) {
          const contentKey = `${(e.username ?? e.email ?? '').toLowerCase()}::${secret}`
          const cl = byContent.get(contentKey) ?? []
          cl.push(toSummary(e))
          byContent.set(contentKey, cl)
        }
      }
      const mode = args.mode ?? 'both'
      const limit = args.limit === undefined ? 50 : args.limit
      if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
        throw new Error('vault_duplicates: limit must be an integer 1–500')
      }
      const sortGroup = (g: VaultEntrySummary[]): VaultEntrySummary[] => [...g].sort((a, b) => a.title.localeCompare(b.title))
      const titleGroups = [...byKey.values()].filter(g => g.length > 1).map(sortGroup)
      const contentGroups = [...byContent.values()].filter(g => g.length > 1).map(sortGroup)
      if (mode === 'title') return { groups: titleGroups.slice(0, limit) }
      if (mode === 'content') return { groups: contentGroups.slice(0, limit) }
      return { groups: [...titleGroups, ...contentGroups].slice(0, limit) }
    },
  }))

  // ── vault_export_totp: list all TOTP entries with their labels ─────────────
  ctx.tools.register(defineTool({
    name: 'vault_export_totp',
    description: 'List every entry that has a TOTP secret, with its title and issuer label. '
      + 'Intended for migrating authenticator apps; never returns the otpSecret itself.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { entries: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.entries) }] },
    async execute() {
      const s = await guardStore()
      const entries: JsonValue[] = s.list()
        .filter(e => e.otpSecret !== undefined)
        .map(e => {
          const row: Record<string, string> = { id: e.id, title: e.title }
          const identity = e.username ?? e.email
          if (identity !== undefined) row.username = identity
          return row as unknown as JsonValue
        })
      return { entries }
    },
  }))

  // ── vault_backup_status: days since last backup ─────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_backup_status',
    description: 'Report how many days have passed since the last backup file was written '
      + '(1Password-style backup reminder; new-style `<vault>-backups-<date>.json` and legacy '
      + '`vault-backup-<epoch>.json` names are both recognized). Returns daysSinceBackup and a suggestion.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { daysSinceBackup: { type: 'integer', required: true }, backups: { type: 'integer', required: true }, lastBackupAt: { type: 'integer' }, oldestBackupAt: { type: 'integer' } } }, render: (_a, v) => [{ type: 'text', text: `last backup ${v.daysSinceBackup} days ago (${v.backups} backup file(s))` }] },
    async execute() {
      const s = await guardStore()
      const dir = dirname(resolveVaultPath(config))
      const stamps: number[] = []
      try {
        const entries = await readdir(dir)
        for (const entry of entries) {
          if (!isBackupFile(entry)) continue
          const key = backupSortKey(entry)
          if (key > 0) stamps.push(key)
        }
      } catch { /* no dir yet */ }
      const last = stamps.length > 0 ? Math.max(...stamps) : 0
      const days = last > 0 ? Math.floor((Date.now() - last) / 86_400_000) : -1
      void s
      const oldest = stamps.length > 0 ? Math.min(...stamps) : 0
      return { daysSinceBackup: days, backups: stamps.length, ...(last > 0 ? { lastBackupAt: last } : {}), ...(oldest > 0 ? { oldestBackupAt: oldest } : {}) }
    },
  }))

  // ── vault_bulk_export: JSON dump of all entries (non-encrypted) ─────────────
  ctx.tools.register(defineTool({
    name: 'vault_bulk_export',
    description: 'Export ALL entries (including secrets) as a JSON file for audit or migration. '
      + 'WARNING: the output file is PLAINTEXT — protect it like a password. For encrypted transfer '
      + 'use vault_export instead.',
    parameters: { path: { type: 'string', required: true, description: 'Absolute output path.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `exported ${v.count} entries to ${v.path} (PLAINTEXT — handle carefully)` }] },
    async execute(args) {
      assertWritable('vault_bulk_export')
      const s = await guardStore()
      const payload = { exportedAt: Date.now(), entries: s.list() }
      await mkdir(dirname(args.path), { recursive: true, mode: 0o700 })
      await writeFile(args.path, JSON.stringify(payload, null, 2), { mode: 0o600 })
      return { path: args.path, count: s.list().length }
    },
  }))

  // ── vault_quick_add: minimal-entry fast add ─────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_quick_add',
    description: 'Add an entry with minimal arguments (title + one secret field). A convenience for '
      + 'capturing a credential fast without the full vault_add field list.',
    parameters: {
      title: { type: 'string', required: true, description: 'Entry title.' },
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'], description: 'Entry kind (default login).' },
      secret: { type: 'string', description: 'The secret value: stored into apiKey for api-key, password for login, secret otherwise.' },
      username: { type: 'string', description: 'Optional username.' },
      tags: { type: 'array', items: { type: 'string' }, description: 'Searchable tags.' },
      notes: { type: 'string', description: 'Optional free-form notes.' },
      favorite: { type: 'boolean', description: 'Pin (favorite) the new entry.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { id: { type: 'string', required: true }, title: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: `added ${v.title} (id: ${v.id})` }] },
    async execute(args) {
      assertWritable('vault_quick_add')
      if (!args.title.trim()) throw new Error('vault_quick_add: title must not be empty')
      if (args.secret === undefined || args.secret.length === 0) {
        throw new Error('vault_quick_add: a secret value is required')
      }
      const s = await guardStore()
      const kind = args.kind ?? 'login'
      const entry = await s.add({
        title: args.title.trim(),
        kind,
        ...(args.username !== undefined ? { username: args.username } : {}),
        ...(args.tags !== undefined ? { tags: normalizeTags(args.tags) } : {}),
        ...(args.notes !== undefined ? { notes: args.notes } : {}),
        ...(args.favorite === true ? { favorite: true } : {}),
        ...(kind === 'api-key' ? { apiKey: args.secret } : kind === 'login' ? { password: args.secret } : { secret: args.secret }),
      })
      emitAudit('write', 'vault_quick_add', entry.id, entry.title)
      return { id: entry.id, title: entry.title }
    },
  }))

  // ── vault_merge: merge duplicate entries ─────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_merge',
    description: 'Merge one entry INTO another (Bitwarden-style duplicate cleanup): non-empty fields of '
      + 'the source fill gaps in the target, then the source is permanently removed (unless keepSource). '
      + 'Returns the merged summary.',
    parameters: {
      fromId: { type: 'string', required: true, description: 'Source entry id (merged into the target, then deleted).' },
      toId: { type: 'string', required: true, description: 'Target entry id (kept, gaps filled).' },
      keepSource: { type: 'boolean', description: 'Keep the source entry after merging (default false = delete it).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { merged: { type: 'boolean', required: true }, entry: { type: 'json' } } }, render: (_a, v) => [{ type: 'text', text: v.merged ? 'entries merged' : 'merge failed (one/both not found or in trash)' }] },
    async execute(args) {
      assertWritable('vault_merge')
      const s = await guardStore()
      const merged = await s.merge(args.fromId, args.toId, { keepSource: args.keepSource === true })
      return merged === undefined ? { merged: false } : { merged: true, entry: toSummaryJson(merged) }
    },
  }))

  // ── vault_copy: copy an entry into another named vault ─────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_copy',
    description: 'Copy an entry (including secrets) into another named vault (same master password). '
      + 'Useful for 1Password-style vault organization. Returns copied or a reason when skipped.',
    parameters: {
      id: { type: 'string', required: true, description: 'Source entry id.' },
      to: { type: 'string', required: true, description: 'Target vault name (e.g. "work").' },
      overwrite: { type: 'boolean', description: 'Update the target entry with the same title (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { copied: { type: 'boolean', required: true }, reason: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.copied ? 'entry copied' : `not copied: ${v.reason ?? '?'}` }] },
    async execute(args) {
      assertWritable('vault_copy')
      const s = await guardStore()
      const entry = s.get(args.id)
      if (!entry) throw new Error('vault_copy: source entry not found')
      const name = args.to.trim()
      if (!/^[a-zA-Z0-9._-]+$/.test(name)) throw new Error('vault_copy: invalid target vault name')
      // Pin the target path explicitly: resolveVaultPath prefers the module-level
      // currentVaultName (set by vault_switch), which would misroute the copy.
      const target = await sharedVaultStore(masterPassword, { name, path: defaultVaultPath(name) })
      const existing = target.list().find(e => e.title === entry.title)
      if (existing && args.overwrite !== true) {
        return { copied: false, reason: `entry "${entry.title}" already exists in vault "${name}" (pass overwrite: true to update)` }
      }
      const patch: VaultEntryPatch = {
        ...(entry.kind !== undefined ? { kind: entry.kind } : {}),
        ...(entry.username !== undefined ? { username: entry.username } : {}),
        ...(entry.email !== undefined ? { email: entry.email } : {}),
        ...(entry.phone !== undefined ? { phone: entry.phone } : {}),
        ...(entry.password !== undefined ? { password: entry.password } : {}),
        ...(entry.host !== undefined ? { host: entry.host } : {}),
        ...(entry.port !== undefined ? { port: entry.port } : {}),
        ...(entry.privateKey !== undefined ? { privateKey: entry.privateKey } : {}),
        ...(entry.apiKey !== undefined ? { apiKey: entry.apiKey } : {}),
        ...(entry.secret !== undefined ? { secret: entry.secret } : {}),
        ...(entry.accessToken !== undefined ? { accessToken: entry.accessToken } : {}),
        ...(entry.refreshToken !== undefined ? { refreshToken: entry.refreshToken } : {}),
        ...(entry.expiresAt !== undefined ? { expiresAt: entry.expiresAt } : {}),
        ...(entry.otpSecret !== undefined ? { otpSecret: entry.otpSecret } : {}),
        ...(entry.cardNumber !== undefined ? { cardNumber: entry.cardNumber } : {}),
        ...(entry.cardExpiry !== undefined ? { cardExpiry: entry.cardExpiry } : {}),
        ...(entry.cardCvv !== undefined ? { cardCvv: entry.cardCvv } : {}),
        ...(entry.cardHolder !== undefined ? { cardHolder: entry.cardHolder } : {}),
        ...(entry.url !== undefined ? { url: entry.url } : {}),
        ...(entry.notes !== undefined ? { notes: entry.notes } : {}),
        ...(entry.tags !== undefined ? { tags: entry.tags } : {}),
        ...(entry.icon !== undefined ? { icon: entry.icon } : {}),
        ...(entry.color !== undefined ? { color: entry.color } : {}),
        ...(entry.sensitivity !== undefined ? { sensitivity: entry.sensitivity } : {}),
        ...(entry.favorite === true ? { favorite: true } : {}),
        ...(entry.rotationDays !== undefined ? { rotationDays: entry.rotationDays } : {}),
        ...(entry.fields !== undefined ? { fields: entry.fields } : {}),
        ...(entry.cookies !== undefined ? { cookies: entry.cookies } : {}),
        ...(entry.attachments !== undefined ? { attachments: entry.attachments } : {}),
      }
      if (existing) {
        await target.update(existing.id, patch)
      } else {
        await target.add({ title: entry.title, ...patch })
      }
      return { copied: true }
    },
  }))

  // ── vault_touch: mark an entry as recently used ─────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_touch',
    description: 'Mark an entry as recently used (update its updatedAt without changing content). '
      + 'Affects vault_recent ordering and the rotation clock.',
    parameters: { id: { type: 'string', required: true, description: 'Entry id.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { touched: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.touched ? 'entry marked as recently used' : 'entry not found' }] },
    async execute(args) {
      const s = await guardStore()
      const updated = await s.markUsed(args.id)
      return { touched: updated !== undefined }
    },
  }))

  // ── vault_export_browser: Chrome/Firefox-compatible CSV export ─────────────
  ctx.tools.register(defineTool({
    name: 'vault_export_browser',
    description: 'Export login entries in the browser password-manager CSV format '
      + '(name,url,username,password) for importing into Chrome/Firefox/Edge. Writes the file and '
      + 'returns its path.',
    parameters: { path: { type: 'string', required: true, description: 'Absolute output .csv path.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `exported ${v.count} logins to ${v.path}` }] },
    async execute(args) {
      const s = await guardStore()
      const rows = [['name', 'url', 'username', 'password']]
      for (const e of s.list()) {
        if (e.password === undefined && e.username === undefined && e.url === undefined) continue
        const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
        rows.push([esc(e.title), esc(e.url), esc(e.username ?? e.email), esc(e.password)])
      }
      await mkdir(dirname(args.path), { recursive: true, mode: 0o700 })
      await writeFile(args.path, rows.map(r => r.join(',')).join('\n') + '\n', { mode: 0o600 })
      return { path: args.path, count: rows.length - 1 }
    },
  }))

  // ── vault_note_secret: store a secret quickly with an auto title ───────────
  ctx.tools.register(defineTool({
    name: 'vault_note_secret',
    description: 'Store a single secret under a generated title (e.g. "secret-2026-08-14-1423") when '
      + 'you just need it saved without choosing a title. Returns the entry id.',
    parameters: {
      secret: { type: 'string', required: true, description: 'The secret value to store.' },
      note: { type: 'string', description: 'Optional context note.' },
      title: { type: 'string', description: 'Optional explicit title; defaults to secret-YYYY-MM-DD-NNNN.' },
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'], description: 'Entry kind (default secret).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { id: { type: 'string', required: true }, title: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: `saved as "${v.title}" (id: ${v.id})` }] },
    async execute(args) {
      assertWritable('vault_note_secret')
      if (!args.secret || args.secret.length === 0) throw new Error('vault_note_secret: secret is required')
      const s = await guardStore()
      const stamp = new Date().toISOString().slice(0, 10)
      const title = typeof args.title === 'string' && args.title.trim().length > 0
        ? args.title.trim()
        : `secret-${stamp}-${Math.floor(Math.random() * 9000 + 1000)}`
      const entry = await s.add({
        title,
        kind: args.kind ?? 'secret',
        secret: args.secret,
        ...(args.note !== undefined ? { notes: args.note } : {}),
      })
      emitAudit('write', 'vault_note_secret', entry.id, entry.title)
      return { id: entry.id, title: entry.title }
    },
  }))

  // ── vault_search_advanced: multi-criteria filter ────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_search_advanced',
    description: 'Search with multiple optional criteria: title substring, username/email substring, '
      + 'kind, tag, created-after/before (epoch millis), and favorite-only. All provided criteria must '
      + 'match (AND). Returns secret-free summaries.',
    parameters: {
      title: { type: 'string', description: 'Title substring.' },
      username: { type: 'string', description: 'Username/email substring.' },
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'], description: 'Entry kind.' },
      tag: { type: 'string', description: 'Exact tag.' },
      createdAfter: { type: 'integer', description: 'Only entries created after this epoch millis.' },
      createdBefore: { type: 'integer', description: 'Only entries created before this epoch millis.' },
      favoriteOnly: { type: 'boolean', description: 'Only pinned (favorite) entries.' },
      limit: { type: 'number', description: 'Max results (default 20).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { results: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.results) }] },
    async execute(args) {
      const s = await guardStore()
      return { results: s.advancedSearch({
        ...(args.title !== undefined ? { title: args.title } : {}),
        ...(args.username !== undefined ? { username: args.username } : {}),
        ...(args.kind !== undefined ? { kind: args.kind } : {}),
        ...(args.tag !== undefined ? { tag: args.tag } : {}),
        ...(args.createdAfter !== undefined ? { createdAfter: args.createdAfter } : {}),
        ...(args.createdBefore !== undefined ? { createdBefore: args.createdBefore } : {}),
        ...(args.favoriteOnly !== undefined ? { favoriteOnly: args.favoriteOnly } : {}),
        limit: validateLimit(args.limit, 'vault_search_advanced'),
      }) as unknown as JsonValue[] }
    },
  }))

  // ── vault_count: lightweight entry count ────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_count',
    description: 'Return the number of active entries (optionally filtered by kind and/or tag). Lightweight '
      + 'alternative to vault_stats when you only need a count.',
    parameters: {
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'], description: 'Count only this kind.' },
      tag: { type: 'string', description: 'Count only entries carrying this tag.' },
      favoriteOnly: { type: 'boolean', description: 'Count only pinned (favorite) entries.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `${v.count} entries` }] },
    async execute(args) {
      const s = await guardStore()
      const kind = args.kind
      const tag = typeof args.tag === 'string' ? args.tag.trim() : ''
      const count = s.list().filter(e => {
        if (kind !== undefined && (e.kind ?? 'login') !== kind) return false
        if (tag.length > 0 && !(e.tags ?? []).includes(tag)) return false
        if (args.favoriteOnly === true && e.favorite !== true) return false
        return true
      }).length
      return { count }
    },
  }))

  // ── vault_set_icon: set icon/color on an entry ──────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_set_icon',
    description: 'Set the UI icon (emoji) and/or accent color on an entry. Quick visual customization.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
      icon: { type: 'string', description: 'Emoji icon, e.g. "🚀".' },
      color: { type: 'string', description: 'Accent color, e.g. "red" or "#ff0000".' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { updated: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.updated ? 'icon updated' : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_set_icon')
      const s = await guardStore()
      const patch: VaultEntryPatch = {}
      if (args.icon !== undefined) patch.icon = args.icon
      if (args.color !== undefined) patch.color = args.color
      if (Object.keys(patch).length === 0) throw new Error('vault_set_icon: provide icon and/or color')
      const updated = await s.update(args.id, patch)
      return { updated: updated !== undefined }
    },
  }))

  // ── vault_describe: human-friendly summary of an entry ─────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_describe',
    description: 'Describe an entry in plain language (kind, identity, host/url, tags, expiry) '
      + 'without revealing secrets. Useful for a quick "what is this entry?" answer.',
    parameters: { id: { type: 'string', required: true, description: 'Entry id.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { description: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.description }] },
    async execute(args) {
      const s = await guardStore()
      const e = s.get(args.id)
      if (!e) return { description: 'entry not found' }
      const bits = [
        `${e.kind ?? 'login'} credential "${e.title}"`,
        e.username !== undefined ? `for ${e.username}` : undefined,
        e.host !== undefined ? `at ${e.host}${e.port !== undefined ? `:${e.port}` : ''}` : undefined,
        e.url !== undefined ? `(${e.url})` : undefined,
        e.tags !== undefined && e.tags.length > 0 ? `tags: ${e.tags.join(', ')}` : undefined,
        e.expiresAt !== undefined ? `expires ${new Date(e.expiresAt).toISOString().slice(0, 10)}` : undefined,
        e.favorite ? 'pinned' : undefined,
        e.sensitivity === 'high' ? 'high-sensitivity' : undefined,
      ].filter(Boolean)
      return { description: bits.join(' ') }
    },
  }))

  // ── vault_migrate_keepass: KeePass-compatible CSV export ────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_migrate_keepass',
    description: 'Export entries in KeePass 2.x import CSV format '
      + '(Group,Title,Username,Password,URL,Notes) for migrating into KeePass. Writes the file.',
    parameters: { path: { type: 'string', required: true, description: 'Absolute output .csv path.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `exported ${v.count} entries to ${v.path}` }] },
    async execute(args) {
      const s = await guardStore()
      const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
      const rows = [['Group', 'Title', 'Username', 'Password', 'URL', 'Notes'].join(',')]
      for (const e of s.list()) {
        const group = e.kind === undefined ? 'General' : String(e.kind)
        rows.push([group, e.title, e.username ?? e.email ?? '', e.password ?? '', e.url ?? '', e.notes ?? ''].map(esc).join(','))
      }
      await mkdir(dirname(args.path), { recursive: true, mode: 0o700 })
      await writeFile(args.path, rows.join('\n') + '\n', { mode: 0o600 })
      return { path: args.path, count: rows.length - 1 }
    },
  }))

  // ── vault_last_modified: most recently updated entries ─────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_last_modified',
    description: 'List entries most recently modified (updatedAt), newest first. Similar to vault_recent '
      + 'but includes updates (not just creation). No secrets.',
    parameters: { limit: { type: 'number', description: 'Max results (default 10).' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { entries: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.entries) }] },
    async execute(args) {
      const s = await guardStore()
      const limit = validateLimit(args.limit, 'vault_last_modified')
      const entries = [...s.list()].sort((a, b) => b.updatedAt - a.updatedAt).slice(0, limit).map(e => toSummary(e))
      return { entries: entries as unknown as JsonValue[] }
    },
  }))

  // ── vault_export_keepass_xml: KeePassXC-compatible XML export ──────────────
  ctx.tools.register(defineTool({
    name: 'vault_export_keepass_xml',
    description: 'Export entries as a KeePassXC-compatible XML document (KeePass 2.x schema). '
      + 'Writes the file and returns its path.',
    parameters: { path: { type: 'string', required: true, description: 'Absolute output .xml path.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `exported ${v.count} entries to ${v.path} — contains plaintext secrets; keep the file protected (mode 600)` }] },
    async execute(args) {
      const s = await guardStore()
      const x = (v: unknown) => String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
      const groups = new Map<string, Array<VaultEntry>>()
      for (const e of s.list()) {
        const g = e.kind ?? 'General'
        const list = groups.get(g) ?? []
        list.push(e)
        groups.set(g, list)
      }
      let xml = `<?xml version="1.0" encoding="utf-8"?>\n<keepass>\n<database>\n<root>\n<group>\n<name>dsh-vault</name>\n`
      for (const [group, entries] of groups) {
        xml += `<group>\n<name>${x(group)}</name>\n`
        for (const e of entries) {
          xml += `<entry>\n<title>${x(e.title)}</title>\n`
          xml += `<username>${x(e.username ?? e.email)}</username>\n`
          xml += `<password>${x(e.password)}</password>\n`
          xml += `<url>${x(e.url)}</url>\n`
          xml += `<notes>${x(e.notes)}</notes>\n`
          if (e.otpSecret !== undefined) {
            const uri = e.otpSecret.startsWith('otpauth://') ? e.otpSecret : `otpauth://totp/${encodeURIComponent(e.title)}?secret=${e.otpSecret}`
            xml += `<otp><name>dsh-vault</name><otpauth>${x(uri)}</otpauth></otp>\n`
          }
          if (e.expiresAt !== undefined) {
            xml += `<Expires>${new Date(e.expiresAt).toISOString().slice(0, 19)}Z</Expires>\n`
          }
          const strings: Array<[string, unknown]> = []
          if (e.host !== undefined) strings.push(['host', e.host])
          if (e.port !== undefined) strings.push(['port', e.port])
          if (e.apiKey !== undefined) strings.push(['apiKey', e.apiKey])
          if (e.secret !== undefined) strings.push(['secret', e.secret])
          if (e.accessToken !== undefined) strings.push(['accessToken', e.accessToken])
          if (e.refreshToken !== undefined) strings.push(['refreshToken', e.refreshToken])
          if (e.privateKey !== undefined) strings.push(['privateKey', e.privateKey])
          if (e.expiresAt !== undefined) strings.push(['expiresAt', e.expiresAt])
          if (e.rotationDays !== undefined) strings.push(['rotationDays', e.rotationDays])
          for (const [k, v] of Object.entries(e.fields ?? {})) strings.push([k, v])
          for (const [k, v] of strings) {
            xml += `<String><Key>${x(k)}</Key><Value>${x(v)}</Value></String>\n`
          }
          xml += `</entry>\n`
        }
        xml += `</group>\n`
      }
      xml += `</group>\n</root>\n</database>\n</keepass>\n`
      await mkdir(dirname(args.path), { recursive: true, mode: 0o700 })
      await writeFile(args.path, xml, { mode: 0o600 })
      return { path: args.path, count: s.list().length }
    },
  }))

  // ── vault_has: check whether a credential exists ────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_has',
    description: 'Quickly check whether the vault contains a credential matching a title/username/host '
      + '(substring, or exact title when exact is set). Returns found + which entry matched. Useful '
      + 'before deciding whether to add.',
    parameters: {
      target: { type: 'string', required: true, description: 'Title, username, or host to look for.' },
      exact: { type: 'boolean', description: 'Require an exact (case-insensitive) title match instead of substring search.' },
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'], description: 'Restrict to this kind.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { found: { type: 'boolean', required: true }, id: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.found ? 'credential found' : 'no matching credential' }] },
    async execute(args) {
      const s = await guardStore()
      const needle = args.target.trim().toLowerCase()
      if (needle.length === 0) return { found: false }
      const match = s.list().find(e => {
        if (args.kind !== undefined && (e.kind ?? 'login') !== args.kind) return false
        if (args.exact === true) return e.title.toLowerCase() === needle
        return e.title.toLowerCase().includes(needle)
          || (e.username ?? '').toLowerCase().includes(needle)
          || (e.host ?? '').toLowerCase().includes(needle)
      })
      return match === undefined ? { found: false } : { found: true, id: match.id }
    },
  }))

  // ── vault_import_browser: import browser-exported CSV ───────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_browser',
    description: 'Import a browser password-manager CSV (name,url,username,password — Chrome/Firefox/'
      + 'Edge export format). Rows without a name are skipped; returns added/skipped counts.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the browser CSV.' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same name instead of skipping (default false).' },
      dryRun: { type: 'boolean', description: 'Preview how many rows would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `imported ${v.added}, updated ${v.updated}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_browser')
      const s = await guardStore()
      const raw = await readFile(args.path, 'utf8')
      const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
      const rows = parseCsv(cleaned)
      if (rows.length === 0) return { added: 0, skipped: 0, updated: 0 }
      // Header may be name,url,username,password or url,name,username,password.
      const header = rows[0]!.map(h => h.trim().toLowerCase())
      let idx = {
        name: header.indexOf('name'),
        url: header.indexOf('url'),
        username: header.indexOf('username'),
        password: header.indexOf('password'),
        otpauth: header.indexOf('otpauth'),
        notes: header.indexOf('notes'),
      }
      // LastPass export order: url,username,password,extra,name,grouping,fav
      if (idx.name < 0 && header.length >= 5 && header[4] === 'name') {
        idx = { name: 4, url: 0, username: 1, password: 2, otpauth: -1, notes: header.indexOf('extra') }
      }
      if (idx.name < 0 || idx.password < 0) return { added: 0, skipped: rows.length - 1, updated: 0 }
      if (args.dryRun === true) {
        const wouldAdd = rows.slice(1).filter(row => {
          const name = (idx.name < row.length ? row[idx.name] : '')?.trim()
          return name && !s.list().some(e => e.title === name)
        }).length
        return { added: 0, skipped: 0, updated: 0, dryRun: true, note: `would add ${wouldAdd} of ${rows.length - 1} rows` }
      }
      let added = 0
      let skipped = 0
      let updated = 0
      const now = Date.now()
      for (let i = 1; i < rows.length; i++) {
        const row = rows[i]!
        const name = (idx.name < row.length ? row[idx.name] : '')?.trim()
        if (!name) { skipped++; continue }
        const entry: VaultEntry = {
          id: randomUUID(),
          title: name,
          createdAt: now,
          updatedAt: now,
          ...(idx.url >= 0 && idx.url < row.length && row[idx.url] ? { url: row[idx.url] } : {}),
          ...(idx.username >= 0 && idx.username < row.length && row[idx.username] ? { username: row[idx.username] } : {}),
          ...(idx.password >= 0 && idx.password < row.length && row[idx.password] ? { password: row[idx.password] } : {}),
          ...(idx.otpauth >= 0 && idx.otpauth < row.length && row[idx.otpauth] ? { otpSecret: row[idx.otpauth] } : {}),
          ...(idx.notes >= 0 && idx.notes < row.length && row[idx.notes] ? { notes: row[idx.notes] } : {}),
        }
        const existing = s.list().find(e => e.title === name)
        if (existing && !args.overwrite) { skipped++; continue }
        if (existing && args.overwrite) {
          const patch: VaultEntryPatch = {}
          if (entry.url !== undefined) patch.url = entry.url
          if (entry.username !== undefined) patch.username = entry.username
          if (entry.password !== undefined) patch.password = entry.password
          if (entry.otpSecret !== undefined) patch.otpSecret = entry.otpSecret
          if (entry.notes !== undefined) patch.notes = entry.notes
          await s.update(existing.id, patch)
          updated++
          continue
        }
        s.insertDirect(entry)
        added++
      }
      await s.persist()
      return { added, skipped, updated }
    },
  }))

  // ── vault_autofill_check: does a target have usable credentials? ────────────
  ctx.tools.register(defineTool({
    name: 'vault_autofill_check',
    description: 'Check whether the vault has a credential usable for a URL/host: returns the best '
      + 'matching entry (username/email only, never the secret) or a not-found verdict. Use before '
      + 'deciding whether to autofill.',
    parameters: { target: { type: 'string', required: true, description: 'URL or host to match.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { found: { type: 'boolean', required: true }, entry: { type: 'json' } } }, render: (_a, v) => [{ type: 'text', text: v.found ? `credentials available for ${(v.entry as { title?: string })?.title ?? 'entry'}` : 'no credentials for this target' }] },
    async execute(args) {
      const s = await guardStore()
      const target = args.target.trim()
      if (target.length === 0) return { found: false }
      let best: VaultEntry | undefined
      let bestScore = 0
      for (const e of s.list()) {
        const hostScore = e.host !== undefined ? matchScore(target, e.host) : 0
        const urlScore = e.url !== undefined ? matchScore(target, e.url) : 0
        const score = Math.max(hostScore, urlScore)
        if (score > bestScore) {
          bestScore = score
          best = e
        }
      }
      if (best === undefined || bestScore === 0) return { found: false }
      const summary: Record<string, string> = { id: best.id, title: best.title, kind: best.kind ?? 'login' }
      const identity = best.username ?? best.email
      if (identity !== undefined) summary.username = identity
      return { found: true, entry: summary as unknown as JsonValue }
    },
  }))

  // ── vault_match_url: find login entries matching a URL ─────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_match_url',
    description: 'Find the login entries whose stored URL/host best match a target URL (Bitwarden/'
      + '1Password-style URL matching): exact host, subdomain, parent domain, and path-prefix are '
      + 'recognized, with www./port normalization. Returns ranked candidates (id/title/username — '
      + 'never the password) plus a 0–100 score so the caller can pick the best or drive automation.',
    parameters: { url: { type: 'string', required: true, description: 'Target URL, e.g. "https://mail.example.com/inbox".' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { matches: { type: 'array', required: true, items: { type: 'json' } }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `${v.count} match(es)` }] },
    async execute(args) {
      const s = await guardStore()
      const target = args.url.trim()
      if (target.length === 0) return { matches: [], count: 0 }
      const scored: Array<{ score: number; entry: VaultEntry }> = []
      for (const e of s.list()) {
        const hostScore = e.host !== undefined ? matchScore(target, e.host) : 0
        const urlScore = e.url !== undefined ? matchScore(target, e.url) : 0
        const score = Math.max(hostScore, urlScore)
        if (score > 0) scored.push({ score, entry: e })
      }
      scored.sort((a, b) => b.score - a.score)
      const matches = scored.map(({ score, entry }) => {
        const m: Record<string, unknown> = { id: entry.id, title: entry.title, kind: entry.kind ?? 'login', score }
        const identity = entry.username ?? entry.email
        if (identity !== undefined) m.username = identity
        return m
      })
      return { matches: matches as unknown as JsonValue[], count: matches.length }
    },
  }))

  // ── vault_backup_now: explicit alias for an immediate backup ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_backup_now',
    description: 'Create an immediate timestamped backup of the vault file (alias of vault_backup). '
      + 'The file is named `<vault>-backups-YYYY-MM-DD_HH-MM-SS.json` so the owning vault and date '
      + 'are visible in the name. Returns the backup path.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: `backup written to ${v.path}` }] },
    async execute() {
      const s = await guardStore()
      const source = resolveVaultPath(config)
      const backup = join(dirname(source), backupFileName(config.name ?? 'default'))
      const raw = await readFile(source, 'utf8')
      await mkdir(dirname(backup), { recursive: true, mode: 0o700 })
      await writeFile(backup, raw, { mode: 0o600 })
      void s
      return { path: backup }
    },
  }))

  // ── vault_restore_backup: restore the vault from an encrypted backup ──────
  ctx.tools.register(defineTool({
    name: 'vault_restore_backup',
    description: 'Restore entries from one of the vault encrypted backup files (new-style '
      + '`<vault>-backups-YYYY-MM-DD_HH-MM-SS.json` or legacy `vault-backup-<epoch>.json`). By '
      + 'default mode="merge": the backup entries are copied INTO the current vault (same-title '
      + 'entries skipped unless overwrite: true), so they appear in the entries list. Pass '
      + 'mode="replace" for the legacy behaviour: a safety snapshot is written first, then the '
      + 'backup overwrites the whole vault file and the store reloads. Use vault_backups to list '
      + 'available backup paths first.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of a backup .json file.' },
      mode: { type: 'string', enum: ['merge', 'replace'], description: '"merge" copies backup entries into the current vault (default); "replace" overwrites the whole vault.' },
      overwrite: { type: 'boolean', description: 'Merge mode only: replace same-title entries (default false).' },
      dryRun: { type: 'boolean', description: 'Merge mode only: preview counts without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { entries: { type: 'integer', required: true }, safetyBackup: { type: 'string' }, note: { type: 'string' }, added: { type: 'integer' }, skipped: { type: 'integer' }, updated: { type: 'integer' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `restored (${v.entries} entries)` }] },
    async execute(args) {
      assertWritable('vault_restore_backup')
      const s = await guardStore()
      const mode = args.mode === 'replace' ? 'replace' : 'merge'
      if (mode === 'merge') {
        const result = await mergeBackupIntoVault(masterPassword, config, args.path, args.overwrite === true, args.dryRun === true)
        void s
        return { entries: result.entries, safetyBackup: '', note: result.note, added: result.added, skipped: result.skipped, updated: result.updated }
      }
      const result = await restoreVaultFromBackup(masterPassword, config, args.path)
      void s
      return result
    },
  }))

  // ── vault_search_history: search including deleted entries ─────────────────
  ctx.tools.register(defineTool({
    name: 'vault_search_history',
    description: 'Search including soft-deleted (trashed) entries, marked with their deleted state. '
      + 'Returns summaries plus a deleted flag — useful to find something you deleted.',
    parameters: { query: { type: 'string', required: true, description: 'Search text.' }, limit: { type: 'number', description: 'Max results (default 20).' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { results: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.results) }] },
    async execute(args) {
      const s = await guardStore()
      const needle = args.query.trim().toLowerCase()
      const limit = validateLimit(args.limit, 'vault_search_history')
      if (needle.length === 0) return { results: [] }
      const results: JsonValue[] = []
      for (const e of s.listTrash()) {
        if (results.length >= limit) break
        const hay = [e.title, e.username, e.email, e.host, e.url, ...(e.tags ?? [])].filter(Boolean).join(' ').toLowerCase()
        if (hay.includes(needle)) {
          results.push({ ...toSummary(e), deleted: true } as unknown as JsonValue)
        }
      }
      return { results }
    },
  }))

  // ── vault_undelete_all: restore every trashed entry ─────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_undelete_all',
    description: 'Restore ALL soft-deleted (trashed) entries back to the active set. Returns how many '
      + 'were restored.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { restored: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `restored ${v.restored} entries` }] },
    async execute() {
      assertWritable('vault_undelete_all')
      const s = await guardStore()
      const trashed = s.listTrash()
      let restored = 0
      for (const e of trashed) {
        if (await s.restore(e.id)) restored++
      }
      return { restored }
    },
  }))

  // ── vault_export_wallet: pass (standard Unix) compatible export ────────────
  ctx.tools.register(defineTool({
    name: 'vault_export_wallet',
    description: 'Export entries as a directory tree of files compatible with pass (the standard Unix '
      + 'password manager): one file per entry containing the password, with metadata in comments. '
      + 'Returns the output directory.',
    parameters: { dir: { type: 'string', required: true, description: 'Absolute output directory (created if needed).' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { dir: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `exported ${v.count} entries to ${v.dir}` }] },
    async execute(args) {
      const s = await guardStore()
      await mkdir(args.dir, { recursive: true, mode: 0o700 })
      let count = 0
      for (const e of s.list()) {
        const safe = e.title.replace(/[^a-zA-Z0-9._-]+/g, '_')
        const file = join(args.dir, safe + '.gpg')
        const lines = [
          e.password ?? '',
          ...(e.username !== undefined ? [`login: ${e.username}`] : []),
          ...(e.email !== undefined ? [`email: ${e.email}`] : []),
          ...(e.url !== undefined ? [`url: ${e.url}`] : []),
          ...(e.notes !== undefined ? [e.notes] : []),
        ]
        await writeFile(file, lines.join('\n') + '\n', { mode: 0o600 })
        count++
      }
      void s
      return { dir: args.dir, count }
    },
  }))

  // ── vault_get_many: batch read with a fields whitelist ─────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_get_many',
    description: 'Read multiple entries by id, returning only the requested fields for each. '
      + 'More efficient than repeated vault_get when you need several entries.',
    parameters: {
      ids: { type: 'array', required: true, items: { type: 'string' }, description: 'Entry ids.' },
      fields: { type: 'array', items: { type: 'string' }, description: 'Fields to include per entry (e.g. ["username", "password"]).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { entries: { type: 'array', required: true, items: { type: 'json' } }, missing: { type: 'array', required: true, items: { type: 'string' } } } }, render: (_a, v) => [{ type: 'text', text: `returned ${(v.entries as unknown[]).length} entries` }] },
    async execute(args) {
      const s = await guardStore()
      const out: JsonValue[] = []
      const missing: string[] = []
      const seen = new Set<string>()
      for (const id of args.ids ?? []) {
        if (seen.has(id)) continue
        seen.add(id)
        const e = s.get(id)
        if (!e) { missing.push(id); continue }
        const full = stripTimestamps(e) as Record<string, unknown>
        if (Array.isArray(args.fields) && args.fields.length > 0) {
          const picked: Record<string, unknown> = {}
          for (const f of args.fields) {
            if (typeof f === 'string' && f in full) picked[f] = full[f]
          }
          out.push(picked as unknown as JsonValue)
        } else {
          out.push(full as unknown as JsonValue)
        }
      }
      return { entries: out, missing }
    },
  }))

  // ── vault_import_wallet: import from a pass directory ──────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_wallet',
    description: 'Import entries from a pass directory tree: each .gpg file (or plaintext file) becomes '
      + 'an entry titled by its filename; the first line is the password, remaining lines are parsed as '
      + 'login:/email:/url: metadata. Returns added/skipped.',
    parameters: {
      dir: { type: 'string', required: true, description: 'Absolute pass directory.' },
      dryRun: { type: 'boolean', description: 'Preview how many entries would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `imported ${v.added}, updated ${v.updated}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_wallet')
      const s = await guardStore()
      let added = 0
      let skipped = 0
      const entries = await readdir(args.dir, { withFileTypes: true })
      if (entries.length > 5000) {
        throw new Error(`vault_import_wallet: ${entries.length} entries exceeds the 5000-entry safety limit — split the directory`)
      }
      if (args.dryRun === true) {
        const files = entries.filter(ent => ent.isFile() && !s.list().some(e => e.title === ent.name.replace(/\.gpg$/i, '')))
        return { added: 0, skipped: 0, updated: 0, dryRun: true, note: `would add ${files.length} of ${entries.length} entries` }
      }
      for (const ent of entries) {
        if (!ent.isFile()) continue
        if (/\.gpg$/i.test(ent.name)) { skipped++; continue } // gpg-encrypted: decrypt with gpg first
        const name = ent.name.replace(/\.gpg$/i, '')
        if (s.list().some(e => e.title === name)) { skipped++; continue }
        const content = await readFile(join(args.dir, ent.name), 'utf8')
        const lines = content.split('\n')
        const password = lines[0] ?? ''
        const entry: VaultEntry = {
          id: randomUUID(),
          title: name,
          password,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        }
        for (const line of lines.slice(1)) {
          const m = /^(login|email|url|notes):\s*(.*)$/.exec(line.trim())
          if (!m) continue
          if (m[1] === 'login' && m[2]) entry.username = m[2]
          else if (m[1] === 'email' && m[2]) entry.email = m[2]
          else if (m[1] === 'url' && m[2]) entry.url = m[2]
          else if (m[1] === 'notes' && m[2]) entry.notes = (entry.notes ? entry.notes + '\n' : '') + m[2]
        }
        s.insertDirect(entry)
        added++
      }
      await s.persist()
      return { added, skipped, updated: 0 }
    },
  }))

  // ── vault_compare: field-by-field diff of two entries ───────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_compare',
    description: 'Compare two entries field by field and report which fields differ, are only in one, '
      + 'or are equal. Secret VALUES are not shown — only the field names and a difference summary.',
    parameters: { idA: { type: 'string', required: true, description: 'First entry id.' }, idB: { type: 'string', required: true, description: 'Second entry id.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { onlyA: { type: 'array', required: true, items: { type: 'string' } }, onlyB: { type: 'array', required: true, items: { type: 'string' } }, differ: { type: 'array', required: true, items: { type: 'string' } }, equal: { type: 'array', required: true, items: { type: 'string' } } } }, render: (_a, v) => [{ type: 'text', text: `only in A: ${v.onlyA.join(',') || '-'} | only in B: ${v.onlyB.join(',') || '-'} | differ: ${v.differ.join(',') || '-'}` }] },
    async execute(args) {
      const s = await guardStore()
      const a = s.get(args.idA)
      const b = s.get(args.idB)
      if (!a || !b) throw new Error('vault_compare: both entries must exist and be active')
      const norm = (e: VaultEntry) => {
        const { createdAt, updatedAt, ...rest } = e
        return rest as Record<string, unknown>
      }
      const na = norm(a)
      const nb = norm(b)
      const keys = new Set([...Object.keys(na), ...Object.keys(nb)])
      const onlyA: string[] = []
      const onlyB: string[] = []
      const differ: string[] = []
      const equal: string[] = []
      for (const k of keys) {
        const va = na[k]
        const vb = nb[k]
        const sa = JSON.stringify(va)
        const sb = JSON.stringify(vb)
        if (va === undefined) onlyB.push(k)
        else if (vb === undefined) onlyA.push(k)
        else if (sa !== sb) differ.push(k)
        else equal.push(k)
      }
      return { onlyA, onlyB, differ, equal }
    },
  }))

  // ── vault_rename: rename an entry quickly ───────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_rename',
    description: 'Rename an entry (set a new title). Convenience shortcut for vault_update.',
    parameters: { id: { type: 'string', required: true, description: 'Entry id.' }, title: { type: 'string', required: true, description: 'New title.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { renamed: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.renamed ? 'entry renamed' : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_rename')
      if (!args.title.trim()) throw new Error('vault_rename: title must not be empty')
      const s = await guardStore()
      const updated = await s.update(args.id, { title: args.title.trim() })
      return { renamed: updated !== undefined }
    },
  }))

  // ── vault_rotation: expiry / rotation report ───────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_rotation',
    description: 'Report credentials that are expired, due for rotation (rotationDays elapsed), '
      + 'or expiring soon. Returns summaries with a due state — never secrets.',
    parameters: { soonWindowDays: { type: 'integer', description: 'How many days ahead counts as "expiring soon" (default 7, 1–90).' } },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { entries: { type: 'array', required: true, items: { type: 'json' } } } },
      render: (_a, v) => [{ type: 'text', text: v.entries.length === 0 ? 'no rotation items' : JSON.stringify(v.entries) }],
    },
    async execute(args) {
      const s = await guardStore()
      const window = args.soonWindowDays === undefined ? 7 : args.soonWindowDays
      if (!Number.isInteger(window) || window < 1 || window > 90) {
        throw new Error('vault_rotation: soonWindowDays must be an integer 1–90')
      }
      return { entries: s.rotationReport(Date.now(), window) }
    },
  }))

  // ── vault_integrity: verify the on-disk vault document ─────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_integrity',
    description: 'Verify the on-disk vault file: decrypts the password-verification envelope with the '
      + 'live key and compares the stored entry count against the in-memory store. Catches a corrupted '
      + 'or partially-written vault document before it causes silent data loss. No secrets in the report.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, verifyOk: { type: 'boolean', required: true }, fileEntries: { type: 'integer', required: true }, memoryEntries: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.ok ? 'vault file is intact' : `integrity mismatch: ${v.fileEntries} on disk vs ${v.memoryEntries} in memory, verify=${v.verifyOk}` }] },
    async execute() {
      const s = await guardStore()
      return await s.integrity()
    },
  }))

  // ── vault_breach_check: Watchtower-style breach scan ──────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_breach_check',
    description: 'Watchtower-style breach scan: check every stored password against the Have I Been '
      + 'Pwned Pwned Passwords database using the k-anonymity protocol (only the first 5 hex chars of '
      + 'the SHA-1 hash leave this machine — the full hash is never sent). Falls back to a built-in '
      + 'common-password list when the network is unavailable. Returns which entries are breached '
      + '(with breach counts) and which use known-weak passwords. No secrets in the report.',
    parameters: {
      ids: { type: 'array', items: { type: 'string' }, description: 'Only check these entry ids (optional; default all).' },
      online: { type: 'boolean', description: 'Allow online Pwned Passwords lookups (default true).' },
      concurrency: { type: 'integer', description: 'Max parallel online lookups (default 4, 1–16).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { checked: { type: 'integer', required: true }, pwned: { type: 'array', required: true, items: { type: 'json' } }, weak: { type: 'array', required: true, items: { type: 'json' } }, offline: { type: 'boolean', required: true }, elapsedMs: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `checked ${v.checked} password(s) in ${v.elapsedMs}ms: ${(v.pwned as unknown[]).length} breached, ${(v.weak as unknown[]).length} weak${v.offline ? ' (offline fallback)' : ''}` }] },
    async execute(args) {
      assertWritable('vault_breach_check')
      const s = await guardStore()
      const ids = new Set(Array.isArray(args.ids) ? args.ids : [])
      const targets = s.list().filter(e => (ids.size === 0 || ids.has(e.id)) && e.password !== undefined)
      const pwned: Array<{ id: string; title: string; count: number }> = []
      const weak: Array<{ id: string; title: string }> = []
      let offline = false
      const concurrency = args.concurrency === undefined ? 4 : args.concurrency
      if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 16) {
        throw new Error('vault_breach_check: concurrency must be an integer 1–16')
      }
      // Bounded parallelism: run up to `concurrency` lookups at once so a large
      // vault never hammers the API or times out as one serial queue.
      let index = 0
      const worker = async (): Promise<void> => {
        while (index < targets.length) {
          const e = targets[index++]!
          const verdict = await checkPassword(e.password!)
          if (verdict.source !== 'hibp') offline = true
          if (verdict.breached && verdict.reason === 'pwned') {
            pwned.push({ id: e.id, title: e.title, count: verdict.count })
          } else if (verdict.breached && verdict.reason === 'weak') {
            weak.push({ id: e.id, title: e.title })
          }
        }
      }
      const started = Date.now()
      await Promise.all(Array.from({ length: Math.min(concurrency, targets.length || 1) }, () => worker()))
      return { checked: targets.length, pwned, weak, offline, elapsedMs: Date.now() - started }
    },
  }))

  // ── vault_health: weak / reused credential scan ────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_health',
    description: 'Scan the vault for weak passwords (shorter than 12 chars) and credentials reused '
      + 'across entries. Returns non-secret findings (entry summaries grouped by the reused value).',
    parameters: {},
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { weak: { type: 'array', required: true, items: { type: 'json' } }, reused: { type: 'array', required: true, items: { type: 'json' } }, strength: { type: 'json', required: true }, no2fa: { type: 'array', required: true, items: { type: 'json' } }, httpSites: { type: 'array', required: true, items: { type: 'json' } }, score: { type: 'integer', required: true }, verdict: { type: 'string', required: true } } },
      render: (_a, v) => [{ type: 'text', text: `weak: ${v.weak.length}, reused groups: ${v.reused.length}` }],
    },
    async execute() {
      const s = await guardStore()
      return s.health()
    },
  }))

  // ── vault_watchtower: per-entry risk analysis (1Password Watchtower-style) ─
  ctx.tools.register(defineTool({
    name: 'vault_watchtower',
    description: 'Watchtower-style per-entry risk analysis (inspired by 1Password Watchtower / '
      + 'Bitwarden reports): every active entry is rated with concrete risk flags — short or weak '
      + 'password, repeated characters, keyboard sequences (qwerty/1234), embedded year, common '
      + 'password, reused across entries, http:// site, missing 2FA, expired. Returns a 0–100 score '
      + 'and a good/warn/poor verdict per entry (no secrets).',
    parameters: {
      minScore: { type: 'integer', description: 'Only return entries with score below this (default 100 = all).' },
      limit: { type: 'integer', description: 'Max entries (default 100).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { entries: { type: 'array', required: true, items: { type: 'json' } }, count: { type: 'integer', required: true }, atRisk: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `${v.atRisk} of ${v.count} entries at risk` }] },
    async execute(args) {
      const s = await guardStore()
      const limit = args.limit === undefined ? 100 : args.limit
      const minScore = args.minScore === undefined ? 100 : args.minScore
      const analyzed = analyzeVault(s.list())
        .filter(e => e.score < minScore)
        .slice(0, limit)
      const atRisk = analyzed.filter(e => e.verdict !== 'good').length
      return { entries: analyzed as unknown as JsonValue[], count: analyzed.length, atRisk }
    },
  }))

  // ── vault_restore / vault_purge: trash management ──────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_restore',
    description: 'Restore a soft-deleted entry from the vault trash back into the active set.',
    parameters: { id: { type: 'string', required: true, description: 'The trashed entry id.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { restored: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.restored ? 'entry restored' : 'entry not found in trash' }] },
    async execute(args) {
      assertWritable('vault_restore')
      const s = await guardStore()
      return { restored: await s.restore(args.id) }
    },
  }))

  // ── vault_restore_recent: undo the last delete ─────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_restore_recent',
    description: 'Undo the most recent delete: restore the trashed entry that was deleted last. '
      + 'Returns the restored summary or restored=false when the trash is empty.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { restored: { type: 'boolean', required: true }, entry: { type: 'json' } } }, render: (_a, v) => [{ type: 'text', text: v.restored ? `restored: ${(v.entry as { title?: string })?.title ?? 'entry'}` : 'trash is empty' }] },
    async execute() {
      assertWritable('vault_restore_recent')
      const s = await guardStore()
      const entry = await s.restoreRecent()
      return entry === undefined ? { restored: false } : { restored: true, entry: toSummaryJson(entry) }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_purge',
    description: 'Permanently delete an entry (active or trashed). Cannot be undone — prefer vault_delete '
      + '(soft delete) unless the entry must be removed from disk.',
    parameters: {
      id: { type: 'string', required: true, description: 'The entry id to purge.' },
      confirm: { type: 'boolean', description: 'Must be true when purging an ACTIVE (non-trashed) entry, to prevent accidental permanent deletion. Trashed entries can be purged without it.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { purged: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.purged ? 'entry purged' : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_purge')
      const s = await guardStore()
      const target = s.getIncludingTrash(args.id)
      if (target !== undefined && target.deletedAt === undefined && args.confirm !== true) {
        throw new Error('vault_purge: refusing to purge an ACTIVE entry — move it to trash first (vault_delete) or pass confirm: true')
      }
      return { purged: await s.purge(args.id) }
    },
  }))

  // ── vault_export / vault_import: portable encrypted transfer ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_export',
    description: 'Export the entire vault (including trash) as a single encrypted document under a '
      + 'separate export password (from the exportPasswordEnv config). Use for backup or migration; '
      + 'the export can be re-imported with vault_import. Never pass the password as an argument.',
    parameters: {
      ids: { type: 'array', items: { type: 'string' }, description: 'Only export these entry ids (optional).' },
      since: { type: 'integer', description: 'Only export active entries created or updated at/after this epoch millis (incremental backup).' },
      path: { type: 'string', description: 'Optional absolute output path; defaults to <vault dir>/vault-export-<ts>.json.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { exported: { type: 'boolean', required: true }, note: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.note }] },
    async execute(args) {
      const exportPassword = resolveExportPassword(config)
      const s = await guardStore()
      let blob: string
      if (args.ids !== undefined && args.ids.length > 0) {
        blob = await s.exportEncrypted(exportPassword, Date.now(), new Set(args.ids))
      } else if (args.since !== undefined) {
        const ids = new Set(s.list().filter(e => e.createdAt >= args.since! || e.updatedAt >= args.since!).map(e => e.id))
        blob = await s.exportEncrypted(exportPassword, Date.now(), ids)
      } else {
        blob = await s.exportEncrypted(exportPassword)
      }
      const file = args.path ?? join(dirname(resolveVaultPath(config)), `vault-export-${Date.now()}.json`)
      await mkdir(dirname(file), { recursive: true, mode: 0o700 })
      await writeFile(file, blob, { mode: 0o600 })
      const count = args.ids !== undefined && args.ids.length > 0
        ? args.ids.length
        : args.since !== undefined
          ? s.list().filter(e => e.createdAt >= args.since! || e.updatedAt >= args.since!).length
          : s.list().length + s.listTrash().length
      return { exported: true, note: `vault exported to ${file}`, count }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_import',
    description: 'Import a previously exported vault document (see vault_export), merging entries by '
      + 'id (gaps filled) or replacing them with overwrite. dryRun previews without writing. Pass the '
      + 'document path; the export password comes from the exportPasswordEnv config.',
    parameters: {
      path: { type: 'string', description: 'Absolute path of the exported vault JSON file (provide exactly one of path or blob).' },
      blob: { type: 'string', description: 'The exported vault document content directly (provide exactly one of path or blob).' },
      overwrite: { type: 'boolean', description: 'Replace existing entries with the same id instead of merging (default false).' },
      dryRun: { type: 'boolean', description: 'Preview how many entries would be imported without writing anything (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { imported: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `imported ${v.imported} entries` }] },
    async execute(args) {
      assertWritable('vault_import')
      const s = await guardStore()
      if (args.path === undefined && args.blob === undefined) {
        throw new Error('vault_import: provide either path or blob')
      }
      if (args.blob !== undefined && args.blob.length > 64 * 1024 * 1024) {
        throw new Error('vault_import: blob exceeds 64 MiB — write it to a file and pass path instead')
      }
      const blob = args.path !== undefined ? await readFile(args.path, 'utf8') : args.blob!
      // Auto-sniff: an unencrypted Bitwarden JSON export (encrypted:false +
      // items[]) routes to the Bitwarden importer; anything else is treated as
      // the portable encrypted dsh-vault document.
      try {
        const probe = JSON.parse(blob)
        if (probe && probe.encrypted === false && Array.isArray(probe.items)) {
          let added = 0
          let skipped = 0
          let updated = 0
          for (const item of probe.items) {
            const title = (item.name ?? '').trim()
            if (!title) { skipped++; continue }
            const patch: VaultEntryPatch = {}
            // Bitwarden type 2 = secure note → store as a custom entry with notes.
            if (item.type === 2) patch.kind = 'custom'
            const login = item.login
            if (login?.username !== undefined) patch.username = login.username
            if (login?.password !== undefined) patch.password = login.password
            if (login?.totp !== undefined) patch.otpSecret = login.totp
            const uri = login?.uris?.find((u: { uri?: string }) => u.uri)?.uri
            if (uri !== undefined) patch.url = uri
            if (item.notes) patch.notes = item.notes
            if (item.favorite === true) patch.favorite = true
            const fields: Record<string, string> = {}
            for (const f of item.fields ?? []) {
              if (f.name !== undefined && f.value !== undefined) fields[f.name] = f.value
            }
            for (const key of ['host', 'apiKey', 'secret', 'accessToken', 'refreshToken', 'privateKey']) {
              if (fields[key] !== undefined) { (patch as unknown as Record<string, unknown>)[key] = fields[key]; delete fields[key] }
            }
            if (Object.keys(fields).length > 0) patch.fields = fields
            const existing = s.list().find(e => e.title === title)
            if (existing && args.overwrite !== true) { skipped++; continue }
            if (existing) { if (args.dryRun !== true) await s.update(existing.id, patch); updated++ }
            else { if (args.dryRun !== true) await s.add({ title, ...patch }); added++ }
          }
          return { imported: added + updated, note: `sniffed Bitwarden JSON: added ${added}, updated ${updated}, skipped ${skipped}${args.dryRun === true ? ' (dry run)' : ''}` }
        }
      } catch { /* not JSON or not Bitwarden — fall through to encrypted import */ }
      const exportPassword = resolveExportPassword(config)
      const count = await s.importEncrypted(blob, exportPassword, args.overwrite === true, args.dryRun === true)
      return { imported: count, note: 'imported encrypted dsh-vault document' }
    },
  }))

  // ── vault_fill: find the credential that fits a target ─────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_fill',
    description: 'Find the vault entry that fits a target (host/URL/username/title) and return the '
      + 'ready-to-use credentials (secrets included, as the caller needs them for the actual login). '
      + 'Use instead of vault_search+vault_get when you know what you are connecting to.',
    parameters: {
      target: { type: 'string', required: true, description: 'Host, URL, username, or title to match.' },
      fields: { type: 'array', items: { type: 'string' }, description: 'Only return these fields (e.g. ["username","password"]). Default returns the full entry.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { found: { type: 'boolean', required: true }, entry: { type: 'json' } } },
      render: (_a, v) => [{ type: 'text', text: v.found ? `matched: ${(v.entry as { title?: string })?.title ?? 'entry'}` : 'no matching entry' }],
    },
    async execute(args) {
      const s = await guardStore()
      const needle = args.target.trim().toLowerCase()
      if (needle.length === 0) return { found: false }
      const scoreOf = (entry: VaultEntry): number => {
        const host = (entry.host ?? '').toLowerCase()
        const url = (entry.url ?? '').toLowerCase()
        const title = entry.title.toLowerCase()
        const username = (entry.username ?? '').toLowerCase()
        const email = (entry.email ?? '').toLowerCase()
        const hostBase = host.split(':')[0] ?? ''
        if (hostBase !== '' && hostBase === needle) return 6
        if (url !== '' && url === needle) return 5
        if (title === needle) return 4
        if (hostBase !== '' && hostBase.includes(needle)) return 3
        if (url.includes(needle)) return 2
        if (title.includes(needle) || username.includes(needle) || email.includes(needle)) return 1
        return 0
      }
      let best: VaultEntry | undefined
      let bestScore = 0
      for (const entry of s.list()) {
        const score = scoreOf(entry)
        if (score > bestScore) { best = entry; bestScore = score }
      }
      if (best === undefined) return { found: false }
      const full = stripTimestamps(best)
      if (Array.isArray(args.fields) && args.fields.length > 0) {
        const picked: Record<string, unknown> = {}
        for (const f of args.fields) {
          const v = (full as unknown as Record<string, unknown>)[f]
          if (v !== undefined) picked[f] = v
        }
        return { found: true, entry: picked as unknown as JsonValue }
      }
      return { found: true, entry: full }
    },
  }))

  // ── vault_env: environment-variable export ─────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_env',
    description: 'Render entries flagged for environment export (tags contain "env") as KEY=VALUE lines '
      + 'suitable for .env or export statements. Keys derive from the title + field name; values are the '
      + 'secrets. Returns the lines so the caller can write them to a file (user-authorized).',
    parameters: {
      kind: { type: 'string', description: 'Only export entries of this kind.', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'] },
      ids: { type: 'array', items: { type: 'string' }, description: 'Only export these entry ids (optional).' },
      mask: { type: 'boolean', description: 'Return masked values (secrets replaced with ***) instead of the real values.' },
      prefix: { type: 'string', description: 'Optional key prefix, e.g. "APP_" → APP_GITHUB_TOKEN.' },
      keysOnly: { type: 'boolean', description: 'Return only the KEY names (values redacted) — useful for config audits.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { lines: { type: 'array', required: true, items: { type: 'string' } } } }, render: (_a, v) => [{ type: 'text', text: v.lines.join('\n') }] },
    async execute(args) {
      const s = await guardStore()
      let raw = await envLines(s, args.kind, args.ids, typeof args.prefix === 'string' ? args.prefix : '')
      if (args.keysOnly === true) raw = raw.map(line => line.split('=')[0] ?? line)
      const lines = args.mask === true
        ? raw.map(line => line.replace(/=(.*)$/, (m, v: string) => '=' + (v.length > 8 ? v.slice(0, 4) + '***' : '***')))
        : raw
      return { lines }
    },
  }))

  // ── vault_export_env: write env-flagged entries to a .env file ──────────────
  ctx.tools.register(defineTool({
    name: 'vault_export_env',
    description: 'Write env-flagged entries (tags contain "env") to a .env file at the given path '
      + 'as KEY=VALUE lines (values shell-quoted). Returns the path and how many lines were written.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the .env file to write.' },
      prefix: { type: 'string', description: 'Optional key prefix, e.g. "APP_" → APP_GITHUB_TOKEN.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, lines: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `wrote ${v.lines} lines to ${v.path}` }] },
    async execute(args) {
      assertWritable('vault_export_env')
      const s = await guardStore()
      const lines = await envLines(s, undefined, undefined, typeof args.prefix === 'string' ? args.prefix : '')
      await mkdir(dirname(args.path), { recursive: true, mode: 0o700 })
      await writeFile(args.path, lines.join('\n') + (lines.length > 0 ? '\n' : ''), { mode: 0o600 })
      return { path: args.path, lines: lines.length }
    },
  }))

  // ── vault_templates: field templates by kind ───────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_templates',
    description: 'Return the recommended fields for a credential kind, so vault_add can be called with '
      + 'the right field names (e.g. kind ssh → host/port/username/password/privateKey). Also supports '
      + 'user-defined templates (action: save/list/remove) persisted next to the vault (KeePassXC-style).',
    parameters: {
      kind: { type: 'string', description: 'Entry kind; default login.', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'] },
      action: { type: 'string', description: 'get (default) | save | list | remove.', enum: ['get', 'save', 'list', 'remove'] },
      name: { type: 'string', description: 'Custom template name (required for save/remove).' },
      fields: { type: 'json', description: 'Field template for action=save, e.g. {"username":"account","password":""}.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { kind: { type: 'string' }, fields: { type: 'json' }, templates: { type: 'array', items: { type: 'json' } }, saved: { type: 'boolean' }, removed: { type: 'boolean' }, message: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.message ?? JSON.stringify(v.fields) }] },
    async execute(args) {
      const kind = args.kind ?? 'login'
      const tplPath = join(dirname(resolveVaultPath(config)), 'templates.json')
      // Custom templates live next to the vault file (same dir).
      let custom: Array<{ name: string; kind: string; fields: Record<string, string> }> = []
      try {
        const raw = await readFile(tplPath, 'utf8')
        custom = JSON.parse(raw)
      } catch { /* no custom templates yet */ }
      if (args.action === 'save') {
        assertWritable('vault_templates')
        const name = typeof args.name === 'string' ? args.name.trim() : ''
        if (!name) throw new Error('vault_templates: name is required for save')
        const fields = (args.fields ?? {}) as Record<string, unknown>
        const clean: Record<string, string> = {}
        for (const [k, v] of Object.entries(fields)) {
          if (typeof v === 'string') clean[k] = v
        }
        custom = custom.filter(t => t.name !== name)
        custom.push({ name, kind, fields: clean })
        await mkdir(dirname(tplPath), { recursive: true, mode: 0o700 })
        await writeFile(tplPath, JSON.stringify(custom, null, 2), { mode: 0o600 })
        return { saved: true, message: `template "${name}" saved (${Object.keys(clean).length} fields)` }
      }
      if (args.action === 'remove') {
        assertWritable('vault_templates')
        const name = typeof args.name === 'string' ? args.name.trim() : ''
        const before = custom.length
        custom = custom.filter(t => t.name !== name)
        if (custom.length === before) return { removed: false, message: `template "${name}" not found` }
        await writeFile(tplPath, JSON.stringify(custom, null, 2), { mode: 0o600 })
        return { removed: true, message: `template "${name}" removed` }
      }
      if (args.action === 'list') {
        return { templates: custom, message: `${custom.length} custom template(s)` }
      }
      // get: named custom template wins over the built-in kind template.
      const named = typeof args.name === 'string' ? custom.find(t => t.name === args.name) : undefined
      if (named) return { kind: named.kind, fields: named.fields, message: `template "${named.name}"` }
      return { kind, fields: TEMPLATES[kind] ?? TEMPLATES.login!, message: `${kind} template` }
    },
  }))

  // ── vault_strength: zero-dependency password strength estimation ────────────
  ctx.tools.register(defineTool({
    name: 'vault_strength',
    description: 'Estimate the strength of a password with a zero-dependency heuristic '
      + '(length, character-class diversity, common-pattern penalties). Returns a score 0–100 '
      + 'and a verdict: weak / fair / strong / very strong. Use before choosing or storing a password.',
    parameters: { password: { type: 'string', required: true, description: 'The password to evaluate.' } },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { score: { type: 'integer', required: true }, verdict: { type: 'string', required: true }, feedback: { type: 'string', required: true }, bits: { type: 'integer', required: true } } },
      render: (_a, v) => [{ type: 'text', text: `${v.verdict} (${v.score}/100, ~${v.bits} bits) — ${v.feedback}` }],
    },
    async execute(args) {
      const r = estimateStrength(args.password)
      return r
    },
  }))

  // ── vault_export_csv: export entries to a CSV file ──────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_export_csv',
    description: 'Export vault entries to a CSV file (the same shape vault_import_csv accepts), '
      + 'optionally filtered by kind. Writes to <vault dir>/vault-export-<ts>.csv and returns the path.',
    parameters: {
      path: { type: 'string', description: 'Optional absolute output path; defaults to <vault dir>/vault-export-<ts>.csv.' },
      delimiter: { type: 'string', description: 'CSV delimiter (default ",").' },
      kind: { type: 'string', description: 'Only export entries of this kind (login/ssh/api-key/secret/oauth/cookie/card/custom).', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'cookie', 'card', 'custom'] },
      includeSecrets: { type: 'boolean', description: 'Include secret columns (password/apiKey/secret/tokens). Default false — the CSV is secret-free for safe handling.' },
      favoriteOnly: { type: 'boolean', description: 'Only export pinned (favorite) entries.' },
      tag: { type: 'string', description: 'Only export entries carrying this tag.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `exported ${v.count} entries to ${v.path}` }] },
    async execute(args) {
      const s = await guardStore()
      const kind = args.kind
      const tag = typeof args.tag === 'string' ? args.tag.trim() : ''
      const entries = s.list().filter(e => (kind === undefined || (e.kind ?? 'login') === kind)
        && (args.favoriteOnly !== true || e.favorite === true)
        && (tag.length === 0 || (e.tags ?? []).includes(tag)))
      const secretFields = ['password', 'apiKey', 'secret', 'accessToken', 'refreshToken', 'otpSecret', 'privateKey', 'cardNumber', 'cardCvv']
      const metaFields = ['url', 'email', 'phone', 'host', 'port', 'expiresAt', 'rotationDays', 'notes', 'tags', 'sensitivity', 'favorite', 'icon', 'color', 'cardExpiry', 'cardHolder']
      const healthFields = ['weakPassword', 'no2fa', 'httpSite', 'expired']
      const stampFields = ['createdAt', 'updatedAt']
      const fields = args.includeSecrets === true
        ? ['title', 'kind', 'username', ...secretFields, ...metaFields, ...healthFields, ...stampFields]
        : ['title', 'kind', 'username', ...metaFields, ...healthFields, ...stampFields]
      const delim = args.delimiter ?? ','
      // Standard CSV quoting: wrap only when needed, and only escape quotes in
      // the comma mode (TSV and other delimiters never escape double quotes).
      const esc = (v: unknown): string => {
        const str = v === undefined || v === null ? '' : Array.isArray(v) ? v.join(';') : String(v)
        const needsQuote = str.includes(delim) || str.includes('"') || str.includes('\n') || str.includes('\r')
        if (!needsQuote) return str
        return `"${str.replace(/"/g, delim === ',' ? '""' : '"')}"`
      }
      const lines = [fields.join(delim)]
      const MIN_LEN = 12
      const now = Date.now()
      for (const e of entries) {
        const rec = e as unknown as Record<string, unknown>
        const pw = typeof rec.password === 'string' ? rec.password : ''
        const kind = typeof rec.kind === 'string' ? rec.kind : 'login'
        ;(rec as Record<string, unknown>).weakPassword = pw.length > 0 && pw.length < MIN_LEN ? 'true' : 'false'
        ;(rec as Record<string, unknown>).no2fa = pw.length > 0 && (kind === 'login' || kind === 'ssh') && rec.otpSecret === undefined ? 'true' : 'false'
        ;(rec as Record<string, unknown>).httpSite = typeof rec.url === 'string' && /^http:\/\//i.test(rec.url) ? 'true' : 'false'
        ;(rec as Record<string, unknown>).expired = typeof rec.expiresAt === 'number' && rec.expiresAt < now ? 'true' : 'false'
        lines.push(fields.map(f => esc(rec[f])).join(delim))
      }
      const file = args.path ?? join(dirname(resolveVaultPath(config)), `vault-export-${Date.now()}.csv`)
      await mkdir(dirname(file), { recursive: true, mode: 0o700 })
      await writeFile(file, lines.join('\n') + '\n', { mode: 0o600 })
      return { path: file, count: entries.length }
    },
  }))

  // ── vault_search_system: search Chrome / Keychain without exposing secrets ─
  ctx.tools.register(defineTool({
    name: 'vault_search_system',
    description: 'Search system credential stores (Chrome Login Data and the macOS keychain) for a '
      + 'keyword, returning matching sites/services and usernames WITHOUT any passwords. Use this to '
      + 'discover whether a credential exists in Chrome or the keychain before importing it.',
    parameters: {
      query: { type: 'string', required: true, description: 'Keyword to match against site/service names (case-insensitive).' },
      source: { type: 'string', enum: ['chrome', 'keychain', 'all'], description: 'Which store to search (default all).' },
      limit: { type: 'integer', description: 'Max matches (default 20, 1–100).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { matches: { type: 'array', required: true, items: { type: 'json' } }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: `${(v.matches as unknown[]).length} match(es)` }] },
    async execute(args) {
      const needle = args.query.trim().toLowerCase()
      const limit = args.limit === undefined ? 20 : args.limit
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('vault_search_system: limit must be an integer 1–100')
      const source = args.source ?? 'all'
      const matches: Array<{ source: string; name: string; username: string }> = []
      if (source === 'chrome' || source === 'all') {
        try {
          const dbPath = defaultChromeLoginData('chrome', 'Default')
          const creds = readChromeLogins(dbPath)
          for (const c of creds) {
            let name = c.origin
            try { name = new URL(c.origin).hostname } catch { /* keep origin */ }
            if (name.toLowerCase().includes(needle)) {
              matches.push({ source: 'chrome', name, username: c.username })
              if (matches.length >= limit) break
            }
          }
        } catch { /* Chrome unavailable — skip */ }
      }
      if (source === 'keychain' || source === 'all') {
        try {
          const entries = listKeychainEntries(limit * 2)
          for (const e of entries) {
            if (e.service.toLowerCase().includes(needle) || e.account.toLowerCase().includes(needle)) {
              matches.push({ source: 'keychain', name: e.service, username: e.account })
              if (matches.length >= limit) break
            }
          }
        } catch { /* keychain unavailable — skip */ }
      }
      return { matches: matches.slice(0, limit), note: 'searched system credential stores (no passwords exposed)' }
    },
  }))

  // ── vault_import_firefox: import passwords from a Firefox profile ──────────
  ctx.tools.register(defineTool({
    name: 'vault_import_firefox',
    description: 'Import passwords from a Firefox profile (logins.json + key4.db) using the NSS '
      + 'decryption scheme from the open-source firepwd tool. Both legacy 3DES and modern PBES2/AES '
      + 'encryption are supported. Pass masterPassword when Firefox has a primary password set.',
    parameters: {
      dir: { type: 'string', description: 'Optional absolute path to the Firefox profile directory; defaults to the latest profile in the Firefox profiles.ini.' },
      masterPassword: { type: 'string', description: 'Firefox primary password (leave empty when none is set).' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same origin+username (default false = incremental).' },
      dryRun: { type: 'boolean', description: 'Preview what would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `added ${v.added}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_firefox')
      const s = await guardStore()
      const dir = args.dir ?? defaultFirefoxProfileDir()
      const creds = readFirefoxLogins(dir, typeof args.masterPassword === 'string' ? args.masterPassword : '')
      let added = 0
      let skipped = 0
      let updated = 0
      for (const c of creds) {
        let title = c.origin
        try { title = new URL(c.origin).hostname || c.origin } catch { /* keep origin */ }
        const existing = s.list().find(e => e.title === title && e.username === c.username)
        if (existing && args.overwrite !== true) { skipped++; continue }
        const patch: VaultEntryPatch = { username: c.username, password: c.password, url: c.origin }
        if (args.dryRun === true) {
          if (existing) updated++
          else added++
        } else if (existing) { await s.update(existing.id, patch); updated++ }
        else { await s.add({ title, ...patch }); added++ }
      }
      return { added, skipped, updated, note: `Firefox import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
    },
  }))

  // ── vault_import_kdbx: import from a KeePass KDBX4 database ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_kdbx',
    description: 'Import entries from a KeePass KDBX database: KDBX 3.1 and 4.x, AES-KDF or Argon2 KDF, '
      + 'AES-256-CBC or ChaCha20 payload cipher, ChaCha20/Salsa20 protected fields, using the open-source '
      + 'KDBX spec and RFC 9106. Password and optional keyfile supported. NOTE: Argon2 is a pure-JS '
      + 'implementation — large memory settings (e.g. 64 MiB+) may take several seconds to derive the key.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the .kdbx file.' },
      password: { type: 'string', description: 'Database password (empty allowed).' },
      keyfile: { type: 'string', description: 'Optional absolute path of a keyfile.' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same title (default false = incremental).' },
          dryRun: { type: 'boolean', description: 'Preview what would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `added ${v.added}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_kdbx')
      const s = await guardStore()
      const data = await readFile(args.path)
      const keyfile = args.keyfile !== undefined ? await readFile(args.keyfile) : undefined
      // Warn on expensive pure-JS Argon2 parameters BEFORE deriving the key,
      // so a 64 MiB database does not look like a hung tool call.
      let kdfNote = ''
      try {
        const info = describeKdbxKdf(data)
        if (info.kdf === 'argon2' && info.memoryKiB !== undefined && info.memoryKiB >= 65536) {
          const seconds = Math.round(info.memoryKiB / 65536 * 7)
          kdfNote = `; Argon2id ${(info.memoryKiB / 1024).toFixed(0)} MiB × ${info.iterations ?? '?'} iters (pure-JS) may take ~${seconds}s to derive — please wait`
        }
      } catch { /* header inspection is best-effort */ }
      const creds = readKdbx(data, args.password ?? '', keyfile)
      let added = 0
      let skipped = 0
      let updated = 0
      for (const c of creds) {
        const title = c.title.trim()
        if (!title) { skipped++; continue }
        const existing = s.list().find(e => e.title === title)
        if (existing && args.overwrite !== true) { skipped++; continue }
        const patch: VaultEntryPatch = {
          ...(c.username.length > 0 ? { username: c.username } : {}),
          ...(c.password.length > 0 ? { password: c.password } : {}),
          ...(c.url.length > 0 ? { url: c.url } : {}),
          ...(c.notes.length > 0 ? { notes: c.notes } : {}),
        }
        if (args.dryRun === true) {
          if (existing) updated++
          else added++
        } else if (existing) { await s.update(existing.id, patch); updated++ }
        else { await s.add({ title, ...patch }); added++ }
      }
      return { added, skipped, updated, note: `KeePass import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)${kdfNote}` }
    },
  }))

  // ── vault_import_1password: import a 1Password 1PUX export ────────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_1password',
    description: 'Import credentials from a 1Password 1PUX export file (an unencrypted ZIP archive '
      + 'containing export.data). Parses accounts → vaults → items → fields per the official 1PUX '
      + 'format, extracting title, username, password, url, notes, TOTP secret and tags. Imports '
      + 'incrementally: entries with the same title are skipped unless overwrite is set.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the .1pux file.' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same title (default false = incremental).' },
          dryRun: { type: 'boolean', description: 'Preview what would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `added ${v.added}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_1password')
      const s = await guardStore()
      const creds = readOnePasswordPux(await readFile(args.path))
      let added = 0
      let skipped = 0
      let updated = 0
      for (const c of creds) {
        const title = c.title.trim()
        if (!title) { skipped++; continue }
        const existing = s.list().find(e => e.title === title)
        if (existing && args.overwrite !== true) { skipped++; continue }
        const patch: VaultEntryPatch = {
          ...(c.username.length > 0 ? { username: c.username } : {}),
          ...(c.password.length > 0 ? { password: c.password } : {}),
          ...(c.url.length > 0 ? { url: c.url } : {}),
          ...(c.notes.length > 0 ? { notes: c.notes } : {}),
          ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
          ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
        ...(c.favorite === true ? { favorite: true } : {}),
        }
        if (args.dryRun === true) {
          if (existing) updated++
          else added++
        } else if (existing) { await s.update(existing.id, patch); updated++ }
        else { await s.add({ title, ...patch }); added++ }
      }
      return { added, skipped, updated, note: `1Password import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
    },
  }))

  // ── vault_import_manager_csv: import a password-manager CSV ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_manager_csv',
    description: 'Import credentials from a password-manager CSV export. The header row is matched '
      + 'against known column names so Bitwarden, 1Password (CSV), Dashlane, NordPass, Keeper, LastPass '
      + '(and similar exports) are auto-detected; header-less legacy files are treated as '
      + 'title,url,login,password,notes. Recognized columns: title/name, username/login, password, '
      + 'url/website address/login_uri, notes/extra, otp/2fa/otpauth/login_totp, '
      + 'tags/folder/group/grouping/category, fav.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the CSV file.' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same title (default false = incremental).' },
          dryRun: { type: 'boolean', description: 'Preview what would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `added ${v.added}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_manager_csv')
      const s = await guardStore()
      const raw = await readFile(args.path, 'utf8')
      const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
      const creds = readPasswordCsv(cleaned)
      let added = 0
      let skipped = 0
      let updated = 0
      for (const c of creds) {
        const title = c.title.trim()
        if (!title) { skipped++; continue }
        const existing = s.list().find(e => e.title === title)
        if (existing && args.overwrite !== true) { skipped++; continue }
        const patch: VaultEntryPatch = {
          ...(c.username.length > 0 ? { username: c.username } : {}),
          ...(c.password.length > 0 ? { password: c.password } : {}),
          ...(c.url.length > 0 ? { url: c.url } : {}),
          ...(c.notes.length > 0 ? { notes: c.notes } : {}),
          ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
          ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
        ...(c.favorite === true ? { favorite: true } : {}),
        }
        if (args.dryRun === true) {
          if (existing) updated++
          else added++
        } else if (existing) { await s.update(existing.id, patch); updated++ }
        else { await s.add({ title, ...patch }); added++ }
      }
      return { added, skipped, updated, note: `CSV import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
    },
  }))

  // ── vault_import_1pif: import a 1Password 1PIF export ─────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_1pif',
    description: 'Import credentials from a legacy 1Password 1PIF export (1Password 4–7 text '
      + 'format): JSON records separated by "***Top of File***" markers. Login/WebForm items are '
      + 'imported with title, username, password, url (location), notes, TOTP and tags; folder '
      + 'records and trashed items are skipped.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the .1pif file.' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same title (default false = incremental).' },
          dryRun: { type: 'boolean', description: 'Preview what would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `added ${v.added}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_1pif')
      const s = await guardStore()
      const raw = await readFile(args.path, 'utf8')
      const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
      const creds = readOnePasswordPif(cleaned)
      let added = 0
      let skipped = 0
      let updated = 0
      for (const c of creds) {
        const title = c.title.trim()
        if (!title) { skipped++; continue }
        const existing = s.list().find(e => e.title === title)
        if (existing && args.overwrite !== true) { skipped++; continue }
        const patch: VaultEntryPatch = {
          ...(c.username.length > 0 ? { username: c.username } : {}),
          ...(c.password.length > 0 ? { password: c.password } : {}),
          ...(c.url.length > 0 ? { url: c.url } : {}),
          ...(c.notes.length > 0 ? { notes: c.notes } : {}),
          ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
          ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
          ...(c.favorite === true ? { favorite: true } : {}),
        }
        if (args.dryRun === true) {
          if (existing) updated++
          else added++
        } else if (existing) { await s.update(existing.id, patch); updated++ }
        else { await s.add({ title, ...patch }); added++ }
      }
      return { added, skipped, updated, note: `1Password 1PIF import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
    },
  }))

  // ── vault_import_keepass_xml: import a KeePass 2.x XML export ─────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_keepass_xml',
    description: 'Import credentials from a KeePass 2.x XML export (File > Export > XML). Values are '
      + 'imported as written: protected values appear as plaintext when "Export passwords" was checked, '
      + 'or as "********" (masked, not recoverable) otherwise. Uses the same entry structure as KDBX.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the KeePass .xml export.' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same title (default false = incremental).' },
          dryRun: { type: 'boolean', description: 'Preview what would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `added ${v.added}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_keepass_xml')
      const s = await guardStore()
      const raw = await readFile(args.path, 'utf8')
      const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
      const creds = readKeePassXml(cleaned)
      let added = 0
      let skipped = 0
      let updated = 0
      for (const c of creds) {
        const title = c.title.trim()
        if (!title) { skipped++; continue }
        const existing = s.list().find(e => e.title === title)
        if (existing && args.overwrite !== true) { skipped++; continue }
        const patch: VaultEntryPatch = {
          ...(c.username.length > 0 ? { username: c.username } : {}),
          ...(c.password.length > 0 ? { password: c.password } : {}),
          ...(c.url.length > 0 ? { url: c.url } : {}),
          ...(c.notes.length > 0 ? { notes: c.notes } : {}),
        }
        if (args.dryRun === true) {
          if (existing) updated++
          else added++
        } else if (existing) { await s.update(existing.id, patch); updated++ }
        else { await s.add({ title, ...patch }); added++ }
      }
      return { added, skipped, updated, note: `KeePass XML import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
    },
  }))

  // ── vault_import_enpass: import an Enpass JSON export ─────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_enpass',
    description: 'Import credentials from an Enpass JSON export (File > Export > .json). Parses the '
      + 'open-source enpass2keepassxc schema: items[] with typed fields (username/password/url/totp), '
      + 'folders mapped to tags, protected (sensitive) values and favorites preserved. Imports '
      + 'incrementally: same title is skipped unless overwrite is set.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the Enpass .json export.' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same title (default false = incremental).' },
          dryRun: { type: 'boolean', description: 'Preview what would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `added ${v.added}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_enpass')
      const s = await guardStore()
      const raw = await readFile(args.path, 'utf8')
      const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
      const creds = readEnpassJson(cleaned)
      let added = 0
      let skipped = 0
      let updated = 0
      for (const c of creds) {
        const title = c.title.trim()
        if (!title) { skipped++; continue }
        const existing = s.list().find(e => e.title === title)
        if (existing && args.overwrite !== true) { skipped++; continue }
        const patch: VaultEntryPatch = {
          ...(c.username.length > 0 ? { username: c.username } : {}),
          ...(c.password.length > 0 ? { password: c.password } : {}),
          ...(c.url.length > 0 ? { url: c.url } : {}),
          ...(c.notes.length > 0 ? { notes: c.notes } : {}),
          ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
          ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
        ...(c.favorite === true ? { favorite: true } : {}),
        }
        if (args.dryRun === true) {
          if (existing) updated++
          else added++
        } else if (existing) { await s.update(existing.id, patch); updated++ }
        else { await s.add({ title, ...patch }); added++ }
      }
      return { added, skipped, updated, note: `Enpass import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
    },
  }))

  // ── vault_import_chrome: import passwords from Chrome's Login Data ─────────
  ctx.tools.register(defineTool({
    name: 'vault_import_chrome',
    description: 'Import passwords from the Chrome (or Chromium/Brave) password manager. Reads the '
      + 'Login Data SQLite database, decrypts v10/v11 entries using the macOS keychain "Chrome Safe '
      + 'Storage" key (key stays in memory only), and imports them incrementally (same origin+username '
      + 'are skipped unless overwrite). Use vault_import_chrome_update to refresh incrementally.',
    parameters: {
      path: { type: 'string', description: 'Optional absolute path to the Login Data file; defaults to the current Chrome profile.' },
      localStatePath: { type: 'string', description: 'Windows only: absolute path to the browser Local State file (holds the DPAPI-wrapped key).' },
      profile: { type: 'string', description: 'Chrome profile directory name (default "Default"), e.g. "Profile 1". Ignored when path is set.' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same origin+username (default false = incremental).' },
      dryRun: { type: 'boolean', description: 'Preview what would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `added ${v.added}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_chrome')
      const s = await guardStore()
      const profile = typeof args.profile === 'string' && args.profile.trim().length > 0 ? args.profile.trim() : 'Default'
      const dbPath = args.path ?? defaultChromeLoginData('chrome', profile)
      const creds = readChromeLogins(dbPath, args.localStatePath)
      let added = 0
      let skipped = 0
      let updated = 0
      for (const c of creds) {
        let title = c.origin
        try { title = new URL(c.origin).hostname || c.origin } catch { /* keep origin as title */ }
        const existing = s.list().find(e => e.title === title && e.username === c.username)
        if (existing && args.overwrite !== true) { skipped++; continue }
        const patch: VaultEntryPatch = { username: c.username, password: c.password, url: c.origin }
        if (args.dryRun === true) {
          if (existing) updated++
          else added++
        } else if (existing) { await s.update(existing.id, patch); updated++ }
        else { await s.add({ title, ...patch }); added++ }
      }
      return { added, skipped, updated, note: `Chrome import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
    },
  }))

  // ── vault_import_keychain: import internet/generic passwords from the macOS keychain ─
  ctx.tools.register(defineTool({
    name: 'vault_import_keychain',
    description: 'Import passwords from the macOS login keychain via the security CLI. '
      + 'By default only internet-password entries (class "inet" — the ones that actually back website '
      + 'logins, with a server/account/protocol) are read; pass classes=["genp"] to read generic '
      + 'passwords (Wi-Fi, app secrets, …) instead. System entries (com.apple.*, iCloud, Wi-Fi, …) are '
      + 'filtered out; fetched entries are cached for the session so the same one is never re-requested. '
      + 'The FIRST fetch of each entry can prompt the macOS keychain authorization — choose "Always '
      + 'Allow" there to consent once for this process. Use preview to list what would be imported '
      + 'without fetching any passwords.',
    parameters: {
      limit: { type: 'integer', description: 'Max entries to fetch (default 10, 1–200).' },
      minLength: { type: 'integer', description: 'Skip passwords shorter than this (default 4).' },
      overwrite: { type: 'boolean', description: 'Update existing entries (default false = incremental).' },
      preview: { type: 'boolean', description: 'Only list the matching entries (no password fetches, no dialogs).' },
      service: { type: 'string', description: 'Only import entries whose service name contains this (case-insensitive).' },
      classes: { type: 'array', items: { type: 'string' }, description: 'Entry classes to read (default ["inet"]; pass ["genp"] for generic passwords, or both).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `added ${v.added}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_keychain')
      const s = await guardStore()
      const limit = args.limit === undefined ? 10 : args.limit
      if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw new Error('vault_import_keychain: limit must be an integer 1–200')
      const rawClasses = Array.isArray(args.classes) ? args.classes.filter((c): c is string => typeof c === 'string') : []
      const classes = rawClasses.length === 0
        ? ['inet']
        : rawClasses.filter(c => c === 'inet' || c === 'genp')
      if (classes.length === 0) throw new Error('vault_import_keychain: classes must be "inet" and/or "genp"')
      const serviceFilter = typeof args.service === 'string' ? args.service.trim().toLowerCase() : ''
      const filterEntries = <T extends { service: string }>(entries: T[]): T[] =>
        serviceFilter.length === 0 ? entries : entries.filter(e => e.service.toLowerCase().includes(serviceFilter))
      if (args.preview === true) {
        const entries = filterEntries(listKeychainEntries(limit * 2, classes as Array<'inet' | 'genp'>)).slice(0, limit)
        return { added: 0, skipped: 0, updated: 0, note: `keychain preview: ${entries.length} matching entry/ies (${classes.join('+')}) — run without preview to import. WARNING: macOS will prompt for authorization once per entry; in the FIRST dialog choose "Always Allow" so this session is not asked again.` }
      }
      const minLength = args.minLength ?? 4
      const allCreds = readKeychainPasswords(limit * 2, minLength, classes as Array<'inet' | 'genp'>)
      const creds = serviceFilter.length === 0 ? allCreds.slice(0, limit) : allCreds.filter(c => c.service.toLowerCase().includes(serviceFilter)).slice(0, limit)
      let added = 0
      let skipped = 0
      let updated = 0
      for (const c of creds) {
        const title = c.class === 'inet' ? `${c.service} (${c.account})` : c.service
        const existing = s.list().find(e => e.title === title)
        if (existing && args.overwrite !== true) { skipped++; continue }
        const patch: VaultEntryPatch = {
          username: c.account,
          password: c.password,
          ...(c.class === 'inet' ? { host: c.service } : {}),
          ...(c.class === 'inet' && c.protocol !== undefined ? { url: `https://${c.service}` } : {}),
          notes: `imported from macOS keychain (${c.class})`,
        }
        if (existing) { await s.update(existing.id, patch); updated++ }
        else { await s.add({ title, ...patch }); added++ }
      }
      return { added, skipped, updated, note: `Keychain import (${classes.join('+')}): ${added} added, ${updated} updated, ${skipped} skipped` }
    },
  }))

  // ── vault_session_open: open a headed browser login session ──────────────
  ctx.tools.register(defineTool({
    name: 'vault_session_open',
    description: 'Open a real browser window at the given URL so the user can log in manually '
      + '(password, 2FA, captcha, …). The session stays open until vault_session_collect or '
      + 'vault_session_close is called. After the user finishes logging in, call '
      + 'vault_session_collect with the returned sessionId to save the session cookies into the vault '
      + '— including HttpOnly session cookies, which a page script can never read. '
      + 'This is the portable way to capture login state for sites that block embedding. '
      + 'Requires playwright-core and a Chromium build (the standard Playwright cache or a system browser). '
      + 'Pass headless: true for automation (no visible window — use only when no human login is needed).',
    parameters: {
      url: { type: 'string', required: true, description: 'Site to open, e.g. "https://example.com/login" (https:// is added when missing).' },
      headless: { type: 'boolean', description: 'Open without a visible window (automation only; default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { sessionId: { type: 'string', required: true }, url: { type: 'string', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: `login session opened at ${v.url} — sessionId ${v.sessionId}. Have the user log in, then call vault_session_collect.` }] },
    async execute(args) {
      assertWritable('vault_session_open')
      const session = await openSession(args.url, { headless: args.headless === true })
      return { sessionId: session.id, url: session.url, note: args.headless === true ? `Headless session opened at ${session.url}.` : `Browser window opened at ${session.url}. Ask the user to log in, then collect the session cookies.` }
    },
  }))

  // ── vault_session_collect: save a browser session's cookies into the vault ─
  ctx.tools.register(defineTool({
    name: 'vault_session_collect',
    description: 'Collect the cookies of a browser login session (opened with vault_session_open) and '
      + 'save them into the vault as a "cookie" entry under the given title. By default only cookies '
      + 'relevant to the session URL (or the url you pass) are collected — pass a url to restrict to '
      + 'that site, or collectAll: true to grab every cookie in the browser context. The browser window '
      + 'stays open (call vault_session_close when done, or open another).',
    parameters: {
      sessionId: { type: 'string', required: true, description: 'Session id returned by vault_session_open.' },
      title: { type: 'string', required: true, description: 'Vault entry title, e.g. "GitHub session".' },
      url: { type: 'string', description: 'Site URL to filter cookies by (defaults to the session URL).' },
      collectAll: { type: 'boolean', description: 'Collect every cookie in the browser context, not just the session URL domain (default false).' },
      overwrite: { type: 'boolean', description: 'Replace an existing entry with the same title (default false = incremental).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { saved: { type: 'integer', required: true }, id: { type: 'string', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: `saved ${v.saved} cookies as "${v.note}"` }] },
    async execute(args) {
      assertWritable('vault_session_collect')
      const s = await guardStore()
      const cookies = args.collectAll === true
        ? await collectSessionCookies(args.sessionId)
        : await collectSessionCookies(args.sessionId, typeof args.url === 'string' && args.url.trim().length > 0 ? args.url.trim() : undefined)
      const title = args.title.trim()
      if (title.length === 0) throw new Error('vault_session_collect: title is required')
      const url = typeof args.url === 'string' && args.url.trim().length > 0 ? args.url.trim() : undefined
      const existing = s.list().find(e => e.title === title)
      const patch: VaultEntryPatch = {
        kind: 'cookie',
        ...(url !== undefined ? { url } : {}),
        cookies,
        notes: `collected from browser login session (${cookies.length} cookies, ${new Date().toISOString()})`,
      }
      if (existing && args.overwrite !== true) throw new Error(`vault_session_collect: entry "${title}" already exists — pass overwrite: true to replace it`)
      let id: string
      if (existing) { await s.update(existing.id, patch); id = existing.id }
      else { const entry = await s.add({ title, ...patch }); id = entry.id }
      return { saved: cookies.length, id, note: title }
    },
  }))

  // ── vault_session_close: close an open browser login session ──────────────
  ctx.tools.register(defineTool({
    name: 'vault_session_close',
    description: 'Close a browser login session opened with vault_session_open (closes the window). '
      + 'Collected cookies are already stored in the vault and are unaffected. Safe to call more than once.',
    parameters: {
      sessionId: { type: 'string', required: true, description: 'Session id returned by vault_session_open.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { closed: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.closed ? 'session closed' : 'session already closed' }] },
    async execute(args) {
      const before = openSessionCount()
      await closeSession(args.sessionId)
      return { closed: before > openSessionCount() }
    },
  }))

  // ── vault_session_list: list saved cookie entries ─────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_session_list',
    description: 'List saved browser login sessions (entries of kind "cookie") with their cookie counts '
      + 'and how many are expired — no cookie values are returned. Use vault_session_export to get a '
      + 'Cookie header or Netscape jar for a saved session (for curl/requests automation), '
      + 'vault_session_prune to drop expired cookies, or vault_get to read the full entry.',
    parameters: {
      query: { type: 'string', description: 'Optional text filter on title/url/domain.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { sessions: { type: 'array', required: true, items: { type: 'json' } }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `${v.count} session(s): ${(v.sessions as Array<{ title: string; cookieCount?: number; expiredCount?: number; expiringSoon?: number }>).map(s => `${s.title} (${s.cookieCount ?? 0} cookies${(s.expiredCount ?? 0) > 0 ? `, ${s.expiredCount} expired` : ''}${(s.expiringSoon ?? 0) > 0 ? `, ${s.expiringSoon} expiring soon` : ''})`).join(', ')}` }] },
    async execute(args) {
      const s = await guardStore()
      const needle = typeof args.query === 'string' ? args.query.trim().toLowerCase() : ''
      const sessions = s.list()
        .filter(e => e.kind === 'cookie')
        .filter(e => needle.length === 0 || e.title.toLowerCase().includes(needle) || (e.url ?? '').toLowerCase().includes(needle))
        .map(e => ({ id: e.id, title: e.title, ...(e.url !== undefined ? { url: e.url } : {}), cookieCount: e.cookies?.length ?? 0, expiredCount: e.cookies !== undefined ? countExpiredCookies(e.cookies) : 0, expiringSoon: e.cookies !== undefined ? countExpiringCookies(e.cookies) : 0, updatedAt: e.updatedAt }))
      return { sessions, count: sessions.length }
    },
  }))

  // ── vault_session_export: export a saved session as Cookie header / Netscape jar ─
  ctx.tools.register(defineTool({
    name: 'vault_session_export',
    description: 'Export a saved browser login session (kind "cookie") for automation: as a `Cookie` '
      + 'request-header value (format "header"), a Netscape cookie-jar file (format "netscape", '
      + 'compatible with curl -b / wget), raw JSON (format "json", the Playwright addCookies shape), '
      + 'or a ready-to-run Playwright snippet (format "playwright"). Returns the text plus the '
      + 'per-cookie details.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id of the saved session (see vault_session_list).' },
      format: { type: 'string', enum: ['header', 'netscape', 'json', 'playwright'], description: 'Export format (default header).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { text: { type: 'string', required: true }, cookieCount: { type: 'integer', required: true }, domains: { type: 'array', items: { type: 'string' } }, expiresAt: { type: 'integer' } } }, render: (_a, v) => [{ type: 'text', text: `${v.cookieCount} cookies —\n${v.text}` }] },
    async execute(args) {
      const s = await guardStore()
      const entry = s.get(args.id)
      if (!entry) throw new Error('vault_session_export: entry not found')
      if ((entry.kind ?? 'login') !== 'cookie' || !Array.isArray(entry.cookies)) {
        throw new Error('vault_session_export: entry is not a saved cookie session')
      }
      const format = args.format ?? 'header'
      const domains = [...new Set(entry.cookies.map(c => c.domain))]
      const expiries = entry.cookies.map(c => c.expires).filter(e => e >= 0)
      let text: string
      if (format === 'netscape') text = netscapeJar(entry.cookies)
      else if (format === 'json') text = JSON.stringify(entry.cookies, null, 2)
      else if (format === 'playwright') text = playwrightSnippet(entry.cookies)
      else text = cookieHeader(entry.cookies)
      return {
        text,
        cookieCount: entry.cookies.length,
        domains,
        ...(expiries.length > 0 ? { expiresAt: Math.max(...expiries) * 1000 } : {}),
      }
    },
  }))

  // ── vault_session_import: save cookies pasted as JSON/header text ─────────
  ctx.tools.register(defineTool({
    name: 'vault_session_import',
    description: 'Save browser session cookies directly from pasted text: a JSON array of '
      + '{name, value, domain, path?, expires?, httpOnly?, secure?, sameSite?} objects (the shape '
      + 'browser devtools export), or a raw `Cookie` header string ("name=value; name2=value2"). '
      + 'This is the no-browser alternative to vault_session_open + vault_session_collect: paste the '
      + 'cookies from an existing logged-in browser session. Saves them as a "cookie" entry.',
    parameters: {
      title: { type: 'string', required: true, description: 'Vault entry title, e.g. "GitHub session".' },
      cookies: { type: 'string', required: true, description: 'JSON array of cookie objects or a Cookie header string.' },
      url: { type: 'string', description: 'Site URL stored on the entry.' },
      overwrite: { type: 'boolean', description: 'Replace an existing entry with the same title (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { saved: { type: 'integer', required: true }, id: { type: 'string', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: `saved ${v.saved} cookies` }] },
    async execute(args) {
      assertWritable('vault_session_import')
      const s = await guardStore()
      const title = args.title.trim()
      if (title.length === 0) throw new Error('vault_session_import: title is required')
      const cookies = parsePastedCookies(args.cookies)
      if (cookies.length === 0) throw new Error('vault_session_import: no cookies parsed from the input')
      const url = typeof args.url === 'string' && args.url.trim().length > 0 ? args.url.trim() : undefined
      // Cookies parsed from a raw `Cookie` header carry no domain; derive one
      // from the entry URL so exports (Netscape jar / header) stay usable.
      if (url !== undefined) {
        const host = hostFromUrl(url)
        for (const c of cookies) {
          if (c.domain.length === 0 && host.length > 0) c.domain = host
        }
      }
      const existing = s.list().find(e => e.title === title)
      const patch: VaultEntryPatch = {
        kind: 'cookie',
        ...(url !== undefined ? { url } : {}),
        cookies,
        notes: `imported from pasted text (${cookies.length} cookies, ${new Date().toISOString()})`,
      }
      if (existing && args.overwrite !== true) throw new Error(`vault_session_import: entry "${title}" already exists — pass overwrite: true to replace it`)
      let id: string
      if (existing) { await s.update(existing.id, patch); id = existing.id }
      else { const entry = await s.add({ title, ...patch }); id = entry.id }
      return { saved: cookies.length, id, note: title }
    },
  }))

  // ── vault_session_import_file: import a Netscape cookie-jar file ──────────
  ctx.tools.register(defineTool({
    name: 'vault_session_import_file',
    description: 'Save session cookies from a Netscape cookie-jar file (the format curl -b / wget '
      + 'and browser extensions export; the same format vault_session_export writes). Parses the '
      + 'tab-separated domain/path/expiry/httpOnly/secure columns and saves them as a "cookie" entry. '
      + 'The no-browser alternative to vault_session_open + vault_session_collect for jar exports.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the .txt/.jar cookie file.' },
      title: { type: 'string', required: true, description: 'Vault entry title, e.g. "GitHub session".' },
      url: { type: 'string', description: 'Site URL stored on the entry (optional).' },
      overwrite: { type: 'boolean', description: 'Replace an existing entry with the same title (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { saved: { type: 'integer', required: true }, id: { type: 'string', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: `saved ${v.saved} cookies` }] },
    async execute(args) {
      assertWritable('vault_session_import_file')
      const s = await guardStore()
      const title = args.title.trim()
      if (title.length === 0) throw new Error('vault_session_import_file: title is required')
      const raw = await readFile(args.path, 'utf8')
      const cookies = parseNetscapeJar(raw)
      if (cookies.length === 0) throw new Error('vault_session_import_file: no cookies parsed from the jar file')
      const url = typeof args.url === 'string' && args.url.trim().length > 0 ? args.url.trim() : undefined
      const existing = s.list().find(e => e.title === title)
      const patch: VaultEntryPatch = {
        kind: 'cookie',
        ...(url !== undefined ? { url } : {}),
        cookies,
        notes: `imported from cookie jar (${cookies.length} cookies, ${new Date().toISOString()})`,
      }
      if (existing && args.overwrite !== true) throw new Error(`vault_session_import_file: entry "${title}" already exists — pass overwrite: true to replace it`)
      let id: string
      if (existing) { await s.update(existing.id, patch); id = existing.id }
      else { const entry = await s.add({ title, ...patch }); id = entry.id }
      return { saved: cookies.length, id, note: title }
    },
  }))

  // ── vault_session_prune: remove expired cookies from a saved session ──────
  ctx.tools.register(defineTool({
    name: 'vault_session_prune',
    description: 'Remove expired cookies from a saved login session: cookies whose expiry time has '
      + 'passed are deleted (session cookies with expires <= 0 are always kept). Use preview: true to '
      + 'see how many would be pruned without modifying the entry. Useful before exporting a stale '
      + 'session to automation.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id of the saved session (see vault_session_list).' },
      preview: { type: 'boolean', description: 'Only report how many cookies would be pruned (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { pruned: { type: 'integer', required: true }, remaining: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `pruned ${v.pruned}, ${v.remaining} remaining` }] },
    async execute(args) {
      const s = await guardStore()
      const entry = s.get(args.id)
      if (!entry) throw new Error('vault_session_prune: entry not found')
      if ((entry.kind ?? 'login') !== 'cookie' || !Array.isArray(entry.cookies)) {
        throw new Error('vault_session_prune: entry is not a saved cookie session')
      }
      const expired = countExpiredCookies(entry.cookies)
      if (args.preview === true || expired === 0) {
        return { pruned: 0, remaining: entry.cookies.length, note: expired === 0 ? `no expired cookies (${entry.cookies.length} valid)` : `preview: ${expired} expired of ${entry.cookies.length} — run without preview to prune` }
      }
      const kept = pruneExpiredCookies(entry.cookies)
      const patch: VaultEntryPatch = {
        cookies: kept,
        notes: `pruned ${expired} expired cookies (${new Date().toISOString()})`,
      }
      await s.update(entry.id, patch)
      return { pruned: expired, remaining: kept.length, note: `pruned ${expired} expired cookies, ${kept.length} remaining` }
    },
  }))

  // ── vault_import_bitwarden: import a Bitwarden JSON export ─────────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_bitwarden',
    description: 'Import a Bitwarden (or Vaultwarden) JSON export: maps each item into a vault entry '
      + '(title, username/password, totp, notes, url, favorite, custom fields). Same-title entries are '
      + 'skipped unless overwrite is set. Returns added/skipped/updated counts.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the Bitwarden .json export.' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same title (default false).' },
          dryRun: { type: 'boolean', description: 'Preview what would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `imported ${v.added}, updated ${v.updated}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_bitwarden')
      const s = await guardStore()
      const raw = JSON.parse(await readFile(args.path, 'utf8')) as {
        items?: Array<{
          name?: string
          notes?: string | null
          favorite?: boolean
          type?: number
          login?: { username?: string; password?: string; totp?: string; uris?: Array<{ uri?: string }> } | null
          fields?: Array<{ name?: string; value?: string }> | null
        }>
      }
      const items = Array.isArray(raw.items) ? raw.items : []
      let added = 0
      let skipped = 0
      let updated = 0
      for (const item of items) {
        const title = (item.name ?? '').trim()
        if (!title) { skipped++; continue }
        const patch: VaultEntryPatch = {}
        if (item.type === 2) patch.kind = 'custom'
        const login = item.login
        if (login?.username !== undefined) patch.username = login.username
        if (login?.password !== undefined) patch.password = login.password
        if (login?.totp !== undefined) patch.otpSecret = login.totp
        const uri = login?.uris?.find(u => u.uri)?.uri
        if (uri !== undefined) patch.url = uri
        if (item.notes !== undefined && item.notes !== null) patch.notes = item.notes
        if (item.favorite === true) patch.favorite = true
        const fields: Record<string, string> = {}
        for (const f of item.fields ?? []) {
          if (f.name !== undefined && f.value !== undefined) fields[f.name] = f.value
        }
        // Promote known custom fields back onto the entry model.
        for (const key of ['host', 'port', 'apiKey', 'secret', 'accessToken', 'refreshToken', 'privateKey', 'expiresAt', 'rotationDays']) {
          if (fields[key] !== undefined) {
            ;(patch as unknown as Record<string, unknown>)[key] = key === 'port' || key === 'expiresAt' || key === 'rotationDays' ? Number(fields[key]) : fields[key]
            delete fields[key]
          }
        }
        if (Object.keys(fields).length > 0) patch.fields = fields
        const existing = s.list().find(e => e.title === title)
        if (existing && !args.overwrite) { skipped++; continue }
        if (existing && args.overwrite) {
          await s.update(existing.id, patch)
          updated++
          continue
        }
        await s.add({ title, ...patch })
        added++
      }
      return { added, skipped, updated }
    },
  }))

  // ── vault_import_bitwarden_encrypted: decrypt + import ────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_bitwarden_encrypted',
    description: 'Import a Bitwarden password-protected JSON export (File > Export > "Encrypted .json"). '
      + 'Derives the enc/mac keys from the passphrase per the official Bitwarden export scheme '
      + '(PBKDF2-SHA256 or Argon2id + HKDF-SHA256 expand), verifies encKeyValidation, decrypts the '
      + 'vault, then imports it as a normal Bitwarden JSON. Supports dryRun preview.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the encrypted Bitwarden .json export.' },
      password: { type: 'string', required: true, description: 'The export passphrase (the one chosen when creating the encrypted export).' },
      overwrite: { type: 'boolean', description: 'Update existing entries with the same title (default false = incremental).' },
      dryRun: { type: 'boolean', description: 'Preview what would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `added ${v.added}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_bitwarden_encrypted')
      const s = await guardStore()
      const raw = await readFile(args.path, 'utf8')
      const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
      const plain = decryptBitwardenExport(cleaned, args.password)
      const creds = readBitwardenJson(plain)
      let added = 0
      let skipped = 0
      let updated = 0
      for (const c of creds) {
        const title = c.title.trim()
        if (!title) { skipped++; continue }
        const existing = s.list().find(e => e.title === title)
        if (existing && args.overwrite !== true) { skipped++; continue }
        const patch: VaultEntryPatch = {
          ...(c.username.length > 0 ? { username: c.username } : {}),
          ...(c.password.length > 0 ? { password: c.password } : {}),
          ...(c.url.length > 0 ? { url: c.url } : {}),
          ...(c.notes.length > 0 ? { notes: c.notes } : {}),
          ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
          ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
          ...(c.favorite === true ? { favorite: true } : {}),
        }
        if (args.dryRun === true) {
          if (existing) updated++
          else added++
        } else if (existing) { await s.update(existing.id, patch); updated++ }
        else { await s.add({ title, ...patch }); added++ }
      }
      return { added, skipped, updated, note: `Bitwarden encrypted import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
    },
  }))

  // ── vault_export_bitwarden: Bitwarden-compatible JSON export ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_export_bitwarden',
    description: 'Export entries in the Bitwarden JSON format (encrypted:false) so they can be '
      + 'imported into Bitwarden, Vaultwarden, or other tools that accept that format. Contains '
      + 'plaintext secrets — write it to a protected file. Returns the output path and count.',
    parameters: { path: { type: 'string', required: true, description: 'Absolute output .json path.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `exported ${v.count} entries to ${v.path} — contains plaintext secrets; keep the file protected (mode 600)` }] },
    async execute(args) {
      assertWritable('vault_export_bitwarden')
      const s = await guardStore()
      const doc = buildBitwardenExport(s.list())
      await mkdir(dirname(args.path), { recursive: true, mode: 0o700 })
      await writeFile(args.path, doc, { mode: 0o600 })
      const items = JSON.parse(doc).items as unknown[]
      return { path: args.path, count: items.length }
    },
  }))

  // ── vault_export_1password: export as a 1Password 1PUX archive ───────────
  ctx.tools.register(defineTool({
    name: 'vault_export_1password',
    description: 'Export entries in the 1Password 1PUX format (a ZIP archive with export.data) so '
      + 'they can be imported into 1Password, 1Password-compatible tools, or re-imported here with '
      + 'vault_import_1password. Item categories map to 1Password types (login / credit card / API '
      + 'credential / server). Contains plaintext secrets — write it to a protected file. Returns '
      + 'the output path and count.',
    parameters: { path: { type: 'string', required: true, description: 'Absolute output .1pux path.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `exported ${v.count} entries to ${v.path} — contains plaintext secrets; keep the file protected (mode 600)` }] },
    async execute(args) {
      assertWritable('vault_export_1password')
      const s = await guardStore()
      const doc = buildOnePasswordPux(s.list())
      await mkdir(dirname(args.path), { recursive: true, mode: 0o700 })
      await writeFile(args.path, doc, { mode: 0o600 })
      return { path: args.path, count: s.list().length }
    },
  }))

  // ── vault_backups: list available encrypted backups ────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_backups',
    description: 'List available encrypted `vault-backup-*.json` files (newest first) with their '
      + 'absolute paths and timestamps. Use the returned path with vault_restore_backup to restore.',
    parameters: { limit: { type: 'number', description: 'Max results (default 20, max 100).' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { backups: { type: 'array', required: true, items: { type: 'json' } }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `${v.count} backup(s)` }] },
    async execute(args) {
      await guardStore()
      const dir = dirname(resolveVaultPath(config))
      const limit = validateLimit(args.limit, 'vault_backups')
      const found: JsonValue[] = []
      try {
        const entries = await readdir(dir)
        for (const entry of entries) {
          if (!isBackupFile(entry)) continue
          found.push({ path: join(dir, entry), at: backupSortKey(entry) })
        }
      } catch { /* no dir yet */ }
      found.sort((a, b) => Number((b as { at: number }).at) - Number((a as { at: number }).at))
      return { backups: found.slice(0, limit), count: found.length }
    },
  }))

  // ── vault_backup: one-shot backup with a timestamped filename ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_backup',
    description: 'Create a timestamped backup of the vault file (a copy of the on-disk encrypted '
      + 'document, not a plaintext export). The file is named `<vault>-backups-YYYY-MM-DD_HH-MM-SS.json` '
      + 'so the owning vault and date are visible in the name. Old backups beyond maxBackups (default '
      + '10) are pruned automatically (newest kept). Returns the backup path and retention stats.',
    parameters: {
      maxBackups: { type: 'integer', description: 'Keep at most this many backups (default 10, min 1).' },
      note: { type: 'string', description: 'Optional note returned with the backup (e.g. why it was taken).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, kept: { type: 'integer', required: true }, pruned: { type: 'integer', required: true }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: `backup written to ${v.path} (kept ${v.kept}, pruned ${v.pruned})${v.note !== undefined ? ' — ' + v.note : ''}` }] },
    async execute(args) {
      const s = await guardStore()
      const source = resolveVaultPath(config)
      const dir = dirname(source)
      const maxBackups = args.maxBackups === undefined ? (config.backupRetention ?? 10) : args.maxBackups
      if (!Number.isInteger(maxBackups) || maxBackups < 1 || maxBackups > 100) {
        throw new Error('vault_backup: maxBackups must be an integer 1–100')
      }
      const backup = join(dir, backupFileName(config.name ?? 'default'))
      const raw = await readFile(source, 'utf8')
      await mkdir(dir, { recursive: true, mode: 0o700 })
      await writeFile(backup, raw, { mode: 0o600 })
      // Retention: keep the newest maxBackups backup files. Prefer the file
      // mtime (true creation order — back-to-back backups can share a second),
      // falling back to the name when mtime is unavailable.
      let backups: string[] = []
      try {
        const names = await readdir(dir)
        backups = names.filter(n => isBackupFile(n))
          .map(n => join(dir, n))
          .sort((a, b) => {
            const ma = statSync(a).mtimeMs
            const mb = statSync(b).mtimeMs
            if (ma !== mb) return mb - ma
            return compareBackupNewest(basename(a), basename(b))
          })
      } catch {
        backups = []
      }
      backups = backups.filter(n => n !== backup)
      let pruned = 0
      for (const stale of backups.slice(maxBackups - 1)) {
        try { await unlink(stale); pruned++ } catch { /* best-effort */ }
      }
      void s
      return { path: backup, kept: Math.min(backups.length + 1, maxBackups), pruned, ...(typeof args.note === 'string' && args.note.length > 0 ? { note: args.note } : {}) }
    },
  }))

  // ── vault_import_csv: bulk import from a CSV file ───────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_csv',
    description: 'Bulk-import credentials from a CSV file. Expected columns (header row): '
      + 'title,username,password,url,email,phone,host,port,apiKey,secret,notes,tags,kind. '
      + 'Unknown columns become custom fields. Returns how many entries were added and skipped.',
    parameters: {
      path: { type: 'string', required: true, description: 'Absolute path of the CSV file.' },
      delimiter: { type: 'string', description: 'CSV delimiter (default ",").' },
      overwrite: { type: 'boolean', description: 'Replace entries with the same title (default false).' },
      dryRun: { type: 'boolean', description: 'Preview how many rows would be imported without writing (default false).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `imported ${v.added}, updated ${v.updated}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_csv')
      const s = await guardStore()
      const raw = await readFile(args.path, 'utf8')
      const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
      const rows = parseCsv(cleaned, args.delimiter ?? ',')
      if (rows.length === 0) return { added: 0, skipped: 0, updated: 0 }
      if (rows.length - 1 > 5000) {
        throw new Error(`vault_import_csv: ${rows.length - 1} rows exceeds the 5000-row safety limit — split the file`)
      }
      if (args.dryRun === true) {
        return { added: 0, skipped: 0, updated: 0, dryRun: true, note: `would import ${rows.length - 1} rows` }
      }
      const headers = rows[0]!.map(h => h.trim())
      const known = new Set(['title', 'username', 'password', 'url', 'email', 'phone', 'host', 'port',
        'apiKey', 'secret', 'accessToken', 'refreshToken', 'expiresAt', 'otpSecret', 'notes', 'tags',
        'kind', 'sensitivity', 'favorite', 'rotationDays', 'icon', 'color', 'privateKey'])
      let added = 0
      let skipped = 0
      let updated = 0
      const now = Date.now()
      for (let i = 1; i < rows.length; i++) {
        const row = rows[i]!
        if (row.every(cell => cell.trim() === '')) continue // blank line
        const record: Record<string, unknown> = { title: row[0] ?? '' }
        const fields: Record<string, string> = {}
        for (let c = 1; c < headers.length && c < row.length; c++) {
          const header = headers[c]!
          const value = row[c] ?? ''
          if (value === '') continue
          if (known.has(header)) {
            if (header === 'tags') record[header] = value.split(/[;,]/).map(t => t.trim()).filter(Boolean)
            else record[header] = value
          } else {
            fields[header] = value
          }
        }
        if (record.title === '') { skipped++; continue }
        const VALID_KINDS = new Set(['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'])
        if (record.kind !== undefined && (typeof record.kind !== 'string' || !VALID_KINDS.has(record.kind))) {
          skipped++
          continue // invalid kind: skip the row
        }
        if (record.sensitivity !== undefined && record.sensitivity !== 'normal' && record.sensitivity !== 'high') {
          delete record.sensitivity
        }
        // Restore boolean/numeric types for fields the CSV layer serialized as strings.
        if (typeof record.favorite === 'string') record.favorite = record.favorite.toLowerCase() === 'true'
        for (const numKey of ['expiresAt', 'rotationDays']) {
          if (typeof record[numKey] === 'string' && /^-?\d+$/.test(record[numKey] as string)) {
            const parsed = Number(record[numKey])
            if (!Number.isSafeInteger(parsed)) { skipped++; continue }
            record[numKey] = parsed
          }
        }
        if (Object.keys(fields).length > 0) record.fields = fields
        const title = record.title as string
        const recordKind = typeof record.kind === 'string' ? record.kind : 'login'
        // Dedupe on title + kind: the same title with a different kind is a
        // distinct entry (e.g. "prod" as ssh vs api-key).
        const existing = s.list().find(e => e.title === title && (e.kind ?? 'login') === recordKind)
        if (existing && !args.overwrite) {
          skipped++
          continue
        }
        if (existing && args.overwrite) {
          // overwrite: merge CSV fields into the existing entry instead of
          // inserting a duplicate. Empty CSV cells are ignored so a partial
          // row can never blank a credential.
          const patch = pickDefinedFromRecord(record)
          delete patch.title
          await s.update(existing.id, patch as VaultEntryPatch)
          updated++
          continue
        }
        const entry: VaultEntry = {
          id: randomUUID(),
          title,
          createdAt: now,
          updatedAt: now,
          ...pickDefinedFromRecord(record),
        }
        s.insertDirect(entry)
        added++
      }
      await s.persist()
      return { added, skipped, updated }
    },
  }))

  // ── vault_switch / vault_list: multi-vault navigation ───────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_list',
    description: 'List available vaults in the vault directory (one .json file per vault, excluding '
      + 'access/meta/export files). Marks the currently active one.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { vaults: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.vaults) }] },
    async execute() {
      const dir = dirname(resolveVaultPath(config))
      const names: string[] = []
      try {
        const entries = await readdir(dir)
        for (const entry of entries) {
          const m = /^(.*)\.json$/.exec(entry)
          if (!m) continue
          if (['access', 'meta'].includes(m[1]!) || m[1]!.startsWith('vault-export-') || isBackupFile(entry)) continue
          names.push(m[1]!)
        }
      } catch { /* dir may not exist yet */ }
      const active = currentVaultName ?? config.name
        ?? (config.path !== undefined ? basename(config.path).replace(/\.json$/, '') : undefined)
        ?? 'default'
      // Report each vault's entry count by opening it (same master password),
      // so a roster of junk/test vaults is easy to spot.
      const vaults = []
      for (const name of names.sort()) {
        try {
          const store = await sharedVaultStore(masterPassword, { name, path: join(dir, `${name}.json`) })
          vaults.push({ name, active: name === active, entries: store.list().length + store.listTrash().length })
        } catch {
          vaults.push({ name, active: name === active, entries: -1 })
        }
      }
      return { vaults }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_switch',
    description: 'Switch the active vault for this session. Future vault_* calls operate on the named '
      + 'vault (created on first use). Returns the newly active vault name.',
    parameters: { name: { type: 'string', required: true, description: 'Vault name (e.g. "work" or "personal").' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { active: { type: 'string', required: true }, vaults: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: `switched to vault "${v.active}"` }] },
    async execute(args) {
      const name = args.name.trim()
      if (name.length === 0) throw new Error('vault_switch: name must not be empty')
      if (!/^[a-zA-Z0-9._-]+$/.test(name)) throw new Error('vault_switch: name may contain only letters, digits, . _ -')
      currentVaultName = name
      // List known vaults (mirrors vault_list) so the caller sees the roster.
      let names: string[] = []
      try {
        const entries = await readdir(dirname(resolveVaultPath(config)))
        for (const entry of entries) {
          const m = /^(.*)\.json$/.exec(entry)
          if (!m) continue
          if (['access', 'meta'].includes(m[1]!) || m[1]!.startsWith('vault-export-') || isBackupFile(entry)) continue
          names.push(m[1]!)
        }
      } catch { /* no dir yet */ }
      return { active: name, vaults: names.sort().map(v => ({ name: v, active: v === name })) }
    },
  }))

  // ── vault_vault_rename: rename a named vault (file) ───────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_vault_rename',
    description: 'Rename a named vault: the vault file (and its access policy file, if any) is '
      + 'moved to the new name. The active session switches to the new name. Default vault "default" '
      + 'cannot be renamed. Returns the new name and the vault roster.',
    parameters: {
      from: { type: 'string', required: true, description: 'Current vault name (e.g. "work").' },
      to: { type: 'string', required: true, description: 'New vault name (e.g. "personal").' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { renamed: { type: 'boolean', required: true }, from: { type: 'string' }, to: { type: 'string' }, vaults: { type: 'array', items: { type: 'json' } }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `renamed vault "${v.from}" -> "${v.to}"` }] },
    async execute(args) {
      assertWritable('vault_vault_rename')
      const from = args.from.trim()
      const to = args.to.trim()
      if (!/^[a-zA-Z0-9._-]+$/.test(from) || !/^[a-zA-Z0-9._-]+$/.test(to)) {
        throw new Error('vault_vault_rename: names may contain only letters, digits, . _ -')
      }
      if (from === 'default') throw new Error('vault_vault_rename: the default vault cannot be renamed')
      if (from === to) return { renamed: false, from, to, note: 'source and target names are identical' }
      const dir = dirname(resolveVaultPath(config))
      const source = join(dir, `${from}.json`)
      const target = join(dir, `${to}.json`)
      if (await existsFile(source) === false) throw new Error(`vault_vault_rename: vault "${from}" not found`)
      if (await existsFile(target)) throw new Error(`vault_vault_rename: vault "${to}" already exists`)
      await renameFile(source, target)
      // Drop cached stores for both names so the next open reads the new file.
      sharedVaultStores.delete(`${target}\0${masterPassword}`)
      if (currentVaultName === from) currentVaultName = to
      const roster = await listVaultRoster(config)
      return { renamed: true, from, to, vaults: roster, note: `vault "${from}" renamed to "${to}"` }
    },
  }))

  // ── vault_vault_delete: delete a named vault (file) ───────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_vault_delete',
    description: 'Permanently delete a named vault and its access-policy file. The default vault '
      + 'cannot be deleted. Consider vault_backup first — deletion is irreversible. If the deleted '
      + 'vault is active, the session switches back to "default".',
    parameters: {
      name: { type: 'string', required: true, description: 'Vault name to delete (e.g. "work").' },
      confirm: { type: 'boolean', required: true, description: 'Must be true to confirm deletion.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { deleted: { type: 'boolean', required: true }, name: { type: 'string' }, active: { type: 'string' }, vaults: { type: 'array', items: { type: 'json' } }, note: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.note ?? `deleted vault "${v.name}"` }] },
    async execute(args) {
      assertWritable('vault_vault_delete')
      const name = args.name.trim()
      if (args.confirm !== true) throw new Error('vault_vault_delete: pass confirm: true to delete a vault')
      if (!/^[a-zA-Z0-9._-]+$/.test(name)) {
        throw new Error('vault_vault_delete: name may contain only letters, digits, . _ -')
      }
      if (name === 'default') throw new Error('vault_vault_delete: the default vault cannot be deleted')
      const dir = dirname(resolveVaultPath(config))
      const source = join(dir, `${name}.json`)
      if (await existsFile(source) === false) throw new Error(`vault_vault_delete: vault "${name}" not found`)
      await unlink(source)
      sharedVaultStores.delete(`${source}\0${masterPassword}`)
      if (currentVaultName === name) currentVaultName = 'default'
      const roster = await listVaultRoster(config)
      return { deleted: true, name, active: currentVaultName ?? 'default', vaults: roster, note: `vault "${name}" deleted` }
    },
  }))

  // ── vault_rekey: upgrade the scrypt KDF parameters in place ────────────────
  ctx.tools.register(defineTool({
    name: 'vault_rekey',
    description: 'Upgrade the vault encryption to fresh scrypt KDF parameters (higher cost) and '
      + 're-encrypt every entry in place. Safe to run periodically or after raising the vault '
      + 'cost expectations; the old document is replaced atomically. Returns the new cost parameter n.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { n: { type: 'integer', required: true }, backup: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: `vault re-keyed with scrypt N=${v.n} (backup: ${v.backup})` }] },
    async execute() {
      assertWritable('vault_rekey')
      const s = await guardStore()
      // Destructive operation: take an automatic encrypted backup first so a
      // failed re-key never strands the vault unrecoverable.
      const source = resolveVaultPath(config)
      const dir = dirname(source)
      const backup = join(dir, backupFileName(config.name ?? 'default'))
      const raw = await readFile(source, 'utf8')
      await mkdir(dir, { recursive: true, mode: 0o700 })
      await writeFile(backup, raw, { mode: 0o600 })
      const result = await s.rekey()
      return { ...result, backup }
    },
  }))

  // UI-facing Remote gateway: the browser Settings Vault page talks to these
  // methods through the /api RPC channel (loopback-trusted), bypassing the
  // model-tool layer entirely. Secrets are returned because the UI is the
  // user's own browser on their own machine; the RPC authority is
  // trusted-host/loopback (see packages/client/connection).
  ctx.plugin(VaultGateway, {
    masterPassword,
    ...(config.path !== undefined ? { path: config.path } : {}),
    ...(config.name !== undefined ? { name: config.name } : {}),
    accessPolicy: policy,
  })
}

/**
 * Remote gateway exposing vault CRUD/search to the browser Settings UI.
 * Registered as an ordinary Cordis plugin; the Typert gateway discovers its
 * `typertRemote` binding and `@Remote` methods at runtime (source-mode), so
 * no code generation is required for an independently distributed plugin.
 */
export class VaultGateway extends TypertRemoteService {
  static inject = ['tools']

  private readonly masterPassword: string
  private readonly vaultPath: string | undefined
  private readonly vaultName: string | undefined
  private readonly accessPolicy: AccessPolicy
  private readonly backupRetention: number
  private activeName: string | undefined
  private readonly genHistory: Array<{ password: string; at: number }> = []

  constructor(ctx: Context, config: Config & { accessPolicy?: AccessPolicy }) {
    super(ctx, 'vault')
    this.masterPassword = config.masterPassword ?? resolveMasterPassword(config)
    this.vaultPath = config.path
    this.vaultName = config.name
    this.activeName = config.name
    this.accessPolicy = config.accessPolicy ?? { mode: config.accessMode ?? 'ask', autoCapture: config.autoCapture ?? false }
    this.backupRetention = config.backupRetention ?? 10
  }

  private async ensureStore(): Promise<VaultStore> {
    return sharedVaultStore(this.masterPassword, {
      ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}),
      ...(this.activeName !== undefined ? { name: this.activeName } : {}),
    })
  }

  /** Ensure the store and refuse reads/writes while the vault is locked. */
  private async guardedStore(): Promise<VaultStore> {
    const store = await this.ensureStore()
    if (store.isLocked) {
      throw new Error('vault is locked — run vault_unlock first')
    }
    return store
  }

  /** Reject mutations when the vault is in readonly mode (UI surface). */
  private assertWritable(action: string): void {
    if (this.accessPolicy.mode === 'readonly') {
      throw new Error(`vault: ${action} is disabled in readonly mode (set accessMode to "ask" or "auto" to enable)`)
    }
  }

  /** Current access policy and capture preference, for the Settings UI. */
  @Remote('config')
  async config(): Promise<{ accessMode: AccessMode; autoCapture: boolean; autoLockSeconds: number }> {
    return {
      accessMode: this.accessPolicy.mode,
      autoCapture: this.accessPolicy.autoCapture,
      autoLockSeconds: this.accessPolicy.autoLockSeconds ?? 0,
    }
  }

  /** Switch the runtime access mode from the Settings UI and persist it. */
  @Remote('setAccessMode')
  async setAccessMode(mode: AccessMode): Promise<{ accessMode: AccessMode; autoCapture: boolean; autoLockSeconds: number }> {
    if (mode !== 'readonly' && mode !== 'ask' && mode !== 'auto') {
      throw new Error(`vault: invalid accessMode "${String(mode)}" (expected readonly, ask, or auto)`)
    }
    this.accessPolicy.mode = mode
    await this.persistPolicy()
    return { accessMode: this.accessPolicy.mode, autoCapture: this.accessPolicy.autoCapture, autoLockSeconds: this.accessPolicy.autoLockSeconds ?? 0 }
  }

  /** Toggle auto-capture (detect credentials in chat → offer to save) from
   * the Settings UI and persist it. */
  @Remote('setAutoCapture')
  async setAutoCapture(enabled: boolean): Promise<{ accessMode: AccessMode; autoCapture: boolean; autoLockSeconds: number }> {
    this.accessPolicy.autoCapture = Boolean(enabled)
    await this.persistPolicy()
    return { accessMode: this.accessPolicy.mode, autoCapture: this.accessPolicy.autoCapture, autoLockSeconds: this.accessPolicy.autoLockSeconds ?? 0 }
  }

  /** Current auto-lock idle timeout in seconds (0 = never) for the Settings UI. */
  @Remote('autoLock')
  async autoLock(): Promise<{ seconds: number }> {
    return { seconds: this.accessPolicy.autoLockSeconds ?? 0 }
  }

  /** Set the auto-lock idle timeout (seconds; 0 disables) from the Settings
   * UI, apply it to the shared store immediately, and persist it. */
  @Remote('setAutoLock')
  async setAutoLock(seconds: number): Promise<{ seconds: number }> {
    const n = Math.floor(Number(seconds))
    if (!Number.isFinite(n) || n < 0 || n > 24 * 60 * 60) {
      throw new Error(`vault: invalid auto-lock timeout "${String(seconds)}" (0–86400 seconds)`)
    }
    this.accessPolicy.autoLockSeconds = n
    await this.persistPolicy()
    const store = await this.ensureStore()
    store.setAutoLock(n > 0 ? n * 1000 : undefined)
    return { seconds: n }
  }

  /** Persist the current policy to `<vault dir>/access.json`. */
  private async persistPolicy(): Promise<void> {
    const file = accessPolicyFile({
      ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}),
      ...(this.vaultName !== undefined ? { name: this.vaultName } : {}),
    })
    await mkdir(dirname(file), { recursive: true, mode: 0o700 })
    await writeFile(file, JSON.stringify(this.accessPolicy, null, 2), { mode: 0o600 })
  }

  /** List every entry as a non-secret summary. */
  @Remote('list')
  async list(): Promise<{ entries: VaultEntrySummaryWire[] }> {
    const store = await this.guardedStore()
    return { entries: store.list().map(toSummary) }
  }

  /** List trashed (soft-deleted) entries as non-secret summaries. */
  @Remote('trash')
  async trash(): Promise<{ entries: VaultEntrySummaryWire[] }> {
    const store = await this.guardedStore()
    return { entries: store.listTrash().map(toSummary) }
  }

  /** Restore every trashed entry; returns how many were restored. */
  @Remote('undeleteAll')
  async undeleteAll(): Promise<{ restored: number }> {
    this.assertWritable('undeleteAll')
    const store = await this.guardedStore()
    let restored = 0
    for (const e of store.listTrash()) {
      if (await store.restore(e.id)) restored++
    }
    return { restored }
  }

  /** Restore a trashed entry (non-secret summary returned). */
  @Remote('restore')
  async restore(id: string): Promise<{ restored: boolean }> {
    this.assertWritable('restore')
    const store = await this.guardedStore()
    return { restored: await store.restore(id) }
  }

  /** Permanently remove a trashed (or active) entry from the Settings UI
   * ("empty trash" / individual purge). */
  @Remote('purge')
  async purge(id: string): Promise<{ purged: boolean }> {
    this.assertWritable('purge')
    const store = await this.guardedStore()
    return { purged: await store.purge(id) }
  }

  /** Days since last backup + backup count (no secrets). */
  @Remote('backup')
  async backup(maxBackups?: number): Promise<{ path: string; kept: number; pruned: number }> {
    const max = maxBackups ?? this.backupRetention
    const dir = dirname(this.vaultPath ?? defaultVaultPath(this.activeName))
    const source = this.vaultPath ?? defaultVaultPath(this.activeName)
    const backup = join(dir, backupFileName(this.activeName ?? 'default'))
    const raw = await readFile(source, 'utf8')
    await mkdir(dir, { recursive: true, mode: 0o700 })
    await writeFile(backup, raw, { mode: 0o600 })
    let total = 1
    let pruned = 0
    try {
      const names = (await readdir(dir)).filter(n => isBackupFile(n))
        .map(n => join(dir, n)).sort((a, b) => {
          const ma = statSync(a).mtimeMs
          const mb = statSync(b).mtimeMs
          return ma !== mb ? mb - ma : compareBackupNewest(basename(a), basename(b))
        })
      total = names.length
      for (const stale of names.filter(n => n !== backup).slice(max - 1)) {
        try { await unlink(stale); pruned++ } catch { /* best-effort */ }
      }
    } catch { /* no dir yet */ }
    return { path: backup, kept: Math.max(1, Math.min(total, max)), pruned }
  }

  @Remote('backupStatus')
  async backupStatus(): Promise<{ daysSinceBackup: number; backups: number }> {
    const dir = dirname(this.vaultPath ?? defaultVaultPath(this.activeName))
    const stamps: number[] = []
    try {
      const entries = await readdir(dir)
      for (const entry of entries) {
        if (!isBackupFile(entry)) continue
        const key = backupSortKey(entry)
        if (key > 0) stamps.push(key)
      }
    } catch { /* no dir yet */ }
    const last = stamps.length > 0 ? Math.max(...stamps) : 0
    const days = last > 0 ? Math.floor((Date.now() - last) / 86_400_000) : -1
    return { daysSinceBackup: days, backups: stamps.length }
  }

  /** Vault overview stats (no secrets). */
  @Remote('stats')
  async stats(): Promise<Record<string, unknown>> {
    const store = await this.guardedStore()
    return store.stats() as unknown as Record<string, unknown>
  }

  /** Most recently created entries (no secrets). */
  @Remote('recent')
  async recent(): Promise<{ entries: unknown[] }> {
    const store = await this.guardedStore()
    return { entries: store.recent(5) as unknown as unknown[] }
  }

  /** Recent mutation history (no secrets). */
  @Remote('history')
  async history(): Promise<{ events: unknown[] }> {
    const store = await this.guardedStore()
    return { events: store.getHistory().slice(0, 20) }
  }

  /** Rotation/expiry report (no secrets). */
  @Remote('rotation')
  async rotation(soonWindowDays?: number): Promise<{ entries: unknown[] }> {
    const store = await this.guardedStore()
    const window = soonWindowDays === undefined ? 7 : soonWindowDays
    return { entries: store.rotationReport(Date.now(), window) as unknown as unknown[] }
  }

  /** Health scan findings (no secrets). */
  @Remote('health')
  async health(): Promise<{ weak: unknown[]; reused: unknown[]; strength: { weak: number; fair: number; strong: number }; no2fa: unknown[]; httpSites: unknown[]; score: number; verdict: string }> {
    const store = await this.guardedStore()
    return store.health()
  }

  /** Watchtower per-entry risk analysis for the UI badges. */
  @Remote('watchtower')
  async watchtower(): Promise<Array<{ id: string; title: string; kind: string; flags: string[]; score: number; verdict: string; bits?: number }>> {
    const store = await this.guardedStore()
    return analyzeVault(store.list())
  }

  /** Watchtower-style breach scan for the UI (k-anonymity; offline fallback). */
  @Remote('breachCheck')
  async breachCheck(online?: boolean): Promise<{ checked: number; pwned: Array<{ id: string; title: string; count: number }>; weak: Array<{ id: string; title: string }>; offline: boolean; elapsedMs: number }> {
    const store = await this.guardedStore()
    const pwned: Array<{ id: string; title: string; count: number }> = []
    const weak: Array<{ id: string; title: string }> = []
    let offline = false
    let checked = 0
    for (const e of store.list()) {
      if (e.password === undefined) continue
      checked++
      const useOnline = online !== false
      const verdict = useOnline ? await checkPassword(e.password) : { breached: false, count: 0, source: 'local' as const }
      if (verdict.source !== 'hibp') offline = true
      if (verdict.breached && verdict.reason === 'pwned') pwned.push({ id: e.id, title: e.title, count: verdict.count })
      else if (verdict.breached && verdict.reason === 'weak') weak.push({ id: e.id, title: e.title })
    }
    return { checked, pwned, weak, offline, elapsedMs: 0 }
  }

  /** Duplicate groups count for the UI health badge (title+kind matches). */
  @Remote('duplicates')
  async duplicates(): Promise<{ groups: number }> {
    const store = await this.guardedStore()
    const byKey = new Map<string, unknown[]>()
    for (const e of store.list()) {
      const key = `${e.title.toLowerCase()}::${e.kind ?? 'login'}`
      const list = byKey.get(key) ?? []
      list.push(e)
      byKey.set(key, list)
    }
    return { groups: [...byKey.values()].filter(g => g.length > 1).length }
  }

  /** Duplicate groups with ids+titles for the UI cleanup panel (title+kind). */
  @Remote('duplicateGroups')
  async duplicateGroups(): Promise<Array<Array<{ id: string; title: string }>>> {
    const store = await this.guardedStore()
    const byKey = new Map<string, Array<{ id: string; title: string }>>()
    for (const e of store.list()) {
      const key = `${e.title.toLowerCase()}::${e.kind ?? 'login'}`
      const list = byKey.get(key) ?? []
      list.push({ id: e.id, title: e.title })
      byKey.set(key, list)
    }
    return [...byKey.values()].filter(g => g.length > 1)
  }

  /** Per-entry verification issues for the UI audit panel (no secrets). */
  @Remote('verifyAll')
  async verifyAll(): Promise<Array<{ id: string; title: string; issues: string[] }>> {
    const store = await this.guardedStore()
    const out: Array<{ id: string; title: string; issues: string[] }> = []
    for (const e of store.list()) {
      const issues: string[] = []
      if (e.port !== undefined && !/^\d{1,5}$/.test(String(e.port))) issues.push('port is not numeric')
      if (e.port !== undefined && /^\d{1,5}$/.test(String(e.port)) && Number(e.port) > 65535) issues.push('port out of range')
      if (e.expiresAt !== undefined && e.expiresAt < Date.now()) issues.push('expired')
      switch (e.kind ?? 'login') {
        case 'ssh':
          if (!e.host) issues.push('ssh: missing host')
          if (!e.password && !e.privateKey) issues.push('ssh: missing password/privateKey')
          break
        case 'api-key':
          if (!e.apiKey && !e.secret) issues.push('api-key: missing apiKey/secret')
          break
        case 'oauth':
          if (!e.accessToken) issues.push('oauth: missing accessToken')
          break
        case 'card':
          if (!e.cardNumber) issues.push('card: missing card number')
          if (!e.cardExpiry) issues.push('card: missing expiry')
          if (!e.cardCvv) issues.push('card: missing CVV')
          break
      }
      if (issues.length > 0) out.push({ id: e.id, title: e.title, issues })
    }
    return out
  }

  /** Generate a strong random password for the editor's password field. */
  @Remote('generatePassword')
  async generatePassword(options?: { length?: number; lowercase?: boolean; uppercase?: boolean; digits?: boolean; symbols?: boolean; excludeAmbiguous?: boolean; passphrase?: boolean; words?: number; separator?: string; wordDigits?: boolean }): Promise<{ password: string }> {
    let password: string
    if (options?.passphrase === true) {
      password = generatePassphrase({
        words: options.words ?? 4,
        separator: options.separator ?? '-',
        wordDigits: options.wordDigits ?? true,
      })
    } else {
      password = generatePassword({
        length: options?.length ?? 24,
        lowercase: options?.lowercase ?? true,
        uppercase: options?.uppercase ?? true,
        digits: options?.digits ?? true,
        symbols: options?.symbols ?? true,
        excludeAmbiguous: options?.excludeAmbiguous ?? false,
      })
    }
    this.genHistory.unshift({ password, at: Date.now() })
    if (this.genHistory.length > 10) this.genHistory.length = 10
    return { password }
  }

  /** List built-in + custom templates for the editor's template picker. */
  @Remote('templates')
  async templates(): Promise<Array<{ name: string; kind: string; fields: Record<string, string> }>> {
    const builtin = Object.entries(TEMPLATES).map(([kind, fields]) => ({ name: `builtin:${kind}`, kind, fields }))
    const tplPath = join(dirname(this.vaultPath ?? defaultVaultPath(this.activeName)), 'templates.json')
    let custom: Array<{ name: string; kind: string; fields: Record<string, string> }> = []
    try {
      custom = JSON.parse(await readFile(tplPath, 'utf8'))
    } catch { /* none yet */ }
    return [...builtin, ...custom]
  }

  /** Save the current form as a reusable template. */
  @Remote('saveTemplate')
  async saveTemplate(name: string, kind: string, fields: Record<string, string>): Promise<{ saved: boolean }> {
    const tplPath = join(dirname(this.vaultPath ?? defaultVaultPath(this.activeName)), 'templates.json')
    let custom: Array<{ name: string; kind: string; fields: Record<string, string> }> = []
    try {
      custom = JSON.parse(await readFile(tplPath, 'utf8'))
    } catch { /* none yet */ }
    custom = custom.filter(t => t.name !== name)
    custom.push({ name, kind, fields })
    await writeFile(tplPath, JSON.stringify(custom, null, 2), { mode: 0o600 })
    return { saved: true }
  }

  /** Search Chrome/Keychain for a keyword without exposing secrets. */
  @Remote('searchSystem')
  async searchSystem(query: string, source?: string, limit?: number): Promise<{ matches: Array<{ source: string; name: string; username: string }>; note: string }> {
    const needle = query.trim().toLowerCase()
    const max = limit ?? 20
    const src = source ?? 'all'
    const matches: Array<{ source: string; name: string; username: string }> = []
    if (src === 'chrome' || src === 'all') {
      try {
        const dbPath = defaultChromeLoginData('chrome', 'Default')
        const localState = defaultChromeLocalState('chrome')
        for (const c of readChromeLogins(dbPath, localState)) {
          let name = c.origin
          try { name = new URL(c.origin).hostname } catch { /* keep origin */ }
          if (name.toLowerCase().includes(needle)) {
            matches.push({ source: 'chrome', name, username: c.username })
            if (matches.length >= max) break
          }
        }
      } catch { /* skip */ }
    }
    if (src === 'keychain' || src === 'all') {
      try {
        for (const e of listKeychainEntries(max * 2)) {
          if (e.service.toLowerCase().includes(needle) || e.account.toLowerCase().includes(needle)) {
            matches.push({ source: 'keychain', name: e.service, username: e.account })
            if (matches.length >= max) break
          }
        }
      } catch { /* skip */ }
    }
    return { matches: matches.slice(0, max), note: 'system search (no passwords exposed)' }
  }

  /** Import Firefox profile passwords into the vault. */
  @Remote('importFirefox')
  async importFirefox(masterPassword?: string, overwrite?: boolean, dryRun?: boolean): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const dir = defaultFirefoxProfileDir()
    const creds = readFirefoxLogins(dir, masterPassword ?? '')
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      let title = c.origin
      try { title = new URL(c.origin).hostname || c.origin } catch { /* keep origin */ }
      const existing = store.list().find(e => e.title === title && e.username === c.username)
      if (existing && overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = { username: c.username, password: c.password, url: c.origin }
      if (dryRun === true) {
        if (existing) updated++
        else added++
      } else if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `Firefox import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
  }

  /** Import Chrome passwords (Login Data) into the vault. */
  @Remote('importChrome')
  async importChrome(overwrite?: boolean, dryRun?: boolean): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const dbPath = defaultChromeLoginData('chrome', 'Default')
    const localState = defaultChromeLocalState('chrome')
    const creds = readChromeLogins(dbPath, localState)
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      let title = c.origin
      try { title = new URL(c.origin).hostname || c.origin } catch { /* keep origin */ }
      const existing = store.list().find(e => e.title === title && e.username === c.username)
      if (existing && overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = { username: c.username, password: c.password, url: c.origin }
      if (dryRun === true) {
        if (existing) updated++
        else added++
      } else if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `Chrome import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
  }

  /** Import a 1Password 1PUX export file. */
  @Remote('import1password')
  async import1password(path: string, overwrite?: boolean, dryRun?: boolean): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const creds = readOnePasswordPux(await readFile(path))
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      const title = c.title.trim()
      if (!title) { skipped++; continue }
      const existing = store.list().find(e => e.title === title)
      if (existing && overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = {
        ...(c.username.length > 0 ? { username: c.username } : {}),
        ...(c.password.length > 0 ? { password: c.password } : {}),
        ...(c.url.length > 0 ? { url: c.url } : {}),
        ...(c.notes.length > 0 ? { notes: c.notes } : {}),
        ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
        ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
        ...(c.favorite === true ? { favorite: true } : {}),
      }
      if (dryRun === true) {
        if (existing) updated++
        else added++
      } else if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `1Password import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
  }

  /** Export the vault as a 1Password 1PUX archive (UI). */
  @Remote('export1pux')
  async export1pux(path: string): Promise<{ path: string; count: number }> {
    this.assertWritable('export1pux')
    const store = await this.guardedStore()
    const doc = buildOnePasswordPux(store.list())
    await mkdir(dirname(path), { recursive: true, mode: 0o700 })
    await writeFile(path, doc, { mode: 0o600 })
    return { path, count: store.list().length }
  }

  /** Export the vault as a Bitwarden JSON document (UI). */
  @Remote('exportBitwarden')
  async exportBitwarden(path: string): Promise<{ path: string; count: number }> {
    this.assertWritable('exportBitwarden')
    const store = await this.guardedStore()
    const doc = buildBitwardenExport(store.list())
    await mkdir(dirname(path), { recursive: true, mode: 0o700 })
    await writeFile(path, doc, { mode: 0o600 })
    const items = JSON.parse(doc).items as unknown[]
    return { path, count: items.length }
  }

  /** Import a password-manager CSV (Dashlane/NordPass/Keeper auto-detected). */
  @Remote('importManagerCsv')
  async importManagerCsv(path: string, overwrite?: boolean, dryRun?: boolean): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const raw = await readFile(path, 'utf8')
    const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
    const creds = readPasswordCsv(cleaned)
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      const title = c.title.trim()
      if (!title) { skipped++; continue }
      const existing = store.list().find(e => e.title === title)
      if (existing && overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = {
        ...(c.username.length > 0 ? { username: c.username } : {}),
        ...(c.password.length > 0 ? { password: c.password } : {}),
        ...(c.url.length > 0 ? { url: c.url } : {}),
        ...(c.notes.length > 0 ? { notes: c.notes } : {}),
        ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
        ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
        ...(c.favorite === true ? { favorite: true } : {}),
      }
      if (dryRun === true) {
        if (existing) updated++
        else added++
      } else if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `CSV import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
  }

  /** Import a legacy 1Password 1PIF export. */
  @Remote('import1pif')
  async import1pif(path: string, overwrite?: boolean, dryRun?: boolean): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const raw = await readFile(path, 'utf8')
    const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
    const creds = readOnePasswordPif(cleaned)
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      const title = c.title.trim()
      if (!title) { skipped++; continue }
      const existing = store.list().find(e => e.title === title)
      if (existing && overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = {
        ...(c.username.length > 0 ? { username: c.username } : {}),
        ...(c.password.length > 0 ? { password: c.password } : {}),
        ...(c.url.length > 0 ? { url: c.url } : {}),
        ...(c.notes.length > 0 ? { notes: c.notes } : {}),
        ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
        ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
        ...(c.favorite === true ? { favorite: true } : {}),
      }
      if (dryRun === true) {
        if (existing) updated++
        else added++
      } else if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `1Password 1PIF import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
  }

  /** Import a KeePass 2.x XML export. */
  @Remote('importKeePassXml')
  async importKeePassXml(path: string, overwrite?: boolean, dryRun?: boolean): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const raw = await readFile(path, 'utf8')
    const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
    const creds = readKeePassXml(cleaned)
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      const title = c.title.trim()
      if (!title) { skipped++; continue }
      const existing = store.list().find(e => e.title === title)
      if (existing && overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = {
        ...(c.username.length > 0 ? { username: c.username } : {}),
        ...(c.password.length > 0 ? { password: c.password } : {}),
        ...(c.url.length > 0 ? { url: c.url } : {}),
        ...(c.notes.length > 0 ? { notes: c.notes } : {}),
      }
      if (dryRun === true) {
        if (existing) updated++
        else added++
      } else if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `KeePass XML import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
  }

  /** Import a KeePass KDBX binary database (3.1/4.x, AES-KDF/Argon2). */
  @Remote('importKdbx')
  async importKdbx(path: string, password?: string, keyfile?: string, overwrite?: boolean, dryRun?: boolean): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const data = await readFile(path)
    let kdfNote = ''
    try {
      const info = describeKdbxKdf(data)
      if (info.kdf === 'argon2' && info.memoryKiB !== undefined && info.memoryKiB >= 65536) {
        const seconds = Math.round(info.memoryKiB / 65536 * 7)
        kdfNote = `; Argon2id ${(info.memoryKiB / 1024).toFixed(0)} MiB × ${info.iterations ?? '?'} iters (pure-JS) may take ~${seconds}s to derive — please wait`
      }
    } catch { /* best-effort */ }
    const keyfileData = keyfile !== undefined && keyfile.length > 0 ? await readFile(keyfile) : undefined
    const creds = readKdbx(data, password ?? '', keyfileData)
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      const title = c.title.trim()
      if (!title) { skipped++; continue }
      const existing = store.list().find(e => e.title === title)
      if (existing && overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = {
        ...(c.username.length > 0 ? { username: c.username } : {}),
        ...(c.password.length > 0 ? { password: c.password } : {}),
        ...(c.url.length > 0 ? { url: c.url } : {}),
        ...(c.notes.length > 0 ? { notes: c.notes } : {}),
      }
      if (dryRun === true) {
        if (existing) updated++
        else added++
      } else if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `KeePass KDBX import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)${kdfNote}` }
  }

  /** Import an Enpass JSON export. */
  @Remote('importEnpass')
  async importEnpass(path: string, overwrite?: boolean, dryRun?: boolean): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const raw = await readFile(path, 'utf8')
    const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
    const creds = readEnpassJson(cleaned)
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      const title = c.title.trim()
      if (!title) { skipped++; continue }
      const existing = store.list().find(e => e.title === title)
      if (existing && overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = {
        ...(c.username.length > 0 ? { username: c.username } : {}),
        ...(c.password.length > 0 ? { password: c.password } : {}),
        ...(c.url.length > 0 ? { url: c.url } : {}),
        ...(c.notes.length > 0 ? { notes: c.notes } : {}),
        ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
        ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
        ...(c.favorite === true ? { favorite: true } : {}),
      }
      if (dryRun === true) {
        if (existing) updated++
        else added++
      } else if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `Enpass import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
  }

  /** Import a Bitwarden JSON export. */
  @Remote('importBitwarden')
  async importBitwarden(path: string, overwrite?: boolean, dryRun?: boolean): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const raw = await readFile(path, 'utf8')
    const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
    const creds = readBitwardenJson(cleaned)
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      const title = c.title.trim()
      if (!title) { skipped++; continue }
      const existing = store.list().find(e => e.title === title)
      if (existing && overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = {
        ...(c.username.length > 0 ? { username: c.username } : {}),
        ...(c.password.length > 0 ? { password: c.password } : {}),
        ...(c.url.length > 0 ? { url: c.url } : {}),
        ...(c.notes.length > 0 ? { notes: c.notes } : {}),
        ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
        ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
        ...(c.favorite === true ? { favorite: true } : {}),
      }
      if (dryRun === true) {
        if (existing) updated++
        else added++
      } else if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `Bitwarden import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
  }

  /** Import a Bitwarden password-protected JSON export (decrypts it first). */
  @Remote('importBitwardenEncrypted')
  async importBitwardenEncrypted(path: string, password: string, overwrite?: boolean, dryRun?: boolean): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const raw = await readFile(path, 'utf8')
    const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
    const plain = decryptBitwardenExport(cleaned, password)
    const creds = readBitwardenJson(plain)
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      const title = c.title.trim()
      if (!title) { skipped++; continue }
      const existing = store.list().find(e => e.title === title)
      if (existing && overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = {
        ...(c.username.length > 0 ? { username: c.username } : {}),
        ...(c.password.length > 0 ? { password: c.password } : {}),
        ...(c.url.length > 0 ? { url: c.url } : {}),
        ...(c.notes.length > 0 ? { notes: c.notes } : {}),
        ...(c.otp !== undefined && c.otp.length > 0 ? { otpSecret: c.otp } : {}),
        ...(c.tags !== undefined && c.tags.length > 0 ? { tags: c.tags } : {}),
        ...(c.favorite === true ? { favorite: true } : {}),
      }
      if (dryRun === true) {
        if (existing) updated++
        else added++
      } else if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `Bitwarden encrypted import: ${added} added, ${updated} updated, ${skipped} skipped (${creds.length} read)` }
  }

  /** Preview or import macOS keychain entries (preview never prompts).
   * Internet passwords (class "inet") are read by default; pass
   * `classes: ["genp"]` for generic passwords. */
  @Remote('keychainImport')
  async keychainImport(options?: { limit?: number; overwrite?: boolean; preview?: boolean; classes?: Array<'inet' | 'genp'> }): Promise<{ added: number; skipped: number; updated: number; note: string }> {
    const store = await this.guardedStore()
    const limit = options?.limit ?? 10
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
      throw new Error('keychainImport: limit must be an integer 1–200')
    }
    const raw = Array.isArray(options?.classes) ? (options!.classes as string[]).filter(c => c === 'inet' || c === 'genp') : []
    const classes = raw.length === 0 ? ['inet'] : raw
    if (options?.preview === true) {
      const entries = listKeychainEntries(limit, classes as Array<'inet' | 'genp'>)
      return { added: 0, skipped: 0, updated: 0, note: `keychain preview: ${entries.length} matching (${classes.join('+')}) — run without preview to import (first fetch may prompt for authorization; choose "Always Allow")` }
    }
    const creds = readKeychainPasswords(limit, 4, classes as Array<'inet' | 'genp'>)
    let added = 0, skipped = 0, updated = 0
    for (const c of creds) {
      const title = c.class === 'inet' ? `${c.service} (${c.account})` : c.service
      const existing = store.list().find(e => e.title === title)
      if (existing && options?.overwrite !== true) { skipped++; continue }
      const patch: VaultEntryPatch = {
        username: c.account,
        password: c.password,
        ...(c.class === 'inet' ? { host: c.service } : {}),
        ...(c.class === 'inet' && c.protocol !== undefined ? { url: `https://${c.service}` } : {}),
        notes: `imported from macOS keychain (${c.class})`,
      }
      if (existing) { await store.update(existing.id, patch); updated++ }
      else { await store.add({ title, ...patch }); added++ }
    }
    return { added, skipped, updated, note: `keychain import (${classes.join('+')}): ${added} added, ${updated} updated, ${skipped} skipped` }
  }

  /** Estimate a password's strength for the editor's live meter. */
  @Remote('strength')
  async strength(password: string): Promise<{ score: number; verdict: string; feedback: string; bits: number }> {
    return estimateStrength(password)
  }

  /** Build an otpauth:// URI for an entry's stored TOTP secret (for other devices). */
  @Remote('totpUri')
  async totpUri(id: string): Promise<{ uri: string }> {
    const store = await this.guardedStore()
    const entry = store.get(id)
    if (!entry || entry.otpSecret === undefined) throw new Error('vault: entry has no otpSecret')
    const secret = entry.otpSecret
    if (secret.startsWith('otpauth://')) return { uri: secret }
    return { uri: `otpauth://totp/${encodeURIComponent(entry.title)}?secret=${secret}&issuer=dsh-vault` }
  }

  /** Last generated passwords (session-scoped, newest first) for the editor. */
  @Remote('generatorHistory')
  async generatorHistory(): Promise<Array<{ password: string; at: number }>> {
    return [...this.genHistory]
  }

  /** Generate a random username suggestion for the editor. */
  @Remote('generateUsername')
  async generateUsername(): Promise<{ username: string }> {
    return { username: generateUsername(2) }
  }

  /** List recent encrypted backups (timestamped files) for the UI. */
  @Remote('backups')
  async backups(limit: number): Promise<Array<{ path: string; at: number; vaultName: string }>> {
    const max = limit === undefined ? 5 : limit
    const dir = dirname(this.vaultPath ?? defaultVaultPath(this.activeName))
    const found: Array<{ path: string; at: number; vaultName: string }> = []
    try {
      const entries = await readdir(dir)
      for (const entry of entries) {
        if (!isBackupFile(entry)) continue
        found.push({ path: join(dir, entry), at: backupSortKey(entry), vaultName: backupVaultName(entry) })
      }
    } catch { /* no dir yet */ }
    return found.sort((a, b) => b.at - a.at).slice(0, max)
  }

  /** Delete one backup file permanently (default vault cannot be deleted, but
   * its backup files may be). */
  @Remote('deleteBackup')
  async deleteBackup(path: string): Promise<{ deleted: boolean; path: string }> {
    this.assertWritable('deleteBackup')
    const dir = dirname(this.vaultPath ?? defaultVaultPath(this.activeName))
    const target = join(dir, basename(path))
    if (!isBackupFile(basename(target))) {
      throw new Error('deleteBackup: not a vault backup file')
    }
    try {
      await unlink(target)
    } catch {
      throw new Error('deleteBackup: backup file not found')
    }
    return { deleted: true, path: target }
  }

  /** Restore the active vault from one of its encrypted backups. A safety
   * snapshot of the current state is written first, then the store reloads. */
  @Remote('restoreBackup')
  async restoreBackup(path: string, mode?: string, overwrite?: boolean): Promise<{ entries: number; safetyBackup: string; note: string; added?: number; skipped?: number; updated?: number }> {
    this.assertWritable('restoreBackup')
    await this.guardedStore()
    const config = {
      ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}),
      ...(this.activeName !== undefined ? { name: this.activeName } : {}),
    }
    if (mode !== 'replace') {
      const result = await mergeBackupIntoVault(this.masterPassword, config, path, overwrite === true, false)
      return { entries: result.entries, safetyBackup: '', note: result.note, added: result.added, skipped: result.skipped, updated: result.updated }
    }
    return restoreVaultFromBackup(this.masterPassword, config, path)
  }

  /** Lock the vault immediately (wipe the in-memory key); UI "lock" button. */
  @Remote('lock')
  async lock(): Promise<{ locked: boolean }> {
    const store = await this.ensureStore()
    if (!store.isLocked) store.lock()
    return { locked: store.isLocked }
  }

  /** Unlock the current vault (the gateway holds the master password). */
  @Remote('unlock')
  async unlock(): Promise<{ locked: boolean }> {
    const store = await this.ensureStore()
    if (store.isLocked) await store.unlock()
    return { locked: store.isLocked }
  }

  /** Generate a one-time recovery code (returns the plaintext once). */
  @Remote('recoveryCode')
  async recoveryCode(): Promise<{ code: string; note: string }> {
    this.assertWritable('recoveryCode')
    await this.guardedStore()
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    const bytes = randomBytes(32)
    let code = ''
    for (let i = 0; i < 32; i++) code += alphabet[bytes[i]! % alphabet.length]
    const hash = createHash('sha256').update(code).digest('hex')
    const meta = await readMeta({ ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}), ...(this.activeName !== undefined ? { name: this.activeName } : {}) })
    meta.recoveryHash = hash
    meta.recoveryIssuedAt = Date.now()
    await writeMeta({ ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}), ...(this.activeName !== undefined ? { name: this.activeName } : {}) }, meta)
    return { code, note: 'Shown only once. Only its hash is stored.' }
  }

  /** Verify a recovery code against the stored hash. */
  @Remote('verifyRecovery')
  async verifyRecovery(code: string): Promise<{ verified: boolean }> {
    const meta = await readMeta({ ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}), ...(this.activeName !== undefined ? { name: this.activeName } : {}) })
    if (meta.recoveryHash === undefined) return { verified: false }
    const hash = createHash('sha256').update(code.trim()).digest('hex')
    return { verified: hash === meta.recoveryHash }
  }

  /** Recovery-code status (set + issuedAt). */
  @Remote('recoveryStatus')
  async recoveryStatus(): Promise<{ set: boolean; issuedAt?: number }> {
    const meta = await readMeta({ ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}), ...(this.activeName !== undefined ? { name: this.activeName } : {}) })
    return { set: meta.recoveryHash !== undefined, ...(meta.recoveryIssuedAt !== undefined ? { issuedAt: meta.recoveryIssuedAt } : {}) }
  }

  /** Vault lock/entry status for the UI banner. */
  @Remote('status')
  async status(): Promise<{ locked: boolean; entries: number }> {
    const store = await this.ensureStore()
    return { locked: store.isLocked, entries: store.isLocked ? 0 : store.list().length }
  }

  /** Switch the active vault by name (same master password), then re-open. */
  @Remote('switchVault')
  async switchVault(name: string): Promise<{ switched: boolean; name: string }> {
    if (typeof name !== 'string' || name.trim().length === 0 || /[^A-Za-z0-9._-]/.test(name)) {
      throw new Error('vault: invalid vault name')
    }
    this.activeName = name.trim()
    await this.ensureStore()
    return { switched: true, name: this.activeName }
  }

  /** List available vault files (one .json per vault, excluding access/meta/exports). */
  @Remote('listVaults')
  async listVaults(): Promise<Array<{ name: string; active: boolean; entries?: number }>> {
    const dir = dirname(this.vaultPath ?? defaultVaultPath(this.activeName))
    const names: string[] = []
    try {
      const entries = await readdir(dir)
      for (const entry of entries) {
        const m = /^(.*)\.json$/.exec(entry)
        if (!m) continue
        if (['access', 'meta'].includes(m[1]!) || m[1]!.startsWith('vault-export-') || isBackupFile(entry)) continue
        names.push(m[1]!)
      }
    } catch { /* no dir yet */ }
    const out: Array<{ name: string; active: boolean; entries?: number }> = []
    for (const name of names.sort()) {
      try {
        const store = await sharedVaultStore(this.masterPassword, { name, path: join(dir, `${name}.json`) })
        out.push({ name, active: name === this.activeName, entries: store.list().length + store.listTrash().length })
      } catch {
        out.push({ name, active: name === this.activeName })
      }
    }
    return out
  }

  /** Tag inventory for the UI tag-management panel. */
  @Remote('tags')
  async tags(): Promise<Array<{ name: string; count: number }>> {
    const store = await this.guardedStore()
    const counts = new Map<string, number>()
    for (const e of store.list()) {
      for (const tag of e.tags ?? []) counts.set(tag, (counts.get(tag) ?? 0) + 1)
    }
    return [...counts.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
  }

  /** Rename a named vault (file + policy); the active session follows. */
  @Remote('vaultRename')
  async vaultRename(from: string, to: string): Promise<{ renamed: boolean; from?: string; to?: string; vaults: Array<{ name: string; active: boolean }>; note: string }> {
    this.assertWritable('vaultRename')
    if (!/^[a-zA-Z0-9._-]+$/.test(from) || !/^[a-zA-Z0-9._-]+$/.test(to)) {
      throw new Error('vaultRename: names may contain only letters, digits, . _ -')
    }
    if (from === 'default') throw new Error('vaultRename: the default vault cannot be renamed')
    if (from === to) {
      return { renamed: false, from, to, vaults: await listVaultRoster({ ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}) }, this.activeName), note: 'source and target names are identical' }
    }
    const dir = dirname(this.vaultPath ?? defaultVaultPath(this.activeName))
    const source = join(dir, `${from}.json`)
    const target = join(dir, `${to}.json`)
    if (!(await existsFile(source))) throw new Error(`vaultRename: vault "${from}" not found`)
    if (await existsFile(target)) throw new Error(`vaultRename: vault "${to}" already exists`)
    await renameFile(source, target)
    sharedVaultStores.delete(`${target}\0${this.masterPassword}`)
    if (this.activeName === from) this.activeName = to
    const vaults = await listVaultRoster({ ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}) }, this.activeName)
    return { renamed: true, from, to, vaults, note: `vault "${from}" renamed to "${to}"` }
  }

  /** Permanently delete a named vault (file + policy); active falls back to default. */
  @Remote('vaultDelete')
  async vaultDelete(name: string, confirm: boolean): Promise<{ deleted: boolean; name?: string; active: string; vaults: Array<{ name: string; active: boolean }>; note: string }> {
    this.assertWritable('vaultDelete')
    if (confirm !== true) throw new Error('vaultDelete: pass confirm: true to delete a vault')
    if (!/^[a-zA-Z0-9._-]+$/.test(name)) {
      throw new Error('vaultDelete: name may contain only letters, digits, . _ -')
    }
    if (name === 'default') throw new Error('vaultDelete: the default vault cannot be deleted')
    const dir = dirname(this.vaultPath ?? defaultVaultPath(this.activeName))
    const source = join(dir, `${name}.json`)
    if (!(await existsFile(source))) throw new Error(`vaultDelete: vault "${name}" not found`)
    await unlink(source)
    sharedVaultStores.delete(`${source}\0${this.masterPassword}`)
    if (this.activeName === name) this.activeName = 'default'
    const vaults = await listVaultRoster({ ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}) }, this.activeName)
    return { deleted: true, name, active: this.activeName ?? 'default', vaults, note: `vault "${name}" deleted` }
  }

  /** Rename a tag across every entry (Bitwarden-style tag merge). */
  @Remote('renameTag')
  async renameTag(from: string, to: string): Promise<{ renamed: number }> {
    const store = await this.guardedStore()
    let renamed = 0
    for (const e of store.list()) {
      const tags = e.tags ?? []
      if (!tags.includes(from)) continue
      const next = [...new Set([...tags.filter(t => t !== from), to])]
      await store.update(e.id, { tags: next })
      renamed++
    }
    return { renamed }
  }

  /** Mark an entry as recently used (touches updatedAt). */
  @Remote('touch')
  async touch(id: string): Promise<{ touched: boolean }> {
    const store = await this.guardedStore()
    const updated = await store.markUsed(id)
    return { touched: updated !== undefined }
  }

  /** Merge one entry into another (Bitwarden-style dedup); keepSource optional. */
  @Remote('merge')
  async merge(fromId: string, toId: string, keepSource?: boolean): Promise<{ found: boolean }> {
    const store = await this.guardedStore()
    const merged = await store.merge(fromId, toId, { keepSource: keepSource === true })
    return { found: merged !== undefined }
  }

  /** Read one full entry (including secrets) by id. */
  @Remote('get')
  async get(id: string): Promise<{ found: boolean; entry?: VaultEntryWire }> {
    const store = await this.guardedStore()
    const entry = store.get(id)
    if (entry === undefined) return { found: false }
    return { found: true, entry: toWire(entry) }
  }

  /** Search entries across text fields; returns non-secret summaries. */
  @Remote('search')
  async search(query: string, limit: number): Promise<{ entries: VaultEntrySummaryWire[] }> {
    const store = await this.guardedStore()
    return { entries: store.search(query, limit) }
  }

  /** Add a new entry; returns its id and summary. */
  @Remote('add')
  async add(patch: VaultEntryPatch & { title: string }): Promise<VaultEntrySummaryWire> {
    this.assertWritable('add')
    if (!patch.title.trim()) throw new Error('vault: title must not be empty')
    const store = await this.guardedStore()
    const entry = await store.add(patch)
    return toSummary(entry)
  }

  /** Update an existing entry's fields; returns the updated summary or not-found. */
  @Remote('update')
  async update(id: string, patch: VaultEntryPatch): Promise<{ found: boolean; entry?: VaultEntrySummaryWire }> {
    this.assertWritable('update')
    const store = await this.guardedStore()
    const updated = await store.update(id, patch)
    if (updated === undefined) return { found: false }
    return { found: true, entry: toSummary(updated) }
  }

  /** Delete an entry by id. */
  @Remote('delete')
  async delete(id: string): Promise<{ deleted: boolean }> {
    this.assertWritable('delete')
    const store = await this.guardedStore()
    return { deleted: await store.delete(id) }
  }

  /** Generate the current TOTP code for a stored otpSecret (or bare secret). */
  @Remote('totp')
  async totp(id?: string, secret?: string): Promise<{ code: string; label?: string; secondsRemaining: number }> {
    if ((id === undefined) === (secret === undefined)) {
      throw new Error('vault.totp: provide exactly one of id or secret')
    }
    let input: string
    let label: string | undefined
    if (id !== undefined) {
      const store = await this.guardedStore()
      const entry = store.get(id)
      if (entry?.otpSecret === undefined) throw new Error(`vault.totp: entry ${id} has no otpSecret`)
      input = entry.otpSecret
      label = entry.title
    } else {
      input = secret!
    }
    const nowMs = Date.now()
    return {
      code: totp(input, nowMs),
      ...(label !== undefined ? { label } : {}),
      secondsRemaining: 30 - (Math.floor(nowMs / 1000) % 30),
    }
  }

  /** Password history of an entry (newest first; current password excluded). */
  @Remote('passwordHistory')
  async passwordHistory(id: string): Promise<Array<{ password: string; at: number }>> {
    const store = await this.guardedStore()
    return store.passwordHistoryOf(id)
  }

  /** Roll the entry password back to a stored history entry. */
  @Remote('passwordRollback')
  async passwordRollback(id: string, at: number): Promise<{ rolledBack: boolean; password?: string }> {
    this.assertWritable('passwordRollback')
    const store = await this.guardedStore()
    const entry = store.get(id)
    if (!entry) return { rolledBack: false }
    const updated = await store.rollbackPassword(id, at)
    if (updated === undefined || updated.password === undefined) return { rolledBack: false }
    return { rolledBack: true, password: updated.password }
  }

  /** Open a headed browser login session; returns the session handle. */
  @Remote('sessionOpen')
  async sessionOpen(url: string): Promise<{ sessionId: string; url: string }> {
    this.assertWritable('sessionOpen')
    const session = await openSession(url)
    return { sessionId: session.id, url: session.url }
  }

  /** Collect the cookies of an open browser session (no vault write here —
   * the UI saves them via sessionSave). */
  @Remote('sessionCollect')
  async sessionCollect(sessionId: string, url?: string): Promise<{ cookies: CookieData[]; count: number }> {
    const cookies = await collectSessionCookies(sessionId, url)
    return { cookies, count: cookies.length }
  }

  /** Close a browser login session. */
  @Remote('sessionClose')
  async sessionClose(sessionId: string): Promise<{ closed: boolean }> {
    const before = openSessionCount()
    await closeSession(sessionId)
    return { closed: before > openSessionCount() }
  }

  /** List open browser sessions (no secrets). */
  @Remote('sessionListOpen')
  async sessionListOpen(): Promise<Array<{ sessionId: string; url: string; openedAt: number }>> {
    return listSessions().map(s => ({ sessionId: s.id, url: s.url, openedAt: s.openedAt }))
  }

  /** List saved cookie entries (no values). */
  @Remote('sessionListSaved')
  async sessionListSaved(): Promise<Array<{ id: string; title: string; url?: string; cookieCount: number; expiredCount: number; expiringSoon: number; updatedAt?: number }>> {
    const store = await this.guardedStore()
    return store.list()
      .filter(e => e.kind === 'cookie')
      .map(e => ({
        id: e.id,
        title: e.title,
        ...(e.url !== undefined ? { url: e.url } : {}),
        cookieCount: e.cookies?.length ?? 0,
        expiredCount: e.cookies !== undefined ? countExpiredCookies(e.cookies) : 0,
        expiringSoon: e.cookies !== undefined ? countExpiringCookies(e.cookies) : 0,
        ...(e.updatedAt !== undefined ? { updatedAt: e.updatedAt } : {}),
      }))
  }

  /** Save cookies (from a collected session or pasted text) as a cookie entry. */
  @Remote('sessionSave')
  async sessionSave(options: { title: string; cookies: CookieData[]; url?: string; overwrite?: boolean }): Promise<{ saved: number; id: string }> {
    this.assertWritable('sessionSave')
    const store = await this.guardedStore()
    const title = options.title.trim()
    if (title.length === 0) throw new Error('sessionSave: title is required')
    if (!Array.isArray(options.cookies) || options.cookies.length === 0) throw new Error('sessionSave: no cookies to save')
    const existing = store.list().find(e => e.title === title)
    if (existing && options.overwrite !== true) throw new Error(`sessionSave: entry "${title}" already exists — pass overwrite: true to replace it`)
    const patch: VaultEntryPatch = {
      kind: 'cookie',
      ...(typeof options.url === 'string' && options.url.trim().length > 0 ? { url: options.url.trim() } : {}),
      cookies: options.cookies,
      notes: `saved ${options.cookies.length} session cookies (${new Date().toISOString()})`,
    }
    if (existing) { await store.update(existing.id, patch); return { saved: options.cookies.length, id: existing.id } }
    const entry = await store.add({ title, ...patch })
    return { saved: options.cookies.length, id: entry.id }
  }

  /** Export a saved cookie entry as a Cookie header string (values included —
   * the UI copy button). */
  @Remote('sessionExport')
  async sessionExport(id: string, format?: 'header' | 'netscape' | 'json' | 'playwright'): Promise<{ text: string; cookieCount: number; domains: string[] }> {
    const store = await this.guardedStore()
    const entry = store.get(id)
    if (!entry) throw new Error('sessionExport: entry not found')
    if ((entry.kind ?? 'login') !== 'cookie' || !Array.isArray(entry.cookies)) {
      throw new Error('sessionExport: entry is not a saved cookie session')
    }
    const fmt = format ?? 'header'
    const text = fmt === 'netscape' ? netscapeJar(entry.cookies)
      : fmt === 'json' ? JSON.stringify(entry.cookies, null, 2)
      : fmt === 'playwright' ? playwrightSnippet(entry.cookies)
      : cookieHeader(entry.cookies)
    return { text, cookieCount: entry.cookies.length, domains: [...new Set(entry.cookies.map(c => c.domain))] }
  }

  /** Read the full cookie entry (values) for the UI detail view. */
  @Remote('sessionGet')
  async sessionGet(id: string): Promise<{ id: string; title: string; url?: string; cookies: CookieData[]; notes?: string }> {
    const store = await this.guardedStore()
    const entry = store.get(id)
    if (!entry) throw new Error('sessionGet: entry not found')
    if ((entry.kind ?? 'login') !== 'cookie' || !Array.isArray(entry.cookies)) {
      throw new Error('sessionGet: entry is not a saved cookie session')
    }
    return {
      id: entry.id,
      title: entry.title,
      ...(entry.url !== undefined ? { url: entry.url } : {}),
      cookies: entry.cookies,
      ...(entry.notes !== undefined ? { notes: entry.notes } : {}),
    }
  }

  /** Remove expired cookies from a saved session (preview keeps them). */
  @Remote('sessionPrune')
  async sessionPrune(id: string, preview?: boolean): Promise<{ pruned: number; remaining: number; note: string }> {
    this.assertWritable('sessionPrune')
    const store = await this.guardedStore()
    const entry = store.get(id)
    if (!entry) throw new Error('sessionPrune: entry not found')
    if ((entry.kind ?? 'login') !== 'cookie' || !Array.isArray(entry.cookies)) {
      throw new Error('sessionPrune: entry is not a saved cookie session')
    }
    const expired = countExpiredCookies(entry.cookies)
    if (preview === true || expired === 0) {
      return { pruned: 0, remaining: entry.cookies.length, note: expired === 0 ? `no expired cookies (${entry.cookies.length} valid)` : `preview: ${expired} expired of ${entry.cookies.length} — run without preview to prune` }
    }
    const kept = pruneExpiredCookies(entry.cookies)
    await store.update(entry.id, { cookies: kept, notes: `pruned ${expired} expired cookies (${new Date().toISOString()})` })
    return { pruned: expired, remaining: kept.length, note: `pruned ${expired} expired cookies, ${kept.length} remaining` }
  }
}

/** Wire-safe summary shape (non-secret fields only). */
export type VaultEntrySummaryWire = {
  id: string
  title: string
  sensitivity?: 'normal' | 'high'
  favorite?: boolean
  kind?: VaultEntryKind
  username?: string
  email?: string
  phone?: string
  host?: string
  port?: string
  url?: string
  tags?: string[]
  icon?: string
  color?: string
  cardExpiry?: string
  cardHolder?: string
  updatedAt?: number
}

/** Wire-safe full entry shape (secrets included; loopback UI only). */
export type VaultEntryWire = Omit<VaultEntry, 'createdAt' | 'updatedAt'>

/** Project a stored entry onto its wire summary. */
function toSummary(entry: VaultEntry | VaultEntrySummary): VaultEntrySummaryWire {
  return {
    id: entry.id,
    title: entry.title,
    ...(entry.updatedAt !== undefined ? { updatedAt: entry.updatedAt } : {}),
    ...(entry.sensitivity !== undefined ? { sensitivity: entry.sensitivity } : {}),
    ...(entry.favorite !== undefined ? { favorite: entry.favorite } : {}),
    ...(entry.icon !== undefined ? { icon: entry.icon } : {}),
    ...(entry.color !== undefined ? { color: entry.color } : {}),
    ...(entry.kind !== undefined ? { kind: entry.kind } : {}),
    ...(entry.username !== undefined ? { username: entry.username } : {}),
    ...(entry.email !== undefined ? { email: entry.email } : {}),
    ...(entry.phone !== undefined ? { phone: entry.phone } : {}),
    ...(entry.host !== undefined ? { host: entry.host } : {}),
    ...(entry.port !== undefined ? { port: entry.port } : {}),
    ...(entry.url !== undefined ? { url: entry.url } : {}),
    ...(entry.tags !== undefined ? { tags: entry.tags } : {}),
    ...(entry.cardExpiry !== undefined ? { cardExpiry: entry.cardExpiry } : {}),
    ...(entry.cardHolder !== undefined ? { cardHolder: entry.cardHolder } : {}),
  }
}

/** Project a stored entry onto its full wire shape (timestamps stripped). */
function toWire(entry: VaultEntry): VaultEntryWire {
  const { createdAt, updatedAt, ...rest } = entry
  return rest
}

/** Resolve the master password from config or the named environment variable. */
function resolveMasterPassword(config: Config): string {
  if (config.masterPasswordEnv !== undefined) {
    const fromEnv = process.env[config.masterPasswordEnv]
    if (fromEnv === undefined || fromEnv.length === 0) {
      throw new Error(`dsh-vault: environment variable ${config.masterPasswordEnv} is not set`)
    }
    return fromEnv
  }
  if (config.masterPassword !== undefined && config.masterPassword.length > 0) {
    return config.masterPassword
  }
  throw new Error('dsh-vault: configure masterPassword or masterPasswordEnv to unlock the vault')
}

/** Resolve the export/import password from the configured environment
 * variable, or fail loudly (the model must never pass it as an argument). */
function resolveExportPassword(config: Config): string {
  if (config.exportPasswordEnv !== undefined) {
    const fromEnv = process.env[config.exportPasswordEnv]
    if (fromEnv === undefined || fromEnv.length === 0) {
      throw new Error(`dsh-vault: environment variable ${config.exportPasswordEnv} is not set (needed for vault_export/import)`)
    }
    return fromEnv
  }
  throw new Error('dsh-vault: configure exportPasswordEnv to use vault_export / vault_import')
}

/**
 * Shared vault-store instances keyed by resolved path + master password. The
 * model tools and the UI-facing VaultGateway must observe ONE store so writes
 * through either surface are visible to the other immediately — two
 * independent `openVault()` calls would each cache their own snapshot and
 * drift apart. Keying on the password too keeps two deployments pointing at
 * the same file but configured with different master passwords from sharing
 * (and silently "unlocking") each other's store.
 */
const sharedVaultStores = new Map<string, Promise<VaultStore>>()

/** Runtime access policy shared between the model tools and the Settings UI.
 * The `mode` may be changed from the UI (`setAccessMode`); the value is
 * persisted to `<vault dir>/access.json` and restored on the next launch. */
export type AccessMode = 'readonly' | 'ask' | 'auto'

interface AccessPolicy {
  mode: AccessMode
  autoCapture: boolean
  /** Auto-lock idle timeout in seconds (0 = never); persisted with the policy. */
  autoLockSeconds?: number
}

const sharedAccessPolicies = new Map<string, AccessPolicy>()

/** Current vault-name override (vault_switch); undefined = use config name. */
let currentVaultName: string | undefined

/** Reset the session vault-switch override (tests). */
export function resetVaultSwitch(): void {
  currentVaultName = undefined
}


/** Resolve the canonical vault file path for a config (path override or name). */
function resolveVaultPath(config: Config): string {
  if (config.path !== undefined) return config.path
  return defaultVaultPath(currentVaultName ?? config.name)
}

/** The `<vault dir>/access.json` path holding the persisted access policy. */
function accessPolicyFile(config: Config): string {
  return join(dirname(resolveVaultPath(config)), 'access.json')
}

/** Read a persisted access policy, defaulting to the configured values. */
async function loadAccessPolicy(config: Config): Promise<AccessPolicy> {
  const fallback: AccessPolicy = { mode: config.accessMode ?? 'ask', autoCapture: config.autoCapture ?? false }
  const file = accessPolicyFile(config)
  try {
    const raw = await readFile(file, 'utf8')
    const parsed = JSON.parse(raw) as Partial<AccessPolicy>
    return {
      mode: parsed.mode === 'readonly' || parsed.mode === 'ask' || parsed.mode === 'auto' ? parsed.mode : fallback.mode,
      autoCapture: typeof parsed.autoCapture === 'boolean' ? parsed.autoCapture : fallback.autoCapture,
      ...(typeof parsed.autoLockSeconds === 'number' && Number.isFinite(parsed.autoLockSeconds) && parsed.autoLockSeconds >= 0
        ? { autoLockSeconds: parsed.autoLockSeconds }
        : {}),
    }
  } catch {
    return fallback
  }
}

/** Open (or reuse) the shared access policy for one vault path. */
async function sharedAccessPolicy(config: Config): Promise<AccessPolicy> {
  const path = resolveVaultPath(config)
  const existing = sharedAccessPolicies.get(path)
  if (existing !== undefined) return existing
  const policy = await loadAccessPolicy(config)
  sharedAccessPolicies.set(path, policy)
  return policy
}

/** Meta file: plaintext brute-force bookkeeping (no secrets). */
interface VaultMeta {
  failedAttempts: number
  lockedUntil?: number
  /** SHA-256 hash of the one-time recovery code (never the plaintext). */
  recoveryHash?: string
  /** Epoch millis when the recovery code was issued. */
  recoveryIssuedAt?: number
}

const MAX_ATTEMPTS = 5
const LOCKOUT_MS = 5 * 60 * 1000

/** `<vault dir>/meta.json` — failed-attempt counter and lockout window. */
function metaFile(config: Config): string {
  return join(dirname(resolveVaultPath(config)), 'meta.json')
}

async function readMeta(config: Config): Promise<VaultMeta> {
  try {
    const raw = await readFile(metaFile(config), 'utf8')
    return JSON.parse(raw) as VaultMeta
  } catch {
    return { failedAttempts: 0 }
  }
}

async function writeMeta(config: Config, meta: VaultMeta): Promise<void> {
  const file = metaFile(config)
  await mkdir(dirname(file), { recursive: true, mode: 0o700 })
  await writeFile(file, JSON.stringify(meta), { mode: 0o600 })
}

/** Record one failed unlock: increment the counter, start a lockout when the
 * threshold is crossed. */
async function recordFailedAttempt(config: Config): Promise<void> {
  const meta = await readMeta(config)
  meta.failedAttempts = (meta.failedAttempts ?? 0) + 1
  if (meta.failedAttempts >= MAX_ATTEMPTS) {
    meta.lockedUntil = Date.now() + LOCKOUT_MS
  }
  await writeMeta(config, meta)
}

/** Clear the counter after a successful unlock. */
async function clearFailedAttempts(config: Config): Promise<void> {
  await writeMeta(config, { failedAttempts: 0 })
}

/**
 * Open (or reuse) the vault store for one deployment configuration. All
 * callers within the process share the same instance for the same path and
 * master password, so a write via a model tool is immediately visible to the
 * Settings UI and vice versa.
 */
async function sharedVaultStore(masterPassword: string, config: Config): Promise<VaultStore> {
  const path = resolveVaultPath(config)
  // Brute-force guard: refuse to even attempt while a lockout window is open.
  const meta = await readMeta(config)
  if (meta.lockedUntil !== undefined && Date.now() < meta.lockedUntil) {
    const minutes = Math.ceil((meta.lockedUntil - Date.now()) / 60000)
    throw new Error(`vault is temporarily locked after ${MAX_ATTEMPTS} failed password attempts — retry in ~${minutes} min`)
  }
  // The master password is part of the identity: a different password must
  // open its own store (and fail authentication) rather than reuse a store
  // unlocked with another password.
  const cacheKey = `${path}\0${masterPassword}`
  const existing = sharedVaultStores.get(cacheKey)
  if (existing !== undefined) {
    // A successful re-open of a cached store clears the failure counter.
    await clearFailedAttempts(config)
    return existing
  }
  const opening = openVault({
    masterPassword,
    path,
  }).catch(async (error: unknown) => {
    // A failed open must not poison the cache for later retries, and counts
    // toward the brute-force lockout.
    sharedVaultStores.delete(cacheKey)
    await recordFailedAttempt(config)
    throw error
  })
  sharedVaultStores.set(cacheKey, opening)
  await clearFailedAttempts(config)
  return opening
}

/** Validate a model-supplied result limit: a positive integer capped at 100. */
function validateLimit(value: number | undefined, tool: string): number {
  if (value === undefined) return 20
  if (!Number.isInteger(value) || value < 1 || value > 100) {
    throw new Error(`${tool}: limit must be an integer between 1 and 100`)
  }
  return value
}

/** Add a `dryRun` flag to an import tool's parameters. */
function withDryRun<T extends Record<string, unknown>>(params: T, description = 'Preview what would be imported without writing anything (default false).'): T {
  return { ...params, dryRun: { type: 'boolean' as const, description } }
}

/** Extract the hostname from a URL (e.g. "https://github.com/login" → "github.com").
 * Returns '' when no host is present. */
function hostFromUrl(url: string): string {
  try {
    const u = new URL(url)
    return u.hostname
  } catch {
    const match = /^https?:\/\/([^/]+)/i.exec(url)
    return match !== null ? match[1]!.replace(/:\d+$/, '') : ''
  }
}

/** Build a ready-to-run Playwright snippet that injects the cookies into a
 * browser context (automation convenience): `await context.addCookies([...])`. */
function playwrightSnippet(cookies: CookieData[]): string {
  const rows = cookies.map((c) => {
    const parts: string[] = [
      `name: ${JSON.stringify(c.name)}`,
      `value: ${JSON.stringify(c.value)}`,
      `domain: ${JSON.stringify(c.domain)}`,
      `path: ${JSON.stringify(c.path || '/')}`,
      `expires: ${c.expires}`,
      `httpOnly: ${c.httpOnly}`,
      `secure: ${c.secure}`,
    ]
    if (c.sameSite !== undefined) parts.push(`sameSite: ${JSON.stringify(c.sameSite)}`)
    return `  { ${parts.join(', ')} }`
  })
  return `// Playwright session cookies (dsh-vault export)\n// Usage: await context.addCookies(COOKIES);\nconst COOKIES = [\n${rows.join(',\n')},\n];`
}

/** Parse pasted session cookies: a JSON array of cookie objects (devtools
 * export shape) or a raw `Cookie` header string ("a=1; b=2"). Returns a
 * normalized CookieData list, or throws when nothing usable is found. */
function parsePastedCookies(text: string): CookieData[] {
  const trimmed = text.trim()
  if (trimmed.length === 0) throw new Error('vault_session_import: input is empty')
  const out: CookieData[] = []
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    let parsed: unknown
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      throw new Error('vault_session_import: invalid JSON — expected an array of cookie objects or a Cookie header string')
    }
    const rows = Array.isArray(parsed) ? parsed : (typeof parsed === 'object' && parsed !== null ? [parsed] : [])
    for (const row of rows) {
      if (typeof row !== 'object' || row === null) continue
      const r = row as Record<string, unknown>
      if (typeof r.name !== 'string' || typeof r.value !== 'string' || typeof r.domain !== 'string') continue
      out.push({
        name: r.name,
        value: r.value,
        domain: r.domain,
        path: typeof r.path === 'string' ? r.path : '/',
        expires: typeof r.expires === 'number' ? r.expires : -1,
        httpOnly: r.httpOnly === true,
        secure: r.secure === true,
        ...(r.sameSite === 'Strict' || r.sameSite === 'Lax' || r.sameSite === 'None' ? { sameSite: r.sameSite } : {}),
      })
    }
  } else {
    // Cookie header: "name=value; name2=value2"
    for (const pair of trimmed.split(';')) {
      const eq = pair.indexOf('=')
      if (eq <= 0) continue
      const name = pair.slice(0, eq).trim()
      const value = pair.slice(eq + 1).trim()
      if (name.length === 0) continue
      out.push({ name, value, domain: '', path: '/', expires: -1, httpOnly: false, secure: false })
    }
  }
  return out
}

/** A summary view of an entry without timestamps or secrets (used by update output). */
function toSummaryJson(entry: VaultEntry | VaultEntrySummary): JsonValue {
  return toSummary(entry) as unknown as JsonValue
}

/** Strip timestamps from an entry for model-visible output (keeps secrets
 * when the caller asked for the full entry via vault_get). */

/** Build a Bitwarden card object from a dsh-vault card entry. Expiry is
 * parsed from `MM/YY` or `MM/YYYY`; card brand is inferred from the number. */
function buildBitwardenCard(e: VaultEntry): Record<string, unknown> {
  const card: Record<string, unknown> = {
    cardholderName: e.cardHolder ?? null,
    number: e.cardNumber ?? null,
    code: e.cardCvv ?? null,
    brand: inferCardBrand(e.cardNumber),
    expMonth: null,
    expYear: null,
  }
  const expiry = e.cardExpiry
  if (expiry !== undefined) {
    const m = /^(\d{1,2})\s*[/\-]\s*(\d{2}|\d{4})$/.exec(expiry.trim())
    if (m !== null) {
      card.expMonth = Number.parseInt(m[1]!, 10)
      const yy = m[2]!
      card.expYear = yy.length === 2 ? 2000 + Number.parseInt(yy, 10) : Number.parseInt(yy, 10)
    }
  }
  return card
}

/** Build the Bitwarden JSON export document (encrypted:false) from entries. */
function buildBitwardenExport(entries: VaultEntry[]): string {
  const items: unknown[] = []
  for (const e of entries) {
    const uris = e.url !== undefined ? [{ match: null, uri: e.url }] : null
    const login: Record<string, unknown> = {}
    if (e.username !== undefined) login.username = e.username
    if (e.email !== undefined && login.username === undefined) login.username = e.email
    if (e.password !== undefined) login.password = e.password
    if (e.otpSecret !== undefined) login.totp = e.otpSecret
    if (uris !== null) login.uris = uris
    const fields: Array<{ name: string; value: string; type: number }> = []
    for (const [k, v] of Object.entries(e.fields ?? {})) {
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
        fields.push({ name: k, value: String(v), type: 0 })
      }
    }
    if (e.host !== undefined) fields.push({ name: 'host', value: e.host, type: 0 })
    if (e.port !== undefined) fields.push({ name: 'port', value: String(e.port), type: 0 })
    if (e.apiKey !== undefined) fields.push({ name: 'apiKey', value: e.apiKey, type: 0 })
    if (e.secret !== undefined) fields.push({ name: 'secret', value: e.secret, type: 0 })
    if (e.accessToken !== undefined) fields.push({ name: 'accessToken', value: e.accessToken, type: 0 })
    if (e.refreshToken !== undefined) fields.push({ name: 'refreshToken', value: e.refreshToken, type: 0 })
    if (e.privateKey !== undefined) fields.push({ name: 'privateKey', value: e.privateKey, type: 0 })
    if (e.rotationDays !== undefined) fields.push({ name: 'rotationDays', value: String(e.rotationDays), type: 0 })
    if (e.expiresAt !== undefined) fields.push({ name: 'expiresAt', value: String(e.expiresAt), type: 0 })
    items.push({
      id: e.id,
      organizationId: null,
      folderId: null,
      type: (e.kind ?? 'login') === 'card' ? 3 : 1,
      reprompt: 0,
      name: e.title,
      notes: e.notes ?? null,
      favorite: e.favorite === true,
      ...((e.kind ?? 'login') === 'card' ? { card: buildBitwardenCard(e) } : {}),
      login: (e.kind ?? 'login') === 'card' ? {} : (Object.keys(login).length > 0 ? login : {}),
      fields: fields.length > 0 ? fields : null,
      collectionIds: null,
    })
  }
  return JSON.stringify({ encrypted: false, folders: [], items }, null, 2)
}

/** Heuristic card brand from the first digits (Visa/Mastercard/Amex/Discover). */
function inferCardBrand(number: string | undefined): string | null {
  if (number === undefined) return null
  const digits = number.replace(/[\s-]/g, '')
  if (/^4/.test(digits)) return 'Visa'
  if (/^5[1-5]/.test(digits)) return 'Mastercard'
  if (/^3[47]/.test(digits)) return 'Amex'
  if (/^6(?:011|5)/.test(digits)) return 'Discover'
  return null
}

/** Check a file exists (promise-friendly). */
async function existsFile(path: string): Promise<boolean> {
  try {
    await readFile(path)
    return true
  } catch {
    return false
  }
}

/** List the named vaults (one .json per vault) with an active flag. */
async function listVaultRoster(config: Config, activeName?: string): Promise<Array<{ name: string; active: boolean }>> {
  const dir = dirname(resolveVaultPath(config))
  const names: string[] = []
  try {
    const entries = await readdir(dir)
    for (const entry of entries) {
      const m = /^(.*)\.json$/.exec(entry)
      if (!m) continue
      if (['access', 'meta'].includes(m[1]!) || m[1]!.startsWith('vault-export-') || isBackupFile(entry)) continue
      names.push(m[1]!)
    }
  } catch { /* no dir yet */ }
  const active = activeName ?? currentVaultName
  return names.sort().map(name => ({ name, active: name === active }))
}

/** Format a backup filename: `<vault>-backups-YYYY-MM-DD_HH-MM-SS.json` so the
 * owning vault and the exact date are visible in the file name. Falls back to
 * the legacy `vault-backup-<epoch>` scheme for `default` (kept for
 * compatibility with existing files/tools). */
function backupFileName(vaultName: string, at = new Date()): string {
  const pad = (n: number): string => String(n).padStart(2, '0')
  const stamp = `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}_${pad(at.getHours())}-${pad(at.getMinutes())}-${pad(at.getSeconds())}`
  const safe = /^[A-Za-z0-9._-]+$/.test(vaultName) ? vaultName : 'vault'
  // Second-precision names can collide when backups are taken back-to-back,
  // so a short random suffix always follows the timestamp.
  return `${safe}-backups-${stamp}-${randomUUID().slice(0, 6)}.json`
}

/** Match either a new-style (`<name>-backups-<stamp>.json`) or legacy
 * (`vault-backup-<epoch>[-<hex>].json`) backup file name. Returns the matched
 * timestamp text (epoch for legacy, the `YYYY-MM-DD_HH-MM-SS` part for new). */
function backupStampMatch(name: string): string | null {
  const legacy = /^vault-backup-(\d+)(?:-[0-9a-f]{8})?\.json$/.exec(name)
  if (legacy !== null) return legacy[1]!
  const modern = /-backups-(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})(?:-[0-9a-f]{6})?\.json$/.exec(name)
  if (modern !== null) return modern[1]!
  return null
}

/** Whether a file name is one of our backup files. */
function isBackupFile(name: string): boolean {
  return backupStampMatch(name) !== null
}

/** The owning vault name of a backup file, parsed from its name
 * (`default-backups-...` → `default`); legacy `vault-backup-*` files predate
 * per-vault names and return an empty string. */
function backupVaultName(name: string): string {
  const modern = /^([^/]+?)-backups-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:-[0-9a-f]{6})?\.json$/.exec(name)
  if (modern !== null) return modern[1]!
  return ''
}

/** Extract a comparable sort key from a backup file name (epoch ms for legacy,
 * parsed date for new-style). Same-second new-style names share a key — callers
 * that need strict ordering use the filename (whose trailing random suffix
 * disambiguates back-to-back runs). */
function backupSortKey(name: string): number {
  const stamp = backupStampMatch(name)
  if (stamp === null) return 0
  if (/^\d+$/.test(stamp)) return Number(stamp)
  const parts = stamp.split('_')
  const date = parts[0]
  const time = parts[1]
  if (date === undefined || time === undefined) return 0
  const [y, mo, d] = date.split('-').map(Number)
  const [h, mi, s] = time.split('-').map(Number)
  return new Date(y!, mo! - 1, d, h, mi, s).getTime()
}

/** Compare two backup file names newest-first. New-style names embed a
 * sortable `YYYY-MM-DD_HH-MM-SS` stamp plus a trailing random suffix, so a
 * plain descending string comparison orders by time then by creation order. */
function compareBackupNewest(a: string, b: string): number {
  const ka = backupSortKey(a)
  const kb = backupSortKey(b)
  if (ka !== kb) return kb - ka
  return b.localeCompare(a) // same stamp: later random suffix sorts first
}

/** Restore the active vault from an encrypted backup file: validate the path
 * is one of our `*-backups-*` files, snapshot the current state as a new
 * backup first, then copy the backup over the live file and reload the shared
 * store so both the tools and the UI see the restored entries immediately. */
async function restoreVaultFromBackup(masterPassword: string, config: Config, backupPath: string): Promise<{ entries: number; safetyBackup: string; note: string }> {
  const target = resolveVaultPath(config)
  const backup = join(dirname(target), basename(backupPath))
  if (!isBackupFile(basename(backup))) {
    throw new Error('vault_restore_backup: not a vault backup file (expected <vault>-backups-<timestamp>.json)')
  }
  if (backup === target) throw new Error('vault_restore_backup: cannot restore the live vault file onto itself')
  const raw = await readFile(backup, 'utf8').catch(() => {
    throw new Error('vault_restore_backup: backup file not found')
  })
  // Safety snapshot of the current state before overwriting.
  const safety = join(dirname(target), backupFileName(config.name ?? 'default', new Date()).replace(/\.json$/, '-pre-restore.json'))
  const current = await readFile(target, 'utf8').catch(() => undefined)
  if (current !== undefined) {
    await writeFile(safety, current, { mode: 0o600 })
  }
  await writeFile(target, raw, { mode: 0o600 })
  // The restored file may use different KDF parameters (rare) — drop the
  // cached store instance so the next open derives fresh from disk.
  const cacheKey = `${target}\0${masterPassword}`
  sharedVaultStores.delete(cacheKey)
  const store = await sharedVaultStore(masterPassword, config)
  await clearFailedAttempts(config)
  return {
    entries: store.list().length,
    safetyBackup: current !== undefined ? safety : '',
    note: `vault restored from ${basename(backup)} (${store.list().length} entries)` + (current !== undefined ? `; pre-restore snapshot: ${basename(safety)}` : ''),
  }
}


/** Minimal RFC-4180-ish CSV parser: handles quoted fields with embedded
 * delimiters/newlines and escaped double quotes. Returns rows of fields. */
function parseCsv(input: string, delimiter = ','): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let field = ''
  let inQuotes = false
  let i = 0
  const pushField = () => { row.push(field); field = '' }
  const pushRow = () => { pushField(); rows.push(row); row = [] }
  while (i < input.length) {
    const ch = input[i]!
    if (inQuotes) {
      if (ch === '"') {
        if (input[i + 1] === '"') { field += '"'; i++ }
        else inQuotes = false
      } else {
        field += ch
      }
    } else if (ch === '"') {
      inQuotes = true
    } else if (ch === delimiter) {
      pushField()
    } else if (ch === '\n') {
      pushRow()
    } else if (ch === '\r') {
      if (input[i + 1] === '\n') i++
      pushRow()
    } else {
      field += ch
    }
    i++
  }
  if (field.length > 0 || row.length > 0) pushRow()
  return rows
}

/** Copy only defined non-empty record fields into a VaultEntry-shaped patch,
 * skipping the identity fields (title handled separately). */
function pickDefinedFromRecord(record: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  const identity = new Set(['id', 'createdAt', 'updatedAt', 'deletedAt'])
  for (const [key, value] of Object.entries(record)) {
    if (key === 'title' || identity.has(key)) continue
    if (value === undefined || value === '') continue
    if (Array.isArray(value) && value.length === 0) continue
    result[key] = value
  }
  return result
}



/** Zero-dependency password strength estimator: score 0–100 from length,
 * character-class coverage, and penalties for common weak patterns. */
function estimateStrength(password: string): { score: number; verdict: string; feedback: string; bits: number } {
  let score = 0
  const length = password.length
  // Length is the dominant factor.
  score += Math.min(45, length * 3)
  const classes = [
    /[a-z]/.test(password),
    /[A-Z]/.test(password),
    /[0-9]/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ].filter(Boolean).length
  score += classes * 8
  // Diversity bonus for longer unique characters.
  const unique = new Set(password).size
  score += Math.min(15, unique)
  // Penalties for common weak patterns.
  let feedback: string[] = []
  if (length < 8) feedback.push('too short (aim ≥ 12)')
  if (/^(password|123456|qwerty|letmein|admin|welcome|abc123)$/i.test(password)) { score -= 40; feedback.push('common password') }
  if (/(.)\1{2,}/.test(password)) { score -= 8; feedback.push('repeated characters') }
  if (/^\d+$/.test(password)) { score -= 15; feedback.push('digits only') }
  if (/^[a-z]+$/i.test(password)) { score -= 10; feedback.push('letters only') }
  if (password.length > 0 && new Set(password).size <= Math.max(3, Math.floor(length / 2))) feedback.push('low diversity')
  score = Math.max(0, Math.min(100, Math.round(score)))
  const verdict = score >= 80 ? 'very strong' : score >= 60 ? 'strong' : score >= 40 ? 'fair' : 'weak'
  // Entropy estimate in bits: log2(pool size) per character.
  let pool = 0
  if (/[a-z]/.test(password)) pool += 26
  if (/[A-Z]/.test(password)) pool += 26
  if (/[0-9]/.test(password)) pool += 10
  if (/[^A-Za-z0-9]/.test(password)) pool += 33
  const bits = password.length > 0 && pool > 0 ? Math.round(password.length * Math.log2(pool)) : 0
  return { score, verdict, feedback: feedback.length > 0 ? feedback.join('; ') : 'no obvious weaknesses', bits }
}


/** Quote a value for safe use in .env / shell export (single-quote, escaping
 * embedded single quotes the POSIX way). */
function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}


/** Generate a random username from adjective/noun syllables + digits. */
function generateUsername(parts: number): string {
  const syllables = ['orca', 'plover', 'ferret', 'manta', 'koala', 'panda', 'otter', 'lynx',
    'wren', 'quokka', 'tarsier', 'okapi', 'gecko', 'moose', 'heron', 'bison']
  const chosen: string[] = []
  for (let i = 0; i < parts; i++) {
    chosen.push(syllables[Math.floor(Math.random() * syllables.length)]!)
  }
  const digits = Math.floor(Math.random() * 9000) + 1000
  return chosen.join('_') + '_' + digits
}


/** TOTP with explicit period/digits. otpauth-URI-declared period/digits take
 * precedence (the URI is the authoritative provisioning contract); bare
 * secrets use the caller's explicit values. */
function totpWith(input: string, nowMs: number, period: number, digits: number): string {
  const parsed = parseTotpSecret(input)
  const effPeriod = parsed.periodSeconds === 30 && parsed.secret === input.trim() ? period : parsed.periodSeconds
  const effDigits = parsed.digits === 6 && parsed.secret === input.trim() ? digits : parsed.digits
  const key = base32Decode(parsed.secret)
  const counter = Math.floor(nowMs / 1000 / effPeriod)
  return hotp(key, counter, effDigits)
}


/** Accept tags as an array or a comma/semicolon-separated string. */

/** Compute env lines for env-flagged entries (optionally kind-filtered). */
async function envLines(store: VaultStore, kind?: string, ids?: string[], keyPrefix = ''): Promise<string[]> {
  const lines: string[] = []
  const seen = new Set<string>()
  const keyOf = (title: string, field: string): string => keyPrefix + title.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') + '_' + field.toUpperCase()
  for (const entry of store.list()) {
    if (kind !== undefined && (entry.kind ?? 'login') !== kind) continue
    if (ids !== undefined && ids.length > 0 && !ids.includes(entry.id)) continue
    if (!(entry.tags ?? []).includes('env')) continue
    for (const [field, value] of Object.entries(entry)) {
      if (typeof value !== 'string' || value.length === 0) continue
      if (['id', 'title', 'kind', 'sensitivity', 'favorite', 'host', 'url', 'notes', 'createdAt', 'updatedAt', 'deletedAt'].includes(field)) continue
      if (['username', 'email', 'phone', 'port', 'tags'].includes(field)) continue
      const key = keyOf(entry.title, field)
      if (seen.has(key)) continue // first entry wins; avoid duplicate exports
      seen.add(key)
      lines.push(`${key}=${shellQuote(value)}`)
    }
  }
  return lines
}

function normalizeTags(tags: unknown): string[] {
  if (Array.isArray(tags)) return tags.filter((t): t is string => typeof t === 'string')
  if (typeof tags === 'string') return tags.split(/[;,]/).map(t => t.trim()).filter(Boolean)
  return []
}


/** Remove empty-string entries from a fields map (caller-side hygiene). */
function cleanFieldsValue(fields: unknown): Record<string, unknown> | undefined {
  if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) return undefined
  const clean: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(fields as Record<string, unknown>)) {
    if (v === '') continue
    clean[k] = v as string | number | boolean | null
  }
  return clean
}

function stripTimestamps(entry: VaultEntry): JsonValue {
  const { createdAt, updatedAt, ...rest } = entry
  // Drop explicitly-empty fields so the model sees a clean structure.
  const clean: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(rest)) {
    if (value === undefined || value === '' || (Array.isArray(value) && value.length === 0)) continue
    clean[key] = value
  }
  return clean as unknown as JsonValue
}

/** Merge the entries of a backup file into the current vault. The backup is a
 * same-password encrypted copy of the vault document, so it opens with the
 * master password; its entries are added to the active vault, skipping titles
 * that already exist unless `overwrite` is set. This is the "restore as copy"
 * flow the UI offers — entries appear in the entries list instead of the whole
 * vault being replaced. Returns counts. */
async function mergeBackupIntoVault(masterPassword: string, config: Config, backupPath: string, overwrite = false, dryRun = false): Promise<{ added: number; skipped: number; updated: number; entries: number; note: string }> {
  const target = resolveVaultPath(config)
  const backup = join(dirname(target), basename(backupPath))
  if (!isBackupFile(basename(backup))) {
    throw new Error('vault_restore_backup: not a vault backup file (expected <vault>-backups-<timestamp>.json)')
  }
  const backupStore = await openVault({ masterPassword, path: backup, name: 'backup' }).catch(() => {
    throw new Error('vault_restore_backup: could not open the backup (wrong master password or corrupt file)')
  })
  const active = await sharedVaultStore(masterPassword, config)
  const sourceEntries = backupStore.list()
  let added = 0
  let updated = 0
  let skipped = 0
  for (const entry of sourceEntries) {
    const existing = active.list().find(e => e.title === entry.title)
    if (existing !== undefined) {
      if (!overwrite) { skipped++; continue }
      if (!dryRun) {
        const patch: VaultEntryPatch = { ...stripFieldsForPatch(entry) }
        await active.update(existing.id, patch)
      }
      updated++
      continue
    }
    if (!dryRun) {
      const patch = { ...stripFieldsForPatch(entry), title: entry.title }
      await active.add(patch)
    }
    added++
  }
  const total = active.list().length
  return {
    added,
    skipped,
    updated,
    entries: total,
    note: `restored from backup as merge: ${added} added, ${updated} updated, ${skipped} skipped (${total} entries total${dryRun ? ' — dry run, nothing written' : ''})`,
  }
}

/** Reduce a full entry to a patch (strip identity + timestamps, keep secrets). */
function stripFieldsForPatch(entry: VaultEntry): VaultEntryPatch {
  const patch: VaultEntryPatch = {
    ...(entry.kind !== undefined ? { kind: entry.kind } : {}),
    ...(entry.username !== undefined ? { username: entry.username } : {}),
    ...(entry.email !== undefined ? { email: entry.email } : {}),
    ...(entry.phone !== undefined ? { phone: entry.phone } : {}),
    ...(entry.password !== undefined ? { password: entry.password } : {}),
    ...(entry.host !== undefined ? { host: entry.host } : {}),
    ...(entry.port !== undefined ? { port: entry.port } : {}),
    ...(entry.privateKey !== undefined ? { privateKey: entry.privateKey } : {}),
    ...(entry.apiKey !== undefined ? { apiKey: entry.apiKey } : {}),
    ...(entry.secret !== undefined ? { secret: entry.secret } : {}),
    ...(entry.accessToken !== undefined ? { accessToken: entry.accessToken } : {}),
    ...(entry.refreshToken !== undefined ? { refreshToken: entry.refreshToken } : {}),
    ...(entry.expiresAt !== undefined ? { expiresAt: entry.expiresAt } : {}),
    ...(entry.otpSecret !== undefined ? { otpSecret: entry.otpSecret } : {}),
    ...(entry.cardNumber !== undefined ? { cardNumber: entry.cardNumber } : {}),
    ...(entry.cardExpiry !== undefined ? { cardExpiry: entry.cardExpiry } : {}),
    ...(entry.cardCvv !== undefined ? { cardCvv: entry.cardCvv } : {}),
    ...(entry.cardHolder !== undefined ? { cardHolder: entry.cardHolder } : {}),
    ...(entry.url !== undefined ? { url: entry.url } : {}),
    ...(entry.notes !== undefined ? { notes: entry.notes } : {}),
    ...(entry.tags !== undefined ? { tags: entry.tags } : {}),
    ...(entry.icon !== undefined ? { icon: entry.icon } : {}),
    ...(entry.color !== undefined ? { color: entry.color } : {}),
    ...(entry.sensitivity !== undefined ? { sensitivity: entry.sensitivity } : {}),
    ...(entry.favorite === true ? { favorite: true } : {}),
    ...(entry.rotationDays !== undefined ? { rotationDays: entry.rotationDays } : {}),
    ...(entry.fields !== undefined ? { fields: entry.fields } : {}),
    ...(entry.cookies !== undefined ? { cookies: entry.cookies } : {}),
    ...(entry.attachments !== undefined ? { attachments: entry.attachments } : {}),
  }
  return patch
}
