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
import { openVault, defaultVaultPath, type VaultEntry, type VaultEntryKind, type VaultEntryPatch, type VaultStore } from './store.ts'
import { totp } from './totp.ts'
import { generatePassword } from './password.ts'

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
}

export const Config: Schema<Config> = Schema.object({
  masterPassword: Schema.string(),
  masterPasswordEnv: Schema.string(),
  path: Schema.string(),
  name: Schema.string(),
})

export function apply(ctx: Context, config: Config): void {
  const masterPassword = resolveMasterPassword(config)

  /** Ensure the shared store is open (lazily on first use, so a missing
   * master password fails at the first tool call with a clear message). */
  async function ensureStore(): Promise<VaultStore> {
    return sharedVaultStore(masterPassword, config)
  }

  /** Read a full entry (with secrets) by id. */
  async function readEntry(id: string): Promise<VaultEntry | undefined> {
    const s = await ensureStore()
    return s.get(id)
  }

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
        description: 'Entry category: login (default), ssh, api-key, secret, oauth, or custom.',
        enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'],
      },
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
      url: { type: 'string', description: 'Associated URL (login page or service home).' },
      notes: { type: 'string', description: 'Free-form notes.' },
      tags: { type: 'array', description: 'Searchable tags.', items: { type: 'string' } },
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
      if (!args.title.trim()) throw new Error('vault_add: title must not be empty')
      const s = await ensureStore()
      const entry = await s.add({
        title: args.title.trim(),
        ...(args.kind !== undefined ? { kind: args.kind } : {}),
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
        ...(args.url !== undefined ? { url: args.url } : {}),
        ...(args.notes !== undefined ? { notes: args.notes } : {}),
        ...(args.tags !== undefined ? { tags: args.tags } : {}),
        ...(args.fields !== undefined ? { fields: args.fields } : {}),
      })
      return { id: entry.id, title: entry.title, message: 'added credential entry' }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_get',
    description: 'Read one credential entry from the vault by its id, including the stored password and TOTP secret. '
      + 'Secrets are returned only to this tool call; prefer vault_search for non-secret summaries.',
    parameters: {
      id: { type: 'string', required: true, description: 'The entry id returned by vault_add or vault_search.' },
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
      return { found: true, entry: stripTimestamps(entry) }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_search',
    description: 'Search the encrypted vault across titles, categories, usernames, emails, phone numbers, hosts, ports, '
      + 'URLs, notes, tags, and custom field values. '
      + 'Returns non-secret summaries (id, title, kind, username, email, phone, host, port, url, tags) — never passwords, '
      + 'keys, tokens, or TOTP secrets. Use vault_get with a result id to read the full entry.',
    parameters: {
      query: { type: 'string', required: true, description: 'Search text; matches case-insensitively.' },
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
      const s = await ensureStore()
      const limit = validateLimit(args.limit, 'vault_search')
      const results = s.search(args.query, limit)
      return { results, total: results.length }
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
        enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'],
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
      otpSecret: { type: 'string', description: 'New TOTP secret.' },
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
      const s = await ensureStore()
      const patch: VaultEntryPatch = {}
      for (const key of [
        'title', 'kind', 'username', 'email', 'phone', 'password', 'host', 'port', 'privateKey',
        'apiKey', 'secret', 'accessToken', 'refreshToken', 'expiresAt', 'otpSecret', 'url', 'notes', 'tags', 'fields',
      ] as const) {
        const value = args[key]
        if (value !== undefined) {
          ;(patch as Record<string, unknown>)[key] = value
        }
      }
      const updated = await s.update(args.id, patch)
      if (!updated) return { found: false }
      return { found: true, entry: toSummaryJson(updated) }
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
      const s = await ensureStore()
      const deleted = await s.delete(args.id)
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
      const code = totp(secret, nowMs)
      const secondsRemaining = 30 - Math.floor(nowMs / 1000) % 30
      return { code, ...(label !== undefined ? { label } : {}), secondsRemaining }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_generate_password',
    description: 'Generate a cryptographically strong random password with configurable length and character classes. '
      + 'Use this when a user needs a new password; the generated value is returned and is not stored automatically — '
      + 'call vault_add or vault_update to persist it.',
    parameters: {
      length: { type: 'integer', description: 'Total length (default 20, min = number of selected classes).' },
      lowercase: { type: 'boolean', description: 'Include lowercase (default true).' },
      uppercase: { type: 'boolean', description: 'Include uppercase (default true).' },
      digits: { type: 'boolean', description: 'Include digits (default true).' },
      symbols: { type: 'boolean', description: 'Include symbols (default true).' },
      excludeAmbiguous: { type: 'boolean', description: 'Exclude 0/O/1/l/I (default false).' },
      group: { type: 'integer', description: 'Insert "-" every N characters (e.g. 3 → vK7-mQ2-zt9).' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          password: { type: 'string', required: true },
          length: { type: 'integer', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.password }],
    },
    async execute(args) {
      const password = generatePassword({
        ...(args.length !== undefined ? { length: args.length } : {}),
        ...(args.lowercase !== undefined ? { lowercase: args.lowercase } : {}),
        ...(args.uppercase !== undefined ? { uppercase: args.uppercase } : {}),
        ...(args.digits !== undefined ? { digits: args.digits } : {}),
        ...(args.symbols !== undefined ? { symbols: args.symbols } : {}),
        ...(args.excludeAmbiguous !== undefined ? { excludeAmbiguous: args.excludeAmbiguous } : {}),
        ...(args.group !== undefined ? { group: args.group } : {}),
      })
      return { password, length: password.length }
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

  constructor(ctx: Context, config: Config) {
    super(ctx, 'vault')
    this.masterPassword = config.masterPassword ?? resolveMasterPassword(config)
    this.vaultPath = config.path
    this.vaultName = config.name
  }

  private async ensureStore(): Promise<VaultStore> {
    return sharedVaultStore(this.masterPassword, {
      ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}),
      ...(this.vaultName !== undefined ? { name: this.vaultName } : {}),
    })
  }

  /** List every entry as a non-secret summary. */
  @Remote('list')
  async list(): Promise<{ entries: VaultEntrySummaryWire[] }> {
    const store = await this.ensureStore()
    return { entries: store.list().map(toSummary) }
  }

  /** Read one full entry (including secrets) by id. */
  @Remote('get')
  async get(id: string): Promise<{ found: boolean; entry?: VaultEntryWire }> {
    const store = await this.ensureStore()
    const entry = store.get(id)
    if (entry === undefined) return { found: false }
    return { found: true, entry: toWire(entry) }
  }

  /** Search entries across text fields; returns non-secret summaries. */
  @Remote('search')
  async search(query: string, limit: number): Promise<{ entries: VaultEntrySummaryWire[] }> {
    const store = await this.ensureStore()
    return { entries: store.search(query, limit) }
  }

  /** Add a new entry; returns its id and summary. */
  @Remote('add')
  async add(patch: VaultEntryPatch & { title: string }): Promise<VaultEntrySummaryWire> {
    if (!patch.title.trim()) throw new Error('vault: title must not be empty')
    const store = await this.ensureStore()
    const entry = await store.add(patch)
    return toSummary(entry)
  }

  /** Update an existing entry's fields; returns the updated summary or not-found. */
  @Remote('update')
  async update(id: string, patch: VaultEntryPatch): Promise<{ found: boolean; entry?: VaultEntrySummaryWire }> {
    const store = await this.ensureStore()
    const updated = await store.update(id, patch)
    if (updated === undefined) return { found: false }
    return { found: true, entry: toSummary(updated) }
  }

  /** Delete an entry by id. */
  @Remote('delete')
  async delete(id: string): Promise<{ deleted: boolean }> {
    const store = await this.ensureStore()
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
      const store = await this.ensureStore()
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
}

/** Wire-safe summary shape (non-secret fields only). */
export type VaultEntrySummaryWire = {
  id: string
  title: string
  kind?: VaultEntryKind
  username?: string
  email?: string
  phone?: string
  host?: string
  port?: string
  url?: string
  tags?: string[]
}

/** Wire-safe full entry shape (secrets included; loopback UI only). */
export type VaultEntryWire = Omit<VaultEntry, 'createdAt' | 'updatedAt'>

/** Project a stored entry onto its wire summary. */
function toSummary(entry: VaultEntry): VaultEntrySummaryWire {
  return {
    id: entry.id,
    title: entry.title,
    ...(entry.kind !== undefined ? { kind: entry.kind } : {}),
    ...(entry.username !== undefined ? { username: entry.username } : {}),
    ...(entry.email !== undefined ? { email: entry.email } : {}),
    ...(entry.phone !== undefined ? { phone: entry.phone } : {}),
    ...(entry.host !== undefined ? { host: entry.host } : {}),
    ...(entry.port !== undefined ? { port: entry.port } : {}),
    ...(entry.url !== undefined ? { url: entry.url } : {}),
    ...(entry.tags !== undefined ? { tags: entry.tags } : {}),
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

/** Resolve the canonical vault file path for a config (path override or name). */
function resolveVaultPath(config: Config): string {
  if (config.path !== undefined) return config.path
  return defaultVaultPath(config.name)
}

/**
 * Open (or reuse) the vault store for one deployment configuration. All
 * callers within the process share the same instance for the same path and
 * master password, so a write via a model tool is immediately visible to the
 * Settings UI and vice versa.
 */
async function sharedVaultStore(masterPassword: string, config: Config): Promise<VaultStore> {
  const path = resolveVaultPath(config)
  // The master password is part of the identity: a different password must
  // open its own store (and fail authentication) rather than reuse a store
  // unlocked with another password.
  const cacheKey = `${path}\0${masterPassword}`
  const existing = sharedVaultStores.get(cacheKey)
  if (existing !== undefined) return existing
  const opening = openVault({
    masterPassword,
    path,
  }).catch((error: unknown) => {
    // A failed open must not poison the cache for later retries.
    sharedVaultStores.delete(cacheKey)
    throw error
  })
  sharedVaultStores.set(cacheKey, opening)
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

/** A summary view of an entry without timestamps or secrets (used by update output). */
function toSummaryJson(entry: VaultEntry): JsonValue {
  return toSummary(entry) as unknown as JsonValue
}

/** Strip timestamps from an entry for model-visible output (keeps secrets
 * when the caller asked for the full entry via vault_get). */
function stripTimestamps(entry: VaultEntry): JsonValue {
  const { createdAt, updatedAt, ...rest } = entry
  return rest as unknown as JsonValue
}
