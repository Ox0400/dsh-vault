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
import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { dirname, join } from 'node:path'
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
})

export async function apply(ctx: Context, config: Config): Promise<void> {
  const masterPassword = resolveMasterPassword(config)
  const WRITE_TOOLS = new Set(['vault_add', 'vault_update', 'vault_delete'])
  const lockTimeoutSeconds = config.lockTimeoutSeconds ?? 0

  /** Shared access policy; resolved once, mutated by the UI via setAccessMode. */
  const policy = await sharedAccessPolicy(config)

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
    if (policy.mode === 'ask' && exec?.name !== undefined && WRITE_TOOLS.has(exec.name)) {
      return { kind: 'ask', reason: `dsh-vault: ${exec.name} requires your confirmation in "ask" (prompt-before-write) mode` }
    }
    return next()
  })

  /** Ensure the shared store is open (lazily on first use, so a missing
   * master password fails at the first tool call with a clear message). */
  async function ensureStore(): Promise<VaultStore> {
    const store = await sharedVaultStore(masterPassword, config)
    // Install the auto-lock policy once per store instance.
    if (lockTimeoutSeconds > 0) store.setAutoLock(lockTimeoutSeconds * 1000)
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
      assertWritable('vault_add')
      if (!args.title.trim()) throw new Error('vault_add: title must not be empty')
      const s = await guardStore()
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
      const s = await guardStore()
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
      assertWritable('vault_update')
      const s = await guardStore()
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
      assertWritable('vault_delete')
      const s = await guardStore()
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
      await s.unlock()
      return { unlocked: true }
    },
  }))

  // ── vault_rotation: expiry / rotation report ───────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_rotation',
    description: 'Report credentials that are expired, due for rotation (rotationDays elapsed), '
      + 'or expiring within 7 days. Returns summaries with a due state — never secrets.',
    parameters: {},
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { entries: { type: 'array', required: true, items: { type: 'json' } } } },
      render: (_a, v) => [{ type: 'text', text: v.entries.length === 0 ? 'no rotation items' : JSON.stringify(v.entries) }],
    },
    async execute() {
      const s = await guardStore()
      return { entries: s.rotationReport() }
    },
  }))

  // ── vault_health: weak / reused credential scan ────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_health',
    description: 'Scan the vault for weak passwords (shorter than 12 chars) and credentials reused '
      + 'across entries. Returns non-secret findings (entry summaries grouped by the reused value).',
    parameters: {},
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { weak: { type: 'array', required: true, items: { type: 'json' } }, reused: { type: 'array', required: true, items: { type: 'json' } } } },
      render: (_a, v) => [{ type: 'text', text: `weak: ${v.weak.length}, reused groups: ${v.reused.length}` }],
    },
    async execute() {
      const s = await guardStore()
      return s.health()
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

  ctx.tools.register(defineTool({
    name: 'vault_purge',
    description: 'Permanently delete an entry (active or trashed). Cannot be undone — prefer vault_delete '
      + '(soft delete) unless the entry must be removed from disk.',
    parameters: { id: { type: 'string', required: true, description: 'The entry id to purge.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { purged: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.purged ? 'entry purged' : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_purge')
      const s = await guardStore()
      return { purged: await s.purge(args.id) }
    },
  }))

  // ── vault_export / vault_import: portable encrypted transfer ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_export',
    description: 'Export the entire vault (including trash) as a single encrypted document under a '
      + 'separate export password (from the exportPasswordEnv config). Use for backup or migration; '
      + 'the export can be re-imported with vault_import. Never pass the password as an argument.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { exported: { type: 'boolean', required: true }, note: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.note }] },
    async execute() {
      const exportPassword = resolveExportPassword(config)
      const s = await guardStore()
      const blob = await s.exportEncrypted(exportPassword)
      const file = join(dirname(resolveVaultPath(config)), `vault-export-${Date.now()}.json`)
      await mkdir(dirname(file), { recursive: true, mode: 0o700 })
      await writeFile(file, blob, { mode: 0o600 })
      return { exported: true, note: `vault exported to ${file}` }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_import',
    description: 'Import a previously exported vault document (see vault_export), merging entries by '
      + 'id. Pass the document path; the export password comes from the exportPasswordEnv config.',
    parameters: { path: { type: 'string', required: true, description: 'Absolute path of the exported vault JSON file.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { imported: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `imported ${v.imported} entries` }] },
    async execute(args) {
      assertWritable('vault_import')
      const exportPassword = resolveExportPassword(config)
      const s = await guardStore()
      const blob = await readFile(args.path, 'utf8')
      const count = await s.importEncrypted(blob, exportPassword)
      return { imported: count }
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
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { found: { type: 'boolean', required: true }, entry: { type: 'json' } } },
      render: (_a, v) => [{ type: 'text', text: v.found ? `matched: ${(v.entry as { title?: string })?.title ?? 'entry'}` : 'no matching entry' }],
    },
    async execute(args) {
      const s = await guardStore()
      const needle = args.target.trim().toLowerCase()
      for (const entry of s.list()) {
        const haystack = [entry.title, entry.host, entry.url, entry.username, entry.email].filter(Boolean).join(' ').toLowerCase()
        if (needle.length > 0 && haystack.includes(needle)) {
          return { found: true, entry: stripTimestamps(entry) }
        }
      }
      return { found: false }
    },
  }))

  // ── vault_env: environment-variable export ─────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_env',
    description: 'Render entries flagged for environment export (tags contain "env") as KEY=VALUE lines '
      + 'suitable for .env or export statements. Keys derive from the title + field name; values are the '
      + 'secrets. Returns the lines so the caller can write them to a file (user-authorized).',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { lines: { type: 'array', required: true, items: { type: 'string' } } } }, render: (_a, v) => [{ type: 'text', text: v.lines.join('\n') }] },
    async execute() {
      const s = await guardStore()
      const lines: string[] = []
      const keyOf = (title: string, field: string): string => title.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') + '_' + field.toUpperCase()
      for (const entry of s.list()) {
        if (!(entry.tags ?? []).includes('env')) continue
        for (const [field, value] of Object.entries(entry)) {
          if (typeof value !== 'string' || value.length === 0) continue
          if (['id', 'title', 'kind', 'sensitivity', 'host', 'url', 'notes', 'createdAt', 'updatedAt', 'deletedAt'].includes(field)) continue
          if (['username', 'email', 'phone', 'port', 'tags'].includes(field)) continue
          lines.push(`${keyOf(entry.title, field)}=${value}`)
        }
      }
      return { lines }
    },
  }))

  // ── vault_templates: field templates by kind ───────────────────────────────
  const TEMPLATES: Record<string, Record<string, string>> = {
    login: { username: 'account username', email: 'account email', password: 'account password' },
    ssh: { host: 'server host', port: 'port (e.g. 22)', username: 'login user', password: 'password or passphrase', privateKey: 'PEM private key' },
    'api-key': { apiKey: 'the API key', url: 'API base URL', username: 'owner/account (optional)' },
    oauth: { accessToken: 'access token', refreshToken: 'refresh token', expiresAt: 'expiry epoch millis', clientId: 'client id (via fields)' },
    secret: { secret: 'the shared secret', notes: 'what it is for' },
    custom: { fields: 'arbitrary key/value pairs' },
  }
  ctx.tools.register(defineTool({
    name: 'vault_templates',
    description: 'Return the recommended fields for a credential kind, so vault_add can be called with '
      + 'the right field names (e.g. kind ssh → host/port/username/password/privateKey).',
    parameters: { kind: { type: 'string', description: 'Entry kind; default login.', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'] } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { kind: { type: 'string', required: true }, fields: { type: 'json', required: true } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.fields) }] },
    async execute(args) {
      const kind = args.kind ?? 'login'
      return { kind, fields: TEMPLATES[kind] ?? TEMPLATES.login! }
    },
  }))

  // ── vault_rekey: upgrade the scrypt KDF parameters in place ────────────────
  ctx.tools.register(defineTool({
    name: 'vault_rekey',
    description: 'Upgrade the vault encryption to fresh scrypt KDF parameters (higher cost) and '
      + 're-encrypt every entry in place. Safe to run periodically or after raising the vault '
      + 'cost expectations; the old document is replaced atomically. Returns the new cost parameter n.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { n: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `vault re-keyed with scrypt N=${v.n}` }] },
    async execute() {
      assertWritable('vault_rekey')
      const s = await guardStore()
      return await s.rekey()
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

  constructor(ctx: Context, config: Config & { accessPolicy?: AccessPolicy }) {
    super(ctx, 'vault')
    this.masterPassword = config.masterPassword ?? resolveMasterPassword(config)
    this.vaultPath = config.path
    this.vaultName = config.name
    this.accessPolicy = config.accessPolicy ?? { mode: config.accessMode ?? 'ask', autoCapture: config.autoCapture ?? false }
  }

  private async ensureStore(): Promise<VaultStore> {
    return sharedVaultStore(this.masterPassword, {
      ...(this.vaultPath !== undefined ? { path: this.vaultPath } : {}),
      ...(this.vaultName !== undefined ? { name: this.vaultName } : {}),
    })
  }

  /** Reject mutations when the vault is in readonly mode (UI surface). */
  private assertWritable(action: string): void {
    if (this.accessPolicy.mode === 'readonly') {
      throw new Error(`vault: ${action} is disabled in readonly mode (set accessMode to "ask" or "auto" to enable)`)
    }
  }

  /** Current access policy and capture preference, for the Settings UI. */
  @Remote('config')
  async config(): Promise<{ accessMode: AccessMode; autoCapture: boolean }> {
    return { accessMode: this.accessPolicy.mode, autoCapture: this.accessPolicy.autoCapture }
  }

  /** Switch the runtime access mode from the Settings UI and persist it. */
  @Remote('setAccessMode')
  async setAccessMode(mode: AccessMode): Promise<{ accessMode: AccessMode; autoCapture: boolean }> {
    if (mode !== 'readonly' && mode !== 'ask' && mode !== 'auto') {
      throw new Error(`vault: invalid accessMode "${String(mode)}" (expected readonly, ask, or auto)`)
    }
    this.accessPolicy.mode = mode
    await this.persistPolicy()
    return { accessMode: this.accessPolicy.mode, autoCapture: this.accessPolicy.autoCapture }
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
    const store = await this.ensureStore()
    return { entries: store.list().map(toSummary) }
  }

  /** List trashed (soft-deleted) entries as non-secret summaries. */
  @Remote('trash')
  async trash(): Promise<{ entries: VaultEntrySummaryWire[] }> {
    const store = await this.ensureStore()
    return { entries: store.listTrash().map(toSummary) }
  }

  /** Restore a trashed entry (non-secret summary returned). */
  @Remote('restore')
  async restore(id: string): Promise<{ restored: boolean }> {
    this.assertWritable('restore')
    const store = await this.ensureStore()
    return { restored: await store.restore(id) }
  }

  /** Rotation/expiry report (no secrets). */
  @Remote('rotation')
  async rotation(): Promise<{ entries: unknown[] }> {
    const store = await this.ensureStore()
    return { entries: store.rotationReport() }
  }

  /** Health scan findings (no secrets). */
  @Remote('health')
  async health(): Promise<{ weak: unknown[]; reused: unknown[] }> {
    const store = await this.ensureStore()
    return store.health()
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
    this.assertWritable('add')
    if (!patch.title.trim()) throw new Error('vault: title must not be empty')
    const store = await this.ensureStore()
    const entry = await store.add(patch)
    return toSummary(entry)
  }

  /** Update an existing entry's fields; returns the updated summary or not-found. */
  @Remote('update')
  async update(id: string, patch: VaultEntryPatch): Promise<{ found: boolean; entry?: VaultEntrySummaryWire }> {
    this.assertWritable('update')
    const store = await this.ensureStore()
    const updated = await store.update(id, patch)
    if (updated === undefined) return { found: false }
    return { found: true, entry: toSummary(updated) }
  }

  /** Delete an entry by id. */
  @Remote('delete')
  async delete(id: string): Promise<{ deleted: boolean }> {
    this.assertWritable('delete')
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
}

const sharedAccessPolicies = new Map<string, AccessPolicy>()

/** Resolve the canonical vault file path for a config (path override or name). */
function resolveVaultPath(config: Config): string {
  if (config.path !== undefined) return config.path
  return defaultVaultPath(config.name)
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
