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
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { dirname, join } from 'node:path'
import { openVault, defaultVaultPath, type VaultEntry, type VaultEntryKind, type VaultEntryPatch, type VaultEntrySummary, type VaultStore } from './store.ts'
import { totp, parseTotpSecret, hotp, base32Decode } from './totp.ts'
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
      kind: { type: 'string', description: 'Only return entries of this kind (login/ssh/api-key/secret/oauth/custom).', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'] },
      favoriteOnly: { type: 'boolean', description: 'Only return pinned (favorite) entries.' },
      regex: { type: 'boolean', description: 'Treat query as a regular expression (case-insensitive).' },
      sortBy: { type: 'string', enum: ['alpha', 'recent'], description: 'Sort results alphabetically (default) or by updatedAt desc.' },
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
      sensitivity: { type: 'string', enum: ['normal', 'high'], description: 'Sensitivity tier; "high" entries require confirmation when read in ask mode.' },
      rotationDays: { type: 'integer', description: 'Rotation interval in days; vault_rotation reports when it elapses.' },
      icon: { type: 'string', description: 'Optional emoji/icon shown in the UI (e.g. "🚀").' },
      color: { type: 'string', description: 'Optional accent color (e.g. "red", "#ff0000").' },
      favorite: { type: 'boolean', description: 'Pin/unpin the entry (favorites rank first in search).' },
      resetRotation: { type: 'boolean', description: 'Reset the rotation timer now (sets updatedAt to now).' },
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
      prefix: { type: 'string', description: 'Fixed prefix prepended to the random core (site requirements).' },
      suffix: { type: 'string', description: 'Fixed suffix appended to the random core (site requirements).' },
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
        ...(args.prefix !== undefined ? { prefix: args.prefix } : {}),
        ...(args.suffix !== undefined ? { suffix: args.suffix } : {}),
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
      field: { type: 'string', required: true, description: 'Field to copy: username, password, apiKey, secret, accessToken, refreshToken, otpSecret, privateKey.' },
    },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { value: { type: 'string', required: true }, caution: { type: 'string', required: true } } },
      render: (_a, v) => [{ type: 'text', text: `copied value (do not echo) — ${v.caution}` }],
    },
    async execute(args) {
      const entry = await readEntry(args.id)
      if (!entry) throw new Error(`vault_clipboard: entry ${args.id} not found`)
      const value = entry[args.field as keyof VaultEntry]
      if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`vault_clipboard: entry ${args.id} has no ${args.field}`)
      }
      return { value, caution: 'value returned for copy; do not repeat it in the conversation' }
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

  // ── vault_expiry: set/update an entry's expiry ──────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_expiry',
    description: 'Set or update the expiry (epoch millis) of an entry; pass expiresAt as 0 to clear it. '
      + 'vault_rotation reports entries whose expiry is near or past.',
    parameters: {
      id: { type: 'string', required: true, description: 'Entry id.' },
      expiresAt: { type: 'integer', required: true, description: 'Expiry epoch millis, or 0 to clear.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { updated: { type: 'boolean', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.updated ? 'expiry updated' : 'entry not found' }] },
    async execute(args) {
      assertWritable('vault_expiry')
      const s = await guardStore()
      const patch: VaultEntryPatch = args.expiresAt === 0 ? { expiresAt: '' as unknown as number } : { expiresAt: args.expiresAt }
      const updated = await s.update(args.id, patch)
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
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { changes: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.changes) }] },
    async execute(args) {
      const s = await guardStore()
      const hours = args.hours === undefined ? 24 : args.hours
      if (!Number.isFinite(hours) || hours <= 0 || hours > 8760) {
        throw new Error('vault_changes: hours must be a positive number ≤ 8760')
      }
      return { changes: s.changes(hours * 60 * 60 * 1000) }
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
      return { results: scored.slice(0, validateLimit(args.limit, 'vault_find')).map(x => x.entry) }
    },
  }))

  // ── vault_verify: integrity/completeness check of one entry ─────────────────
  ctx.tools.register(defineTool({
    name: 'vault_verify',
    description: 'Verify one entry for completeness and plausibility: required fields per kind, '
      + 'valid port/expiry, and that required secrets are present. No secrets in the report.',
    parameters: { id: { type: 'string', required: true, description: 'Entry id.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean', required: true }, issues: { type: 'array', required: true, items: { type: 'string' } } } }, render: (_a, v) => [{ type: 'text', text: v.ok ? 'entry looks complete' : `issues: ${v.issues.join('; ')}` }] },
    async execute(args) {
      const s = await guardStore()
      const entry = s.get(args.id)
      if (!entry) return { ok: false, issues: ['entry not found'] }
      const issues: string[] = []
      if (!entry.title) issues.push('missing title')
      if (entry.port !== undefined && !/^\d{1,5}$/.test(String(entry.port))) issues.push('port is not numeric')
      if (entry.expiresAt !== undefined && entry.expiresAt < Date.now()) issues.push('expired')
      switch (entry.kind ?? 'login') {
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
    parameters: { limit: { type: 'number', description: 'Max entries (default 20).' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { events: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.events) }] },
    async execute(args) {
      const s = await guardStore()
      const limit = validateLimit(args.limit, 'vault_history')
      return { events: s.getHistory().slice(0, limit) as unknown as JsonValue[] }
    },
  }))

  // ── vault_recent: most recently touched entries ─────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_recent',
    description: 'List the most recently created or updated entries (newest first), as secret-free '
      + 'summaries. Useful to pick up where you left off or surface what changed.',
    parameters: { limit: { type: 'number', description: 'Max results (default 10).' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { entries: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: JSON.stringify(v.entries) }] },
    async execute(args) {
      const s = await guardStore()
      return { entries: s.recent(validateLimit(args.limit, 'vault_recent')) }
    },
  }))

  // ── vault_stats: vault overview statistics ───────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_stats',
    description: 'Vault overview: total entries, counts by kind, entries with TOTP, high-sensitivity '
      + 'entries, and expired credentials. No secrets returned. Useful for a quick health glance.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { total: { type: 'integer', required: true }, byKind: { type: 'json', required: true }, byTag: { type: 'json', required: true }, withTotp: { type: 'integer', required: true }, withPrivateKey: { type: 'integer', required: true }, highSensitivity: { type: 'integer', required: true }, expired: { type: 'integer', required: true }, recent7d: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `vault: ${v.total} entries (${JSON.stringify(v.byKind)})` }] },
    async execute() {
      const s = await guardStore()
      return s.stats()
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
      const lines: string[] = []
      for (const e of s.list()) {
        const parts = [
          e.favorite ? '★' : '·',
          `[${e.kind ?? 'login'}]`,
          e.title,
          e.username ?? e.email ?? '',
          e.host !== undefined ? `@${e.host}${e.port !== undefined ? `:${e.port}` : ''}` : '',
          e.expiresAt !== undefined ? `exp ${new Date(e.expiresAt).toISOString().slice(0, 10)}` : '',
        ].filter(Boolean)
        lines.push(parts.join(' '))
      }
      const header = `dsh-vault inventory (${s.list().length} entries)\n${'-'.repeat(40)}`
      return { report: lines.length > 0 ? header + '\n' + lines.join('\n') : header }
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
      const matched = query.length === 0
        ? all
        : all.filter(e => {
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

  // ── vault_duplicates: exact-title+kind duplicates ───────────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_duplicates',
    description: 'Find entries that are exact duplicates (same title + kind). Returns groups of '
      + 'summaries (no secrets) so the caller can merge or delete them.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { groups: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: `found ${(v.groups as unknown[]).length} duplicate groups` }] },
    async execute() {
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
      const titleGroups = [...byKey.values()].filter(g => g.length > 1)
      const contentGroups = [...byContent.values()].filter(g => g.length > 1)
      return { groups: [...titleGroups, ...contentGroups] }
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
    description: 'Report how many days have passed since the last vault-backup-* file was written '
      + '(1Password-style backup reminder). Returns daysSinceBackup and a suggestion.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { daysSinceBackup: { type: 'integer', required: true }, backups: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `last backup ${v.daysSinceBackup} days ago (${v.backups} backup file(s))` }] },
    async execute() {
      const s = await guardStore()
      const dir = dirname(resolveVaultPath(config))
      const backups: number[] = []
      try {
        const entries = await readdir(dir)
        for (const entry of entries) {
          const m = /^vault-backup-(\d+)\.json$/.exec(entry)
          if (m) backups.push(Number(m[1]))
        }
      } catch { /* no dir yet */ }
      const last = backups.length > 0 ? Math.max(...backups) : 0
      const days = last > 0 ? Math.floor((Date.now() - last) / 86_400_000) : -1
      void s
      return { daysSinceBackup: days, backups: backups.length }
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
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'], description: 'Entry kind (default login).' },
      secret: { type: 'string', description: 'The secret value: stored into apiKey for api-key, password for login, secret otherwise.' },
      username: { type: 'string', description: 'Optional username.' },
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
      + 'the source fill gaps in the target, then the source is permanently removed. Returns the merged summary.',
    parameters: {
      fromId: { type: 'string', required: true, description: 'Source entry id (merged into the target, then deleted).' },
      toId: { type: 'string', required: true, description: 'Target entry id (kept, gaps filled).' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { merged: { type: 'boolean', required: true }, entry: { type: 'json' } } }, render: (_a, v) => [{ type: 'text', text: v.merged ? 'entries merged' : 'merge failed (one/both not found or in trash)' }] },
    async execute(args) {
      assertWritable('vault_merge')
      const s = await guardStore()
      const merged = await s.merge(args.fromId, args.toId)
      return merged === undefined ? { merged: false } : { merged: true, entry: toSummaryJson(merged) }
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
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { id: { type: 'string', required: true }, title: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: `saved as "${v.title}" (id: ${v.id})` }] },
    async execute(args) {
      assertWritable('vault_note_secret')
      if (!args.secret || args.secret.length === 0) throw new Error('vault_note_secret: secret is required')
      const s = await guardStore()
      const stamp = new Date().toISOString().slice(0, 10)
      const title = `secret-${stamp}-${Math.floor(Math.random() * 9000 + 1000)}`
      const entry = await s.add({
        title,
        kind: 'secret',
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
      + 'kind, tag, and created-after (epoch millis). All provided criteria must match (AND). Returns secret-free summaries.',
    parameters: {
      title: { type: 'string', description: 'Title substring.' },
      username: { type: 'string', description: 'Username/email substring.' },
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'], description: 'Entry kind.' },
      tag: { type: 'string', description: 'Exact tag.' },
      createdAfter: { type: 'integer', description: 'Only entries created after this epoch millis.' },
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
      kind: { type: 'string', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'], description: 'Count only this kind.' },
      tag: { type: 'string', description: 'Count only entries carrying this tag.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `${v.count} entries` }] },
    async execute(args) {
      const s = await guardStore()
      const kind = args.kind
      const tag = typeof args.tag === 'string' ? args.tag.trim() : ''
      const count = s.list().filter(e => {
        if (kind !== undefined && (e.kind ?? 'login') !== kind) return false
        if (tag.length > 0 && !(e.tags ?? []).includes(tag)) return false
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
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `exported ${v.count} entries to ${v.path}` }] },
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
          xml += `<notes>${x(e.notes)}</notes>\n</entry>\n`
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
    description: 'Quickly check whether the vault contains a credential matching a title/username/host. '
      + 'Returns found + which entry matched. Useful before deciding whether to add.',
    parameters: { target: { type: 'string', required: true, description: 'Title, username, or host to look for.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { found: { type: 'boolean', required: true }, id: { type: 'string' } } }, render: (_a, v) => [{ type: 'text', text: v.found ? 'credential found' : 'no matching credential' }] },
    async execute(args) {
      const s = await guardStore()
      const needle = args.target.trim().toLowerCase()
      if (needle.length === 0) return { found: false }
      const match = s.list().find(e =>
        e.title.toLowerCase().includes(needle)
        || (e.username ?? '').toLowerCase().includes(needle)
        || (e.host ?? '').toLowerCase().includes(needle))
      return match === undefined ? { found: false } : { found: true, id: match.id }
    },
  }))

  // ── vault_import_browser: import browser-exported CSV ───────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_browser',
    description: 'Import a browser password-manager CSV (name,url,username,password — Chrome/Firefox/'
      + 'Edge export format). Rows without a name are skipped; returns added/skipped counts.',
    parameters: { path: { type: 'string', required: true, description: 'Absolute path of the browser CSV.' } },
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
      const idx = {
        name: header.indexOf('name'),
        url: header.indexOf('url'),
        username: header.indexOf('username'),
        password: header.indexOf('password'),
      }
      if (idx.name < 0 || idx.password < 0) return { added: 0, skipped: rows.length - 1, updated: 0 }
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
        }
        if (s.list().some(e => e.title === name)) { skipped++; continue }
        s.insertDirect(entry)
        added++
      }
      await s.persist()
      return { added, skipped, updated: 0 }
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
      const target = args.target.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '')
      if (target.length === 0) return { found: false }
      let best: VaultEntry | undefined
      for (const e of s.list()) {
        const host = (e.host ?? '').toLowerCase()
        const url = (e.url ?? '').toLowerCase()
        const hostBase = host.split(':')[0] ?? ''
        const matches = (host.length > 0 && host.includes(target))
          || (url.length > 0 && url.includes(target))
          || (hostBase.length > 0 && target.includes(hostBase))
        if (matches) {
          if (best === undefined || host.length > (best.host ?? '').length) best = e
        }
      }
      if (best === undefined) return { found: false }
      const summary: Record<string, string> = { id: best.id, title: best.title, kind: best.kind ?? 'login' }
      const identity = best.username ?? best.email
      if (identity !== undefined) summary.username = identity
      return { found: true, entry: summary as unknown as JsonValue }
    },
  }))

  // ── vault_backup_now: explicit alias for an immediate backup ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_backup_now',
    description: 'Create an immediate timestamped backup of the vault file (alias of vault_backup). '
      + 'Returns the backup path.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: `backup written to ${v.path}` }] },
    async execute() {
      const s = await guardStore()
      const source = resolveVaultPath(config)
      const backup = join(dirname(source), `vault-backup-${Date.now()}.json`)
      const raw = await readFile(source, 'utf8')
      await mkdir(dirname(backup), { recursive: true, mode: 0o700 })
      await writeFile(backup, raw, { mode: 0o600 })
      void s
      return { path: backup }
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
    output: { schema: { type: 'object', additionalProperties: false, properties: { entries: { type: 'array', required: true, items: { type: 'json' } } } }, render: (_a, v) => [{ type: 'text', text: `returned ${(v.entries as unknown[]).length} entries` }] },
    async execute(args) {
      const s = await guardStore()
      const out: JsonValue[] = []
      for (const id of args.ids ?? []) {
        const e = s.get(id)
        if (!e) continue
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
      return { entries: out }
    },
  }))

  // ── vault_import_wallet: import from a pass directory ──────────────────────
  ctx.tools.register(defineTool({
    name: 'vault_import_wallet',
    description: 'Import entries from a pass directory tree: each .gpg file (or plaintext file) becomes '
      + 'an entry titled by its filename; the first line is the password, remaining lines are parsed as '
      + 'login:/email:/url: metadata. Returns added/skipped.',
    parameters: { dir: { type: 'string', required: true, description: 'Absolute pass directory.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `imported ${v.added}, updated ${v.updated}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_wallet')
      const s = await guardStore()
      let added = 0
      let skipped = 0
      const entries = await readdir(args.dir, { withFileTypes: true })
      for (const ent of entries) {
        if (!ent.isFile()) continue
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
      schema: { type: 'object', additionalProperties: false, properties: { weak: { type: 'array', required: true, items: { type: 'json' } }, reused: { type: 'array', required: true, items: { type: 'json' } }, strength: { type: 'json', required: true } } },
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
    parameters: { ids: { type: 'array', items: { type: 'string' }, description: 'Only export these entry ids (optional).' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { exported: { type: 'boolean', required: true }, note: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: v.note }] },
    async execute(args) {
      const exportPassword = resolveExportPassword(config)
      const s = await guardStore()
      const blob = args.ids !== undefined && args.ids.length > 0
        ? await s.exportEncrypted(exportPassword, Date.now(), new Set(args.ids))
        : await s.exportEncrypted(exportPassword)
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
    parameters: {
      kind: { type: 'string', description: 'Only export entries of this kind.', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'] },
      ids: { type: 'array', items: { type: 'string' }, description: 'Only export these entry ids (optional).' },
      mask: { type: 'boolean', description: 'Return masked values (secrets replaced with ***) instead of the real values.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { lines: { type: 'array', required: true, items: { type: 'string' } } } }, render: (_a, v) => [{ type: 'text', text: v.lines.join('\n') }] },
    async execute(args) {
      const s = await guardStore()
      const raw = await envLines(s, args.kind, args.ids)
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
    parameters: { path: { type: 'string', required: true, description: 'Absolute path of the .env file to write.' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, lines: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `wrote ${v.lines} lines to ${v.path}` }] },
    async execute(args) {
      assertWritable('vault_export_env')
      const s = await guardStore()
      const lines = await envLines(s)
      await mkdir(dirname(args.path), { recursive: true, mode: 0o700 })
      await writeFile(args.path, lines.join('\n') + (lines.length > 0 ? '\n' : ''), { mode: 0o600 })
      return { path: args.path, lines: lines.length }
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

  // ── vault_strength: zero-dependency password strength estimation ────────────
  ctx.tools.register(defineTool({
    name: 'vault_strength',
    description: 'Estimate the strength of a password with a zero-dependency heuristic '
      + '(length, character-class diversity, common-pattern penalties). Returns a score 0–100 '
      + 'and a verdict: weak / fair / strong / very strong. Use before choosing or storing a password.',
    parameters: { password: { type: 'string', required: true, description: 'The password to evaluate.' } },
    output: {
      schema: { type: 'object', additionalProperties: false, properties: { score: { type: 'integer', required: true }, verdict: { type: 'string', required: true }, feedback: { type: 'string', required: true } } },
      render: (_a, v) => [{ type: 'text', text: `${v.verdict} (${v.score}/100) — ${v.feedback}` }],
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
      kind: { type: 'string', description: 'Only export entries of this kind (login/ssh/api-key/secret/oauth/custom).', enum: ['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'] },
      includeSecrets: { type: 'boolean', description: 'Include secret columns (password/apiKey/secret/tokens). Default false — the CSV is secret-free for safe handling.' },
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true }, count: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `exported ${v.count} entries to ${v.path}` }] },
    async execute(args) {
      const s = await guardStore()
      const kind = args.kind
      const entries = s.list().filter(e => kind === undefined || (e.kind ?? 'login') === kind)
      const secretFields = ['password', 'apiKey', 'secret', 'accessToken', 'refreshToken', 'otpSecret']
      const fields = args.includeSecrets === true
        ? ['title', 'kind', 'username', ...secretFields, 'url', 'email', 'phone', 'host', 'port', 'expiresAt', 'notes', 'tags', 'sensitivity']
        : ['title', 'kind', 'username', 'url', 'email', 'phone', 'host', 'port', 'expiresAt', 'notes', 'tags', 'sensitivity']
      const esc = (v: unknown): string => {
        const str = v === undefined || v === null ? '' : Array.isArray(v) ? v.join(';') : String(v)
        return `"${str.replace(/"/g, '""')}"`
      }
      const lines = [fields.join(',')]
      for (const e of entries) {
        lines.push(fields.map(f => esc((e as unknown as Record<string, unknown>)[f])).join(','))
      }
      const file = args.path ?? join(dirname(resolveVaultPath(config)), `vault-export-${Date.now()}.csv`)
      await mkdir(dirname(file), { recursive: true, mode: 0o700 })
      await writeFile(file, lines.join('\n') + '\n', { mode: 0o600 })
      return { path: file, count: entries.length }
    },
  }))

  // ── vault_backup: one-shot backup with a timestamped filename ───────────────
  ctx.tools.register(defineTool({
    name: 'vault_backup',
    description: 'Create a timestamped backup of the vault file (a copy of the on-disk encrypted '
      + 'document, not a plaintext export). Returns the backup path. Safe to run anytime.',
    parameters: {},
    output: { schema: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: `backup written to ${v.path}` }] },
    async execute() {
      const s = await guardStore()
      const source = resolveVaultPath(config)
      const backup = join(dirname(source), `vault-backup-${Date.now()}.json`)
      const raw = await readFile(source, 'utf8')
      await mkdir(dirname(backup), { recursive: true, mode: 0o700 })
      await writeFile(backup, raw, { mode: 0o600 })
      void s
      return { path: backup }
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
    },
    output: { schema: { type: 'object', additionalProperties: false, properties: { added: { type: 'integer', required: true }, skipped: { type: 'integer', required: true }, updated: { type: 'integer', required: true } } }, render: (_a, v) => [{ type: 'text', text: `imported ${v.added}, updated ${v.updated}, skipped ${v.skipped}` }] },
    async execute(args) {
      assertWritable('vault_import_csv')
      const s = await guardStore()
      const raw = await readFile(args.path, 'utf8')
      const cleaned = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw
      const rows = parseCsv(cleaned, args.delimiter ?? ',')
      if (rows.length === 0) return { added: 0, skipped: 0, updated: 0 }
      const headers = rows[0]!.map(h => h.trim())
      const known = new Set(['title', 'username', 'password', 'url', 'email', 'phone', 'host', 'port',
        'apiKey', 'secret', 'accessToken', 'refreshToken', 'expiresAt', 'otpSecret', 'notes', 'tags',
        'kind', 'sensitivity', 'favorite', 'rotationDays'])
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
          if (['access', 'meta'].includes(m[1]!) || m[1]!.startsWith('vault-export-')) continue
          names.push(m[1]!)
        }
      } catch { /* dir may not exist yet */ }
      const active = currentVaultName ?? config.name ?? 'default'
      return { vaults: names.sort().map(name => ({ name, active: name === active })) }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'vault_switch',
    description: 'Switch the active vault for this session. Future vault_* calls operate on the named '
      + 'vault (created on first use). Returns the newly active vault name.',
    parameters: { name: { type: 'string', required: true, description: 'Vault name (e.g. "work" or "personal").' } },
    output: { schema: { type: 'object', additionalProperties: false, properties: { active: { type: 'string', required: true } } }, render: (_a, v) => [{ type: 'text', text: `switched to vault "${v.active}"` }] },
    async execute(args) {
      const name = args.name.trim()
      if (name.length === 0) throw new Error('vault_switch: name must not be empty')
      if (!/^[a-zA-Z0-9._-]+$/.test(name)) throw new Error('vault_switch: name may contain only letters, digits, . _ -')
      currentVaultName = name
      return { active: name }
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

  /** Toggle auto-capture (detect credentials in chat → offer to save) from
   * the Settings UI and persist it. */
  @Remote('setAutoCapture')
  async setAutoCapture(enabled: boolean): Promise<{ accessMode: AccessMode; autoCapture: boolean }> {
    this.accessPolicy.autoCapture = Boolean(enabled)
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

  /** Restore every trashed entry; returns how many were restored. */
  @Remote('undeleteAll')
  async undeleteAll(): Promise<{ restored: number }> {
    this.assertWritable('undeleteAll')
    const store = await this.ensureStore()
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
    const store = await this.ensureStore()
    return { restored: await store.restore(id) }
  }

  /** Days since last backup + backup count (no secrets). */
  @Remote('backupStatus')
  async backupStatus(): Promise<{ daysSinceBackup: number; backups: number }> {
    const dir = dirname(this.vaultPath ?? defaultVaultPath(this.vaultName))
    const backups: number[] = []
    try {
      const entries = await readdir(dir)
      for (const entry of entries) {
        const m = /^vault-backup-(\d+)\.json$/.exec(entry)
        if (m) backups.push(Number(m[1]))
      }
    } catch { /* no dir yet */ }
    const last = backups.length > 0 ? Math.max(...backups) : 0
    const days = last > 0 ? Math.floor((Date.now() - last) / 86_400_000) : -1
    return { daysSinceBackup: days, backups: backups.length }
  }

  /** Vault overview stats (no secrets). */
  @Remote('stats')
  async stats(): Promise<Record<string, unknown>> {
    const store = await this.ensureStore()
    return store.stats() as unknown as Record<string, unknown>
  }

  /** Most recently created entries (no secrets). */
  @Remote('recent')
  async recent(): Promise<{ entries: unknown[] }> {
    const store = await this.ensureStore()
    return { entries: store.recent(5) as unknown as unknown[] }
  }

  /** Recent mutation history (no secrets). */
  @Remote('history')
  async history(): Promise<{ events: unknown[] }> {
    const store = await this.ensureStore()
    return { events: store.getHistory().slice(0, 20) }
  }

  /** Rotation/expiry report (no secrets). */
  @Remote('rotation')
  async rotation(): Promise<{ entries: unknown[] }> {
    const store = await this.ensureStore()
    return { entries: store.rotationReport() }
  }

  /** Health scan findings (no secrets). */
  @Remote('health')
  async health(): Promise<{ weak: unknown[]; reused: unknown[]; strength: { weak: number; fair: number; strong: number } }> {
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
}

/** Wire-safe full entry shape (secrets included; loopback UI only). */
export type VaultEntryWire = Omit<VaultEntry, 'createdAt' | 'updatedAt'>

/** Project a stored entry onto its wire summary. */
function toSummary(entry: VaultEntry): VaultEntrySummaryWire {
  return {
    id: entry.id,
    title: entry.title,
    ...(entry.sensitivity !== undefined ? { sensitivity: entry.sensitivity } : {}),
    ...(entry.favorite !== undefined ? { favorite: entry.favorite } : {}),
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
function estimateStrength(password: string): { score: number; verdict: string; feedback: string } {
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
  return { score, verdict, feedback: feedback.length > 0 ? feedback.join('; ') : 'no obvious weaknesses' }
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
async function envLines(store: VaultStore, kind?: string, ids?: string[]): Promise<string[]> {
  const lines: string[] = []
  const seen = new Set<string>()
  const keyOf = (title: string, field: string): string => title.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') + '_' + field.toUpperCase()
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
