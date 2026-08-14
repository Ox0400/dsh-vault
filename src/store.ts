/**
 * The encrypted vault store: a single JSON document on disk holding the KDF
 * parameters and one authenticated-encryption envelope per entry. The whole
 * document is atomically replaced on every mutation (`writeFileAtomic` from
 * `@deepseek-ai/dsh-atomic-write`) and cross-process writers serialize through
 * its companion file lock.
 *
 * All secrets live inside AES-256-GCM envelopes keyed by scrypt(master
 * password). The on-disk document never contains plaintext secrets; the key
 * is never persisted and must be re-derived from the master password on every
 * load.
 *
 * KDF parameters are fixed for the life of a vault (chosen when the document
 * is first created), so loading and persisting always derive the same key.
 *
 * @module dsh-vault/store
 */

import { chmod, mkdir, readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { withFileLock, writeFileAtomic } from '@deepseek-ai/dsh-atomic-write'
import { dshHomePath } from '@deepseek-ai/dsh-home-paths'
import {
  decrypt,
  deriveKey,
  encrypt,
  newKdfParams,
  safeEqual,
  VAULT_FORMAT_VERSION,
  type EncryptedBlob,
  type KdfParams,
} from './crypto.ts'

/** JSON-safe value usable inside an entry's arbitrary `fields` map. */
export type FieldValue = string | number | boolean | null | FieldValue[] | { [key: string]: FieldValue }

/** Entry categories: general login vs. developer credentials. */
export type VaultEntryKind =
  /** Web/account login (username, email, phone, password). */
  | 'login'
  /** SSH connection (host, port, username, password or privateKey). */
  | 'ssh'
  /** API key (apiKey / secret). */
  | 'api-key'
  /** Generic secret / credential (secret, notes). */
  | 'secret'
  /** OAuth token pair (accessToken, refreshToken, expiresAt). */
  | 'oauth'
  /** Generic key/value record via `fields`. */
  | 'custom'

/** One credential entry. All fields except `id`/`title`/timestamps are optional. */
export interface VaultEntry {
  /** Stable unique id (uuid v4). */
  id: string
  /** Human title, e.g. "GitHub personal". */
  title: string
  /** Entry category; defaults to `login`. */
  kind?: VaultEntryKind
  /** Sensitivity tier: `high` entries (e.g. banking, root SSH) additionally
   * require approval when read in ask mode. Defaults to `normal`. */
  sensitivity?: 'normal' | 'high'
  /** Rotation interval in days; the rotation report lists entries whose
   * `rotationDays` elapsed since `createdAt`/`updatedAt`. */
  rotationDays?: number
  /** Epoch millis when the entry was soft-deleted (moved to trash); absent
   * means the entry is active. Trashed entries are excluded from search/list
   * until purged or restored. */
  deletedAt?: number
  /** Pinned/favorite flag (Bitwarden-style): pinned entries rank first in
   * search and list. */
  favorite?: boolean
  /** Account username/login. */
  username?: string
  /** Account email. */
  email?: string
  /** Account phone number. */
  phone?: string
  /** The password. */
  password?: string
  /** SSH host or service hostname. */
  host?: string
  /** SSH/service port (string to allow non-numeric protocols). */
  port?: string
  /** SSH private key (PEM). */
  privateKey?: string
  /** API key. */
  apiKey?: string
  /** Generic secret (client secret, shared secret, …). */
  secret?: string
  /** OAuth access token. */
  accessToken?: string
  /** OAuth refresh token. */
  refreshToken?: string
  /** Token/credential expiry epoch millis. */
  expiresAt?: number
  /** TOTP secret: bare Base32 or an otpauth:// URI. */
  otpSecret?: string
  /** Associated URL (login page, service home). */
  url?: string
  /** Free-form notes. */
  notes?: string
  /** Searchable tags. */
  tags?: string[]
  /** Arbitrary additional key/value fields (e.g. region, username hint). */
  fields?: Record<string, FieldValue>
  /** Creation epoch millis. */
  createdAt: number
  /** Last-update epoch millis. */
  updatedAt: number
}

/** An entry as returned by search/list — never carries secrets. */
export type VaultEntrySummary = Pick<
  VaultEntry,
  'id' | 'title' | 'kind' | 'sensitivity' | 'favorite' | 'username' | 'email' | 'phone' | 'host' | 'port' | 'url' | 'tags'
>

/** The fields `vault_update` may change, mirroring the entry minus identity/timestamps. */
export type VaultEntryPatch = Partial<Omit<VaultEntry, 'id' | 'createdAt' | 'updatedAt'>>

/** On-disk document shape: KDF header plus one encrypted envelope per entry. */
interface VaultFile {
  version: number
  kdf: KdfParams
  /** Password-verification envelope: a fixed plaintext encrypted under the
   * vault key, so a wrong master password fails fast even on an empty vault. */
  verify: EncryptedBlob
  /** One authenticated-encryption blob per entry, in insertion order. */
  entries: Array<EncryptedBlob & { id: string }>
}

/** Fixed plaintext inside the verification envelope. */
const VERIFY_PLAINTEXT = 'dsh-vault:password-ok'

/** Derive the default on-disk path for a named vault. */
export function defaultVaultPath(vaultName = 'default'): string {
  return join(dshHomePath('vault'), `${vaultName}.json`)
}

/**
 * Open (or lazily create) a vault and return a ready-to-use store. Loading
 * decrypts the whole document up front so search and reads are pure in-memory
 * operations.
 */
export async function openVault(options: {
  /** Master password. Required to decrypt; also used to create a new vault. */
  masterPassword: string
  /** Vault file path. Defaults to `$DSH_HOME/vault/default.json`. */
  path?: string
  /** Vault name used only for the default path. */
  name?: string
}): Promise<VaultStore> {
  if (options.masterPassword.length === 0) {
    throw new Error('vault master password must not be empty')
  }
  const path = options.path ?? defaultVaultPath(options.name)
  const store = new VaultStore(path, options.masterPassword)
  await store.load()
  return store
}

/**
 * In-memory vault handle. Mutations persist atomically under the file lock;
 * reads never touch the disk again until a reload.
 */
export class VaultStore {
  private readonly entries = new Map<string, VaultEntry>()
  private readonly path: string
  private readonly masterPassword: string
  /** KDF parameters fixed for this vault's life; set on first load/create. */
  private kdf: KdfParams | undefined
  /** Cached derived key; derived once after load and reused for every persist. */
  private key: Buffer | undefined
  /** Serializes in-process persist calls so concurrent mutations never
   * contend for the cross-process file lock and every write sees the latest
   * in-memory state. */
  private persistChain: Promise<unknown> = Promise.resolve()
  /** Auto-lock: after this many ms of inactivity the vault re-locks (key
   * wiped). `0`/undefined disables auto-lock. */
  private lockTimeoutMs: number | undefined
  /** Epoch millis of the last operation; used for the auto-lock timer. */
  private lastActivity = Date.now()
  /** Whether the vault is currently locked (key wiped, requires re-unlock). */
  private locked = false
  /** Weak-password heuristic: too short or in a tiny common list. */
  private static readonly MIN_PASSWORD_LENGTH = 12

  constructor(path: string, masterPassword: string) {
    this.path = path
    this.masterPassword = masterPassword
  }

  /** Enable auto-lock with the given idle timeout (ms). */
  setAutoLock(timeoutMs: number | undefined): void {
    this.lockTimeoutMs = timeoutMs
    this.lastActivity = Date.now()
  }

  /** Whether the vault is currently locked. */
  get isLocked(): boolean {
    return this.locked
  }

  /** Touch the activity timestamp; call before every read/write. */
  touch(): void {
    this.lastActivity = Date.now()
  }

  /** Whether the auto-lock idle window has elapsed. */
  get expired(): boolean {
    if (this.lockTimeoutMs === undefined || this.lockTimeoutMs <= 0) return false
    return Date.now() - this.lastActivity > this.lockTimeoutMs
  }

  /** Lock the vault: wipe the derived key and require re-unlock. */
  lock(): void {
    this.key?.fill(0)
    this.key = undefined
    this.locked = true
    this.lastActivity = Date.now()
  }

  /** Re-derive the key from the master password (after a lock). */
  async unlock(): Promise<void> {
    if (this.kdf === undefined) {
      await this.load()
      return
    }
    this.key = await deriveKey(this.masterPassword, this.kdf)
    this.locked = false
    this.lastActivity = Date.now()
  }

  /**
   * Load the vault document from disk (creating an empty one on first use)
   * and derive the vault key from the document's fixed KDF parameters.
   */
  async load(): Promise<void> {
    // Ensure the vault directory exists before any lock-file or document
    // write, so first use never fails with ENOENT on a fresh install.
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 })
    // Tighten a pre-existing directory (mkdir leaves existing dirs untouched)
    // so the vault tree stays owner-only even when a parent created it wider.
    await chmod(dirname(this.path), 0o700).catch(() => {})
    const { file, created } = await this.readDocument()
    this.kdf = file.kdf
    this.key = await deriveKey(this.masterPassword, file.kdf)
    if (created) {
      // First run: persist the empty document so the file exists with the
      // chosen KDF (and its verify envelope) before any entry is added.
      await this.persist()
      this.locked = false
      this.lastActivity = Date.now()
      return
    }
    for (const blob of file.entries) {
      const plaintext = decrypt(blob, this.key)
      const entry = JSON.parse(plaintext.toString('utf8')) as VaultEntry
      this.entries.set(entry.id, entry)
    }
    // Verify the password even when the vault has no entries yet.
    const verify = decrypt(file.verify!, this.key)
    if (!safeEqual(verify, Buffer.from(VERIFY_PLAINTEXT, 'utf8'))) {
      throw new Error('vault master password is incorrect')
    }
    this.locked = false
    this.lastActivity = Date.now()
  }

  /** The vault file path (useful for messages and debugging). */
  get filePath(): string {
    return this.path
  }

  /** All active (non-trashed) entries, in insertion order. */
  list(): VaultEntry[] {
    return [...this.entries.values()].filter(entry => entry.deletedAt === undefined)
  }

  /** All trashed entries (soft-deleted, awaiting purge or restore). */
  listTrash(): VaultEntry[] {
    return [...this.entries.values()].filter(entry => entry.deletedAt !== undefined)
  }

  /** Read one active entry by id. */
  get(id: string): VaultEntry | undefined {
    const entry = this.entries.get(id)
    return entry !== undefined && entry.deletedAt === undefined ? entry : undefined
  }

  /** Read one entry by id, including trashed entries. */
  getIncludingTrash(id: string): VaultEntry | undefined {
    return this.entries.get(id)
  }

  /** Search entries across text fields; returns summaries without secrets.
   * Multiple whitespace-separated terms match when ANY term hits (OR).
   * Results are relevance-ranked: title prefix matches first, then title
   * contains, then any-field matches. */
  search(query: string, limit = 20): VaultEntrySummary[] {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
    if (terms.length === 0) return []
    const ranked: Array<{ entry: VaultEntry; rank: number }> = []
    for (const entry of this.list()) {
      const rank = relevanceRank(entry, terms)
      if (rank >= 0) ranked.push({ entry, rank })
    }
    ranked.sort((a, b) => a.rank - b.rank || Number(Boolean(b.entry.favorite)) - Number(Boolean(a.entry.favorite)))
    return ranked.slice(0, limit).map(r => toSummary(r.entry))
  }

  /** Add a new entry; returns the stored entry with its assigned id. Empty
   * strings and empty arrays from the client form are dropped (a blank form
   * field means "not provided", not "store an empty value"). */
  async add(patch: VaultEntryPatch & { title: string }): Promise<VaultEntry> {
    const now = Date.now()
    const entry: VaultEntry = {
      id: randomUUID(),
      title: patch.title,
      ...pickDefined(patch, { skipEmpty: true }),
      createdAt: now,
      updatedAt: now,
    }
    this.entries.set(entry.id, entry)
    await this.persist()
    return entry
  }

  /** Pin or unpin an entry (favorite); returns the updated entry or undefined. */
  async setFavorite(id: string, favorite: boolean): Promise<VaultEntry | undefined> {
    const entry = this.entries.get(id)
    if (!entry || entry.deletedAt !== undefined) return undefined
    if (favorite) entry.favorite = true
    else delete entry.favorite
    entry.updatedAt = Date.now()
    await this.persist()
    return entry
  }

  /** Insert an entry directly (used by bulk import); caller owns timestamps. */
  insertDirect(entry: VaultEntry): void {
    this.entries.set(entry.id, entry)
  }

  /** Update an existing entry's fields; returns the updated entry or undefined.
   * Every defined field in `patch` replaces the stored value; an empty string
   * clears (removes) that field. `id`/`createdAt` can never change. */
  async update(id: string, patch: VaultEntryPatch): Promise<VaultEntry | undefined> {
    const current = this.entries.get(id)
    if (!current) return undefined
    // A title must never be blanked out: an empty-string title is an error
    // rather than a request to remove the entry's identity.
    if ('title' in patch && (patch.title ?? '').trim().length === 0) {
      throw new Error('vault: title must not be empty')
    }
    // Validate typed fields so a bad model argument can never corrupt an entry.
    validatePatchTypes(patch)
    const updated: VaultEntry = {
      ...current,
      ...pickDefined(patch, { allowTitle: true }),
      updatedAt: Date.now(),
    }
    // An empty string means "clear this field": drop it entirely instead of
    // storing a blank value, so search and summaries never surface it.
    const record = updated as unknown as Record<string, unknown>
    for (const key of Object.keys(patch)) {
      if ((patch as Record<string, unknown>)[key] === '') {
        delete record[key]
      }
    }
    this.entries.set(id, updated)
    await this.persist()
    return updated
  }

  /** Soft-delete an entry (move to trash); returns true when it existed.
   * The entry stays encrypted on disk until purged or restored. */
  async delete(id: string): Promise<boolean> {
    const entry = this.entries.get(id)
    if (!entry || entry.deletedAt !== undefined) return false
    entry.deletedAt = Date.now()
    await this.persist()
    return true
  }

  /** Restore a trashed entry; returns true when it existed in trash. */
  async restore(id: string): Promise<boolean> {
    const entry = this.entries.get(id)
    if (!entry || entry.deletedAt === undefined) return false
    delete entry.deletedAt
    await this.persist()
    return true
  }

  /** Permanently remove a trashed (or active) entry; returns true when it existed. */
  async purge(id: string): Promise<boolean> {
    const existed = this.entries.delete(id)
    if (existed) await this.persist()
    return existed
  }

  /** Number of entries. */
  get size(): number {
    return this.entries.size
  }

  /** Whether the vault is unlocked (loaded) with a usable key. */
  get unlocked(): boolean {
    return this.key !== undefined
  }

  /**
   * Rotation & expiry report: entries whose `rotationDays` elapsed since
   * their last update, or whose `expiresAt` is near/past. Returns only
   * summaries plus the computed due state (no secrets).
   */
  rotationReport(now = Date.now()): Array<VaultEntrySummary & { due: 'expired' | 'due' | 'soon'; daysLeft: number }> {
    const report: Array<VaultEntrySummary & { due: 'expired' | 'due' | 'soon'; daysLeft: number }> = []
    for (const entry of this.list()) {
      const base = entry.updatedAt ?? entry.createdAt
      const rotationAt = entry.rotationDays !== undefined ? base + entry.rotationDays * 86_400_000 : undefined
      const expiresAt = entry.expiresAt
      let due: 'expired' | 'due' | 'soon' | undefined
      let daysLeft: number
      if (rotationAt !== undefined && now >= rotationAt) {
        due = 'due'
        daysLeft = 0
      } else if (expiresAt !== undefined && now >= expiresAt) {
        due = 'expired'
        daysLeft = 0
      } else if (expiresAt !== undefined) {
        daysLeft = Math.ceil((expiresAt - now) / 86_400_000)
        if (daysLeft <= 7) {
          due = 'soon'
        }
      } else if (rotationAt !== undefined) {
        daysLeft = Math.ceil((rotationAt - now) / 86_400_000)
        if (daysLeft <= 7) {
          due = 'soon'
        }
      } else {
        continue
      }
      if (due === undefined) continue
      report.push({ ...toSummary(entry), due, daysLeft })
    }
    return report
  }

  /** Vault overview statistics (1Password-style): counts by kind, TOTP,
   * high-sensitivity, expired entries. No secrets. */
  stats(): { total: number; byKind: Record<string, number>; withTotp: number; highSensitivity: number; expired: number } {
    const byKind: Record<string, number> = {}
    let withTotp = 0
    let highSensitivity = 0
    let expired = 0
    const now = Date.now()
    for (const entry of this.list()) {
      const kind = entry.kind ?? 'login'
      byKind[kind] = (byKind[kind] ?? 0) + 1
      if (entry.otpSecret !== undefined) withTotp++
      if (entry.sensitivity === 'high') highSensitivity++
      if (entry.expiresAt !== undefined && entry.expiresAt < now) expired++
    }
    return { total: this.list().length, byKind, withTotp, highSensitivity, expired }
  }

  /** Activity within the last `windowMs`: entries created, updated, or
   * soft-deleted in that window, with their action. No secrets. */
  changes(windowMs = 24 * 60 * 60 * 1000, now = Date.now()): Array<VaultEntrySummary & { action: 'created' | 'updated' | 'deleted'; at: number }> {
    const since = now - windowMs
    const out: Array<VaultEntrySummary & { action: 'created' | 'updated' | 'deleted'; at: number }> = []
    for (const entry of this.entries.values()) {
      if (entry.deletedAt !== undefined) {
        if (entry.deletedAt >= since) out.push({ ...toSummary(entry), action: 'deleted', at: entry.deletedAt })
      } else if (entry.createdAt >= since && entry.updatedAt - entry.createdAt < 60_000) {
        out.push({ ...toSummary(entry), action: 'created', at: entry.createdAt })
      } else if (entry.updatedAt >= since) {
        out.push({ ...toSummary(entry), action: 'updated', at: entry.updatedAt })
      }
    }
    return out.sort((a, b) => b.at - a.at)
  }

  /** Most recently created/updated entries (Bitwarden-style "recent"),
   * returned as summaries without secrets. */
  recent(limit = 10): VaultEntrySummary[] {
    return [...this.list()]
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, limit)
      .map(toSummary)
  }

  /**
   * Health scan: weak passwords (too short), and passwords/API keys reused
   * across entries. Returns non-secret findings keyed by entry id.
   */
  health(): { weak: Array<VaultEntrySummary>; reused: Array<{ value: string; entries: VaultEntrySummary[] }> } {
    const weak: VaultEntrySummary[] = []
    const passwordCounts = new Map<string, VaultEntrySummary[]>()
    const keyCounts = new Map<string, VaultEntrySummary[]>()
    for (const entry of this.list()) {
      const summary = toSummary(entry)
      if (entry.password !== undefined) {
        if (entry.password.length < VaultStore.MIN_PASSWORD_LENGTH) weak.push(summary)
        const list = passwordCounts.get(entry.password) ?? []
        list.push(summary)
        passwordCounts.set(entry.password, list)
      }
      for (const key of [entry.apiKey, entry.accessToken, entry.refreshToken, entry.secret]) {
        if (key === undefined) continue
        const list = keyCounts.get(key) ?? []
        list.push(summary)
        keyCounts.set(key, list)
      }
    }
    const reused = [
      ...[...passwordCounts.entries()].filter(([, v]) => v.length > 1),
      ...[...keyCounts.entries()].filter(([, v]) => v.length > 1),
    ].map(([value, entries]) => ({ value, entries }))
    return { weak, reused }
  }

  /**
   * Export the whole vault (including trash) as a single encrypted blob under
   * a separate export password: a portable, machine-independent document that
   * can be re-imported elsewhere. Returns the armored JSON string.
   */
  async exportEncrypted(exportPassword: string, now = Date.now()): Promise<string> {
    if (exportPassword.length === 0) throw new Error('vault: export password must not be empty')
    const exportKdf = newKdfParams()
    const exportKey = await deriveKey(exportPassword, exportKdf)
    const payload = {
      exportedAt: now,
      kdf: exportKdf,
      entries: [...this.entries.values()].map(entry => ({
        id: entry.id,
        ...encrypt(Buffer.from(JSON.stringify(entry), 'utf8'), exportKey),
      })),
    }
    exportKey.fill(0)
    return JSON.stringify(payload)
  }

  /**
   * Import an exported vault blob, merging entries by id (existing entries win
   * unless `overwrite`). Returns the number of entries added.
   */
  async importEncrypted(blob: string, exportPassword: string, overwrite = false): Promise<number> {
    if (exportPassword.length === 0) throw new Error('vault: export password must not be empty')
    const parsed = JSON.parse(blob) as {
      kdf: KdfParams
      entries: Array<EncryptedBlob & { id: string }>
    }
    if (!parsed.kdf || !Array.isArray(parsed.entries)) {
      throw new Error('vault: invalid export document')
    }
    const exportKey = await deriveKey(exportPassword, parsed.kdf)
    let added = 0
    for (const blobEntry of parsed.entries) {
      const plaintext = decrypt(blobEntry, exportKey)
      const entry = JSON.parse(plaintext.toString('utf8')) as VaultEntry
      const existing = this.entries.get(entry.id)
      if (existing !== undefined && !overwrite) continue
      // Imported entries come back as active (clear any soft-delete marker).
      const { deletedAt, ...active } = entry
      this.entries.set(entry.id, { ...active, updatedAt: Date.now() })
      added++
    }
    exportKey.fill(0)
    await this.persist()
    return added
  }

  /**
   * Persist the current in-memory state: encrypt every entry under the vault
   * key, then atomically replace the document under the cross-process lock.
   * Calls are serialized through an in-process chain so concurrent mutations
   * never contend for the lock and each write snapshots the entries visible
   * when it runs — the final file always reflects every completed mutation.
   * The derived key is cached after load and reused, so a mutation does not
   * re-run scrypt; only a fresh vault (no cached key yet) derives once.
   */
  /**
   * Re-key the vault with fresh scrypt KDF parameters (cost upgrade): derive a
   * new key from the master password under `newKdfParams()` and re-encrypt
   * every entry under it, atomically. The old key buffer is wiped. Returns the
   * new cost parameter `n` for reporting.
   */
  async rekey(): Promise<{ n: number }> {
    if (this.key === undefined) {
      await this.load()
    }
    const newKdf = newKdfParams()
    const newKey = await deriveKey(this.masterPassword, newKdf)
    // Encrypt every entry under the new key first (in memory), so a failure
    // mid-encrypt leaves the on-disk document untouched.
    const reEncrypted = [...this.entries.values()].map(entry => ({
      id: entry.id,
      ...encrypt(Buffer.from(JSON.stringify(entry), 'utf8'), newKey),
    }))
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 })
    await withFileLock(this.path, async () => {
      const file: VaultFile = {
        version: VAULT_FORMAT_VERSION,
        kdf: newKdf,
        verify: encrypt(Buffer.from(VERIFY_PLAINTEXT, 'utf8'), newKey),
        entries: reEncrypted,
      }
      await writeFileAtomic(this.path, JSON.stringify(file), { mode: 0o600, dirMode: 0o700 })
    })
    this.kdf = newKdf
    this.key?.fill(0)
    this.key = newKey
    return { n: newKdf.n }
  }

  async persist(): Promise<void> {
    const run = async (): Promise<void> => {
      const kdf = this.kdf ?? newKdfParams()
      this.kdf = kdf
      if (this.key === undefined) {
        this.key = await deriveKey(this.masterPassword, kdf)
      }
      const key = this.key
      // `withFileLock` creates the `<file>.lock` sibling with exclusive create,
      // which fails when the parent directory is absent, so ensure the directory
      // exists before taking the lock.
      await mkdir(dirname(this.path), { recursive: true, mode: 0o700 })
      await withFileLock(this.path, async () => {
        const file: VaultFile = {
          version: VAULT_FORMAT_VERSION,
          kdf,
          verify: encrypt(Buffer.from(VERIFY_PLAINTEXT, 'utf8'), key),
          entries: [...this.entries.values()].map(entry => ({
            id: entry.id,
            ...encrypt(Buffer.from(JSON.stringify(entry), 'utf8'), key),
          })),
        }
        await writeFileAtomic(this.path, JSON.stringify(file), {
          mode: 0o600,
          dirMode: 0o700,
        })
      })
    }
    // Append to the chain; a rejected write must not stall later writes, so
    // the chain continues with the next operation regardless of outcome.
    const next = this.persistChain.then(run, run)
    this.persistChain = next.catch(() => {})
    return next
  }

  /** Read and parse the vault document, tolerating first-run absence. */
  private async readDocument(): Promise<{ file: VaultFile; created: boolean }> {
    let raw: string
    try {
      raw = await readFile(this.path, 'utf8')
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { file: { version: VAULT_FORMAT_VERSION, kdf: newKdfParams(), verify: EMPTY_BLOB, entries: [] }, created: true }
      }
      throw error
    }
    const parsed = JSON.parse(raw) as VaultFile
    if (parsed.version !== VAULT_FORMAT_VERSION) {
      throw new Error(`unsupported vault format version ${parsed.version} (expected ${VAULT_FORMAT_VERSION})`)
    }
    if (!parsed.kdf || parsed.kdf.algo !== 'scrypt' || !parsed.kdf.saltHex) {
      throw new Error('vault document is missing valid KDF parameters')
    }
    if (!parsed.verify) {
      throw new Error('vault document is missing its password-verification envelope')
    }
    return { file: parsed, created: false }
  }
}

/** Placeholder envelope for a not-yet-persisted vault; replaced on first persist. */
const EMPTY_BLOB: EncryptedBlob = { ivHex: '', tagHex: '', dataHex: '' }


/** Relevance rank for search: 0 = title prefix, 1 = title contains,
 * 2 = any field contains, -1 = no match. Lower is better. */
function relevanceRank(entry: VaultEntry, terms: string[]): number {
  const title = entry.title.toLowerCase()
  const primary = terms[0]!
  if (title.startsWith(primary)) return 0
  if (title.includes(primary)) return 1
  return terms.some(term => matches(entry, term)) ? 2 : -1
}

/** Case-insensitive substring match across the entry's searchable fields. */
function matches(entry: VaultEntry, needle: string): boolean {
  const fieldValues: string[] = []
  collectSearchable(entry.fields ?? {}, fieldValues)
  return [
    entry.title,
    entry.kind,
    entry.username,
    entry.email,
    entry.phone,
    entry.host,
    entry.port,
    entry.url,
    entry.notes,
    ...(entry.tags ?? []),
    ...fieldValues,
  ].some(value => value?.toLowerCase().includes(needle))
}

/** Recursively collect every scalar string from a fields value (numbers and
 * booleans stringified so they are searchable too). */
function collectSearchable(value: FieldValue, out: string[]): void {
  if (typeof value === 'string') {
    out.push(value)
  } else if (typeof value === 'number' || typeof value === 'boolean') {
    out.push(String(value))
  } else if (Array.isArray(value)) {
    for (const item of value) collectSearchable(item, out)
  } else if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value)) collectSearchable(item, out)
  }
}

/** Project an entry to its non-secret summary shape. */
function toSummary(entry: VaultEntry): VaultEntrySummary {
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

/** Copy only the defined properties of a patch, excluding identity fields.
 * `title` is excluded by default (add sets it explicitly); pass
 * `{ allowTitle: true }` for updates, which may rename an entry. With
 * `{ skipEmpty: true }` (adds) empty strings and empty arrays are dropped so
 * blank form fields never land in storage. */
/** Validate typed patch fields, throwing on an invalid type so a bad model
 * argument can never corrupt an entry. Empty strings are allowed (they mean
 * "clear this field"); absent fields are skipped. */
function validatePatchTypes(patch: Record<string, unknown>): void {
  const kindSet = new Set(['login', 'ssh', 'api-key', 'secret', 'oauth', 'custom'])
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined || value === '') continue
    switch (key) {
      case 'kind':
        if (typeof value !== 'string' || !kindSet.has(value)) {
          throw new Error(`vault: kind must be one of ${[...kindSet].join(', ')}`)
        }
        break
      case 'sensitivity':
        if (value !== 'normal' && value !== 'high') {
          throw new Error('vault: sensitivity must be "normal" or "high"')
        }
        break
      case 'rotationDays':
      case 'expiresAt':
        if (typeof value !== 'number' || !Number.isFinite(value)) {
          throw new Error(`vault: ${key} must be a finite number`)
        }
        break
      case 'port':
        if (typeof value !== 'string' && typeof value !== 'number') {
          throw new Error('vault: port must be a string or number')
        }
        break
      case 'favorite':
        if (typeof value !== 'boolean') {
          throw new Error('vault: favorite must be a boolean')
        }
        break
      case 'tags':
        if (!Array.isArray(value) || value.some(t => typeof t !== 'string')) {
          throw new Error('vault: tags must be an array of strings')
        }
        break
      case 'fields':
        if (typeof value !== 'object' || value === null || Array.isArray(value)) {
          throw new Error('vault: fields must be an object')
        }
        break
    }
  }
}

function pickDefined(patch: Record<string, unknown>, options: { allowTitle?: boolean; skipEmpty?: boolean } = {}): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(patch)) {
    const identityField = key === 'id' || key === 'createdAt' || key === 'updatedAt' || (!options.allowTitle && key === 'title')
    if (value === undefined || identityField) continue
    if (options.skipEmpty && (value === '' || (Array.isArray(value) && value.length === 0))) continue
    result[key] = value
  }
  return result
}
