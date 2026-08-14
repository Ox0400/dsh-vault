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
  'id' | 'title' | 'kind' | 'username' | 'email' | 'phone' | 'host' | 'port' | 'url' | 'tags'
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

  constructor(path: string, masterPassword: string) {
    this.path = path
    this.masterPassword = masterPassword
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
  }

  /** The vault file path (useful for messages and debugging). */
  get filePath(): string {
    return this.path
  }

  /** All entries, in insertion order. */
  list(): VaultEntry[] {
    return [...this.entries.values()]
  }

  /** Read one entry by id. */
  get(id: string): VaultEntry | undefined {
    return this.entries.get(id)
  }

  /** Search entries across text fields; returns summaries without secrets. */
  search(query: string, limit = 20): VaultEntrySummary[] {
    const needle = query.trim().toLowerCase()
    if (needle.length === 0) return []
    const results: VaultEntrySummary[] = []
    for (const entry of this.list()) {
      if (results.length >= limit) break
      if (matches(entry, needle)) results.push(toSummary(entry))
    }
    return results
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

  /** Delete an entry; returns true when it existed. */
  async delete(id: string): Promise<boolean> {
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
   * Persist the current in-memory state: encrypt every entry under the vault
   * key, then atomically replace the document under the cross-process lock.
   * Calls are serialized through an in-process chain so concurrent mutations
   * never contend for the lock and each write snapshots the entries visible
   * when it runs — the final file always reflects every completed mutation.
   * The derived key is cached after load and reused, so a mutation does not
   * re-run scrypt; only a fresh vault (no cached key yet) derives once.
   */
  private persist(): Promise<void> {
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
