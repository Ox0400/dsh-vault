/**
 * Vault settings section: list, search, add, edit, delete, and copy encrypted
 * credentials. All mutations go through the host VaultGateway remote; secrets
 * are shown only inside the edit form or a copy action, never in the list.
 */

import { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import type { PropsLocale, PropsRuntime, InjectFace, TranslateNS } from '@deepseek-ai/dsh-client-ui-slots'
import type { VaultLocaleKey } from './locales.ts'
import css from './VaultSection.module.css'

/** Wire shapes shared with the host gateway (mirror of src/index.ts types). */
export interface VaultSummaryWire {
  id: string
  title: string
  sensitivity?: string
  kind?: string
  username?: string
  email?: string
  phone?: string
  host?: string
  port?: string
  url?: string
  tags?: string[]
  icon?: string
  color?: string
  fields?: Record<string, string>
  cardExpiry?: string
  cardHolder?: string
  hasOtp?: boolean
  createdAt?: number
  updatedAt?: number
}

export interface VaultFullWire {
  id: string
  title: string
  kind?: string
  username?: string
  email?: string
  phone?: string
  password?: string
  host?: string
  port?: string
  privateKey?: string
  apiKey?: string
  secret?: string
  accessToken?: string
  refreshToken?: string
  expiresAt?: number
  rotationDays?: number
  sensitivity?: string
  favorite?: boolean
  otpSecret?: string
  cardNumber?: string
  cardCvv?: string
  cardHolder?: string
  url?: string
  notes?: string
  tags?: string[]
  icon?: string
  color?: string
  fields?: Record<string, unknown>
}

/** Patch shape accepted by vault.add / vault.update. */
export type VaultPatch = Partial<Omit<VaultFullWire, 'id'>>

/** Registration-side business face supplied by the plugin entry. */
export interface VaultSectionInjected {
  t: TranslateNS<'settings.vault'>
  config: () => Promise<{ accessMode: 'readonly' | 'ask' | 'auto'; autoCapture: boolean; autoLockSeconds: number }>
  setAccessMode: (mode: 'readonly' | 'ask' | 'auto') => Promise<{ accessMode: 'readonly' | 'ask' | 'auto'; autoCapture: boolean; autoLockSeconds: number }>
  setAutoCapture: (enabled: boolean) => Promise<{ accessMode: 'readonly' | 'ask' | 'auto'; autoCapture: boolean; autoLockSeconds: number }>
  setAutoLock: (seconds: number) => Promise<{ seconds: number }>
  list: () => Promise<VaultSummaryWire[]>
  search: (query: string, limit?: number) => Promise<VaultSummaryWire[]>
  get: (id: string) => Promise<{ found: boolean; entry?: VaultFullWire }>
  add: (patch: VaultPatch & { title: string }) => Promise<VaultSummaryWire>
  update: (id: string, patch: VaultPatch) => Promise<{ found: boolean; entry?: VaultSummaryWire }>
  remove: (id: string) => Promise<{ deleted: boolean }>
  purge: (id: string) => Promise<{ purged: boolean }>
  trash: () => Promise<VaultSummaryWire[]>
  rotation: () => Promise<unknown[]>
  history: () => Promise<unknown[]>
  stats: () => Promise<Record<string, unknown>>
  recent: () => Promise<unknown[]>
  backupStatus: () => Promise<{ daysSinceBackup: number; backups: number }>
  backup: (maxBackups?: number) => Promise<{ path: string; kept: number; pruned: number }>
  health: () => Promise<{ weak: unknown[]; reused: unknown[]; strength: { weak: number; fair: number; strong: number }; no2fa: unknown[]; httpSites: unknown[]; score: number; verdict: string }>
  duplicates: () => Promise<{ groups: number }>
  duplicateGroups: () => Promise<Array<Array<{ id: string; title: string }>>>
  status: () => Promise<{ locked: boolean; entries: number }>
  switchVault: (name: string) => Promise<{ switched: boolean; name: string }>
  lock: () => Promise<{ locked: boolean }>
  unlock: () => Promise<{ locked: boolean }>
  totpUri: (id: string) => Promise<{ uri: string }>
  tags: () => Promise<Array<{ name: string; count: number }>>
  renameTag: (from: string, to: string) => Promise<{ renamed: number }>
  removeTag: (tag: string) => Promise<{ removed: number }>
  generatorHistory: () => Promise<Array<{ password: string; at: number }>>
  backups: (limit?: number) => Promise<Array<{ path: string; at: number; vaultName: string; size: number }>>
  deleteBackup: (path: string) => Promise<{ deleted: boolean; path: string }>
  restoreBackup: (path: string, mode?: string, overwrite?: boolean) => Promise<{ entries: number; safetyBackup: string; note: string; added?: number; skipped?: number; updated?: number }>
  importChrome: (overwrite?: boolean) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  importFirefox: (masterPassword?: string, overwrite?: boolean) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  keychainImport: (options?: { limit?: number; overwrite?: boolean; preview?: boolean; service?: string }) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  import1password: (path: string, overwrite?: boolean, dryRun?: boolean) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  importManagerCsv: (path: string, overwrite?: boolean, dryRun?: boolean) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  previewImportCsv: (path: string) => Promise<{ rows: Array<{ title: string; kind: string; username: string; hasPassword: boolean }>; total: number; skipped: number }>
  importEnpass: (path: string, overwrite?: boolean, dryRun?: boolean) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  importBitwarden: (path: string, overwrite?: boolean, dryRun?: boolean) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  import1pif: (path: string, overwrite?: boolean, dryRun?: boolean) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  importBitwardenEncrypted: (path: string, password: string, overwrite?: boolean, dryRun?: boolean) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  importKeePassXml: (path: string, overwrite?: boolean, dryRun?: boolean) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  importKdbx: (path: string, password?: string, keyfile?: string, overwrite?: boolean, dryRun?: boolean) => Promise<{ added: number; skipped: number; updated: number; note: string }>
  searchSystem: (query: string, source?: string, limit?: number) => Promise<{ matches: Array<{ source: string; name: string; username: string }>; note: string }>
  listVaults: () => Promise<Array<{ name: string; active: boolean }>>
  touch: (id: string) => Promise<{ touched: boolean }>
  setFavorite: (id: string, favorite: boolean) => Promise<{ found: boolean }>
  attachments: (id: string) => Promise<{ found: boolean; attachments: Array<{ name: string; size: number }> }>
  detach: (id: string, name: string) => Promise<{ found: boolean; detached: boolean }>
  attach: (id: string, name: string, dataBase64: string, mime?: string) => Promise<{ found: boolean; attached: boolean; name?: string; size?: number; attachments?: number }>
  downloadAttachment: (id: string, name: string) => Promise<{ found: boolean; name?: string; size?: number; mime?: string; dataBase64?: string }>
  verifyAll: () => Promise<Array<{ id: string; title: string; issues: string[] }>>
  breachCheck: (online?: boolean) => Promise<{ checked: number; pwned: Array<{ id: string; title: string; count: number }>; weak: Array<{ id: string; title: string }>; offline: boolean }>
  generatePassword: (options?: { length?: number; lowercase?: boolean; uppercase?: boolean; digits?: boolean; symbols?: boolean; excludeAmbiguous?: boolean; passphrase?: boolean; words?: number; separator?: string; wordDigits?: boolean }) => Promise<{ password: string }>
  strength: (password: string) => Promise<{ score: number; verdict: string; feedback: string; bits: number }>
  templates: () => Promise<Array<{ name: string; kind: string; fields: Record<string, string> }>>
  saveTemplate: (name: string, kind: string, fields: Record<string, string>) => Promise<{ saved: boolean }>
  generateUsername: () => Promise<{ username: string }>
  merge: (fromId: string, toId: string, keepSource?: boolean) => Promise<{ found: boolean }>
  restore: (id: string) => Promise<{ restored: boolean }>
  undeleteAll: () => Promise<{ restored: number }>
  totp: (id: string) => Promise<{ code: string; label?: string; secondsRemaining: number }>
  sessionOpen: (url: string) => Promise<{ sessionId: string; url: string }>
  sessionCollect: (sessionId: string, url?: string) => Promise<{ cookies: unknown[]; count: number }>
  sessionClose: (sessionId: string) => Promise<{ closed: boolean }>
  sessionListOpen: () => Promise<Array<{ sessionId: string; url: string; openedAt: number }>>
  sessionListSaved: () => Promise<Array<{ id: string; title: string; url?: string; cookieCount: number; expiredCount?: number; expiringSoon?: number; updatedAt?: number }>>
  sessionSave: (options: { title: string; cookies: unknown[]; url?: string; overwrite?: boolean }) => Promise<{ saved: number; id: string }>
  sessionExport: (id: string, format?: 'header' | 'netscape' | 'json' | 'playwright') => Promise<{ text: string; cookieCount: number; domains: string[] }>
  sessionGet: (id: string) => Promise<{ id: string; title: string; url?: string; cookies: unknown[]; notes?: string }>
  sessionPrune: (id: string, preview?: boolean) => Promise<{ pruned: number; remaining: number; note: string }>
  vaultRename: (from: string, to: string) => Promise<{ renamed: boolean; from?: string; to?: string; vaults: Array<{ name: string; active: boolean }>; note: string }>
  vaultDelete: (name: string, confirm: boolean) => Promise<{ deleted: boolean; name?: string; active: string; vaults: Array<{ name: string; active: boolean }>; note: string }>
  watchtower: () => Promise<Array<{ id: string; title: string; kind: string; flags: string[]; score: number; verdict: string; bits?: number }>>
  passwordHistory: (id: string) => Promise<Array<{ password: string; at: number }>>
  passwordRollback: (id: string, at: number) => Promise<{ rolledBack: boolean; password?: string }>
  export1pux: (path: string) => Promise<{ path: string; count: number }>
  exportBitwarden: (path: string) => Promise<{ path: string; count: number }>
  exportCsv: (path: string, fields: string[]) => Promise<{ path: string; count: number; fields: string[] }>
  recoveryCode: () => Promise<{ code: string; note: string }>
  verifyRecovery: (code: string) => Promise<{ verified: boolean }>
  recoveryStatus: () => Promise<{ set: boolean; issuedAt?: number }>
}

/** Type-level alias so consumers can reference the wire shapes without values. */
export type VaultSectionTypes = {
  entries: VaultSummaryWire[]
  fullEntry: VaultFullWire
  summaryEntry: VaultSummaryWire
  config: { accessMode: 'readonly' | 'ask' | 'auto'; autoCapture: boolean; autoLockSeconds: number }
  accessModes: Array<'readonly' | 'ask' | 'auto'>
}

/** Full component props assembled by the Settings slot renderer. */
export type VaultSectionProps =
  PropsRuntime<'settings.section'>
  & PropsLocale<'settings.vault'>
  & InjectFace<VaultSectionInjected>

/** The editable form fields we render (subset of the full wire). */
type FormFields = {
  title?: string | undefined
  kind?: string | undefined
  username?: string | undefined
  email?: string | undefined
  phone?: string | undefined
  password?: string | undefined
  host?: string | undefined
  port?: string | undefined
  privateKey?: string | undefined
  apiKey?: string | undefined
  secret?: string | undefined
  accessToken?: string | undefined
  refreshToken?: string | undefined
  otpSecret?: string | undefined
  cardNumber?: string | undefined
  cardExpiry?: string | undefined
  cardCvv?: string | undefined
  cardHolder?: string | undefined
  url?: string | undefined
  notes?: string | undefined
  icon?: string | undefined
  color?: string | undefined
  expiresAt?: number | undefined
  rotationDays?: number | undefined
  sensitivity?: string | undefined
  favorite?: boolean | undefined
}

const FORM_FIELDS: Array<{ key: keyof FormFields; label: VaultLocaleKey }> = [
  { key: 'title', label: 'fieldTitle' },
  { key: 'kind', label: 'fieldKind' },
  { key: 'username', label: 'fieldUsername' },
  { key: 'email', label: 'fieldEmail' },
  { key: 'phone', label: 'fieldPhone' },
  { key: 'password', label: 'fieldPassword' },
  { key: 'host', label: 'fieldHost' },
  { key: 'port', label: 'fieldPort' },
  { key: 'apiKey', label: 'fieldApiKey' },
  { key: 'secret', label: 'fieldSecret' },
  { key: 'accessToken', label: 'fieldAccessToken' },
  { key: 'refreshToken', label: 'fieldRefreshToken' },
  { key: 'otpSecret', label: 'fieldOtpSecret' },
  { key: 'cardNumber', label: 'fieldCardNumber' },
  { key: 'cardExpiry', label: 'fieldCardExpiry' },
  { key: 'cardCvv', label: 'fieldCardCvv' },
  { key: 'cardHolder', label: 'fieldCardHolder' },
  { key: 'url', label: 'fieldUrl' },
  { key: 'notes', label: 'fieldNotes' },
  { key: 'expiresAt', label: 'fieldExpiresAt' },
  { key: 'rotationDays', label: 'fieldRotationDays' },
  { key: 'sensitivity', label: 'fieldSensitivity' },
  { key: 'favorite', label: 'fieldFavorite' },
  { key: 'icon', label: 'fieldIcon' },
  { key: 'color', label: 'fieldColor' },
]

const VERDICT_KEYS: Record<string, VaultLocaleKey> = { good: 'verdictGood', fair: 'verdictFair', poor: 'verdictPoor' }
const TAB_KEYS: Record<string, VaultLocaleKey> = {
  entries: 'tabEntries', security: 'tabSecurity', transfer: 'tabTransfer',
  backup: 'tabBackup', permissions: 'tabPermissions', sessions: 'tabSessions', audit: 'tabAudit', trash: 'tabTrash',
}
const VERDICT_KEYS_SHORT: Record<string, VaultLocaleKey> = { weak: 'verdictPoor', fair: 'verdictFair', strong: 'verdictGood', 'very strong': 'verdictGood' }
const GEN_OPT_KEYS: Record<string, VaultLocaleKey> = {
  uppercase: 'genOptUppercase', lowercase: 'genOptLowercase', digits: 'genOptDigits',
  symbols: 'genOptSymbols', excludeAmbiguous: 'genOptExcludeAmbiguous',
}

/** Number of entries matching the current kind/tag/favorites/due filters (for
 * pagination and result counts). */
function filteredCount(entries: VaultSummaryWire[], kindFilter: string, tagFilter: string, favOnly: boolean, dueOnly: boolean, dueMap: Record<string, { due: string; daysLeft: number }>): number {
  return entries.filter(entry => (kindFilter === '' || entry.kind === kindFilter)
    && (tagFilter === '' || (entry.tags ?? []).includes(tagFilter))
    && (!favOnly || (entry as VaultSummaryWire & { favorite?: boolean }).favorite === true)
    && (!dueOnly || dueMap[entry.id] !== undefined)).length
}

/** Wrap case-insensitive matches of `term` inside `text` with <mark> spans for
 * search-result highlighting. Returns React nodes (never innerHTML), so user
 * input can't inject markup; regex metacharacters are escaped. */
function highlightText(text: string, term: string): ReactNode {
  const needle = term.trim()
  if (needle.length === 0 || text.length === 0) return text
  const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  let re: RegExp
  try {
    re = new RegExp(escaped, 'gi')
  } catch {
    return text
  }
  const parts: ReactNode[] = []
  let last = 0
  let key = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) { re.lastIndex++; continue }
    if (m.index > last) parts.push(text.slice(last, m.index))
    parts.push(<mark key={key++} className={css.hit}>{m[0]}</mark>)
    last = m.index + m[0].length
  }
  if (last < text.length) parts.push(text.slice(last))
  return parts.length > 0 ? parts : text
}

/** Curated columns offered in the CSV export field picker. */
const CSV_EXPORT_FIELDS: Array<{ key: string; label: VaultLocaleKey }> = [  { key: 'title', label: 'fieldTitle' },
  { key: 'kind', label: 'fieldKind' },
  { key: 'username', label: 'fieldUsername' },
  { key: 'email', label: 'fieldEmail' },
  { key: 'password', label: 'fieldPassword' },
  { key: 'apiKey', label: 'fieldApiKey' },
  { key: 'otpSecret', label: 'fieldOtpSecret' },
  { key: 'url', label: 'fieldUrl' },
  { key: 'notes', label: 'fieldNotes' },
  { key: 'tags', label: 'fieldTags' },
  { key: 'expiresAt', label: 'fieldExpiresAt' },
  { key: 'rotationDays', label: 'fieldRotationDays' },
  { key: 'favorite', label: 'fieldFavorite' },
]

/** Quick-pick emoji icons for the entry icon field. */
const EMOJI_ICONS = ['🔑', '🐙', '👤', '🔒', '💳', '🏠', '☁️', '📧', '🔐', '🛡️', '📡', '🧾', '📱', '🖥️', '🕸️', '🌐']

/** Preset accent colors for the entry color field. */
const COLOR_PRESETS = ['#2e9e5b', '#cf3d3d', '#c98a1b', '#2563eb', '#7c3aed', '#0d9488', '#db2777', '#64748b', '#e0a800', '#111827']

const KIND_KEYS: Record<string, VaultLocaleKey> = {  login: 'kindLogin',
  ssh: 'kindSsh',
  'api-key': 'kindApiKey',
  secret: 'kindSecret',
  oauth: 'kindOauth',
  cookie: 'kindCookie',
  card: 'kindCard',
  custom: 'kindCustom',
}

type ViewState =
  | { readonly status: 'loading' }
  | { readonly status: 'error'; readonly reason?: string }
  | { readonly status: 'ready'; readonly entries: VaultSummaryWire[] }

type EditorState =
  | { readonly status: 'closed' }
  | { readonly status: 'creating' }
  | { readonly status: 'editing'; readonly entry: VaultFullWire }

function emptyForm(): FormFields {
  return { title: '', kind: 'login', username: '', email: '', phone: '', password: '', host: '', port: '', icon: '', color: '' }
}

/** Human label for a built-in template name (`builtin:wifi` → Wi-Fi). */
function templateLabel(name: string): string {
  const labels: Record<string, string> = {
    'builtin:login': 'Login', 'builtin:ssh': 'SSH', 'builtin:api-key': 'API key',
    'builtin:oauth': 'OAuth', 'builtin:secret': 'Secret', 'builtin:card': 'Card',
    'builtin:wifi': 'Wi-Fi', 'builtin:server': 'Server', 'builtin:database': 'Database',
    'builtin:identity': 'Identity', 'builtin:bank': 'Bank account', 'builtin:custom': 'Custom',
  }
  return labels[name] ?? name
}

/** Render the Vault settings section. */
export function VaultSection(props: VaultSectionProps): ReactNode {
  const { t, config, setAccessMode, setAutoCapture, setAutoLock, list, search, get, add, update, remove, purge, trash, rotation, health, duplicates, duplicateGroups, merge, history, stats, backupStatus, backup, recent, restore, undeleteAll, totp, status, switchVault, listVaults, touch, setFavorite, attachments, detach, attach, downloadAttachment, verifyAll, breachCheck, generatePassword, strength, generateUsername, templates, saveTemplate, lock, totpUri, tags, renameTag, removeTag, generatorHistory, backups, deleteBackup, restoreBackup, importChrome, importFirefox, import1password, importManagerCsv, previewImportCsv, importEnpass, importBitwarden, import1pif, importKeePassXml, importKdbx, importBitwardenEncrypted, keychainImport, searchSystem, sessionOpen, sessionCollect, sessionClose, sessionListOpen, sessionListSaved, sessionSave, sessionExport, sessionGet, sessionPrune, passwordHistory, passwordRollback, vaultRename, vaultDelete, watchtower, export1pux, exportBitwarden, exportCsv, recoveryCode, verifyRecovery, recoveryStatus, unlock } = props
  const searchId = useId()
  const searchRef = useRef<HTMLInputElement | null>(null)
  const [query, setQuery] = useState('')
  const [recentSearches, setRecentSearches] = useState<string[]>(() => {
    try {
      const raw = window.sessionStorage.getItem('dsh-vault-recent-searches')
      const arr = raw === null ? [] : JSON.parse(raw) as unknown
      return Array.isArray(arr) ? arr.filter((v): v is string => typeof v === 'string').slice(0, 8) : []
    } catch {
      return []
    }
  })
  const [state, setState] = useState<ViewState>({ status: 'loading' })
  const [editor, setEditor] = useState<EditorState>({ status: 'closed' })
  const [form, setForm] = useState<FormFields>(emptyForm())
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [totpMap, setTotpMap] = useState<Record<string, { code: string; until: number }>>({})
  const [uriMap, setUriMap] = useState<Record<string, string>>({})
  const [tagList, setTagList] = useState<Array<{ name: string; count: number }>>([])
  const [tagManagerOpen, setTagManagerOpen] = useState(false)
  const [genHistory, setGenHistory] = useState<Array<{ password: string; at: number }>>([])
  const [backupList, setBackupList] = useState<Array<{ path: string; at: number; vaultName: string; size: number }>>([])
  const [openSessions, setOpenSessions] = useState<Array<{ sessionId: string; url: string; openedAt: number }>>([])
  const [savedSessions, setSavedSessions] = useState<Array<{ id: string; title: string; url?: string; cookieCount: number; expiredCount?: number; expiringSoon?: number; updatedAt?: number }>>([])
  const [sessionUrl, setSessionUrl] = useState('')
  const [sessionTitle, setSessionTitle] = useState('')
  const [sessionDetail, setSessionDetail] = useState<{ id: string; title: string; url?: string; cookies: unknown[]; notes?: string } | null>(null)
  const [watchMap, setWatchMap] = useState<Record<string, { score: number; verdict: string; flags: string[] }>>({})
  const [sessionPaste, setSessionPaste] = useState('')
  const [sessionPasteTitle, setSessionPasteTitle] = useState('')
  const [sysQuery, setSysQuery] = useState('')
  const [sysMatches, setSysMatches] = useState<Array<{ source: string; name: string; username: string }>>([])
  const [importPreview, setImportPreview] = useState<{ path: string; rows: Array<{ title: string; kind: string; username: string; hasPassword: boolean }>; total: number; skipped: number } | null>(null)
  const [exportFields, setExportFields] = useState<string[]>(CSV_EXPORT_FIELDS.map(f => f.key))
  const [nowTick, setNowTick] = useState(Date.now())
  const [tagsDraft, setTagsDraft] = useState('')
  const [fieldsDraft, setFieldsDraft] = useState('')
  const [revealed, setRevealed] = useState<Record<string, boolean>>({})
  const [genOpts, setGenOpts] = useState<{ length: number; uppercase: boolean; lowercase: boolean; digits: boolean; symbols: boolean; excludeAmbiguous: boolean; passphrase: boolean; words: number; separator: string; wordDigits: boolean }>({ length: 24, uppercase: true, lowercase: true, digits: true, symbols: true, excludeAmbiguous: false, passphrase: false, words: 4, separator: '-', wordDigits: true })
  const [showGenOpts, setShowGenOpts] = useState(false)
  const [pwStrength, setPwStrength] = useState<{ score: number; verdict: string; bits: number } | null>(null)
  const [tplList, setTplList] = useState<Array<{ name: string; kind: string; fields: Record<string, string> }>>([])
  const [kindFilter, setKindFilter] = useState('')
  const [tagFilter, setTagFilter] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [attachmentsMap, setAttachmentsMap] = useState<Record<string, Array<{ name: string; size: number }>>>({})
  const [selectMode, setSelectMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [pwHistory, setPwHistory] = useState<Array<{ password: string; at: number }> | null>(null)
  const [pwHistoryFor, setPwHistoryFor] = useState<string | null>(null)
  const [pwHistRevealed, setPwHistRevealed] = useState<number | null>(null)
  const [openMenuId, setOpenMenuId] = useState<string | null>(null)
  const [auditFilter, setAuditFilter] = useState('')
  const [visibleCount, setVisibleCount] = useState(50)
  const [sortBy, setSortBy] = useState<'alpha' | 'recent' | 'created' | 'favorite' | 'smart'>('alpha')
  const [favOnly, setFavOnly] = useState(false)
  const [dueOnly, setDueOnly] = useState(false)
  const [activeTab, setActiveTab] = useState<'entries' | 'security' | 'transfer' | 'backup' | 'permissions' | 'sessions' | 'audit' | 'trash'>('entries')
  const [policy, setPolicy] = useState<{ accessMode: 'readonly' | 'ask' | 'auto'; autoCapture: boolean; autoLockSeconds: number } | null>(null)
  const [trashEntries, setTrashEntries] = useState<VaultSummaryWire[]>([])
  const [report, setReport] = useState<{ rotation: unknown[]; weak: unknown[]; reused: unknown[]; strength: { weak: number; fair: number; strong: number } | null; no2fa: unknown[]; httpSites: unknown[]; score: number; verdict: string } | null>(null)
  const [dueMap, setDueMap] = useState<Record<string, { due: string; daysLeft: number }>>({})
  const [recentEvents, setRecentEvents] = useState<Array<Record<string, unknown>>>([])
  const [vaultStats, setVaultStats] = useState<Record<string, unknown> | null>(null)
  const [backupInfo, setBackupInfo] = useState<{ daysSinceBackup: number; backups: number } | null>(null)
  const [recentEntries, setRecentEntries] = useState<Array<Record<string, unknown>>>([])
  const [dupGroups, setDupGroups] = useState<number>(0)
  const [dupList, setDupList] = useState<Array<Array<{ id: string; title: string }>>>([])
  const [locked, setLocked] = useState(false)
  const [vaults, setVaults] = useState<Array<{ name: string; active: boolean; entries?: number }>>([])
  const [audit, setAudit] = useState<Array<{ id: string; title: string; issues: string[] }>>([])
  const [breach, setBreach] = useState<{ checked: number; pwned: Array<{ id: string; title: string; count: number }>; weak: Array<{ id: string; title: string }>; offline: boolean } | null>(null)

  const readonly = policy?.accessMode === 'readonly'

  /** Format a byte count for display (e.g. 1536 → "1.5 KB"). */
  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  /** Turn an RPC/Error failure into a specific, localized message instead of
   * the generic "operation failed" copy. The RPC channel wraps errors as
   * `vault.<method> failed: <code>: <message>`; unwrap and map the common
   * host-side failures to friendly copy, falling back to the raw detail. */
  function errText(err: unknown): string {
    const raw = err instanceof Error ? err.message : String(err ?? '')
    const clean = raw.replace(/^vault\.[a-z]+ failed: [^:]+: /i, '')
    if (/vault is locked/i.test(clean)) return t('errLocked')
    if (/title must not be empty/i.test(clean)) return t('errTitleEmpty')
    if (/invalid vault name/i.test(clean)) return t('errInvalidVaultName')
    if (/disabled in readonly mode/i.test(clean)) return t('errReadonly')
    if (clean.length === 0) return t('error')
    return t('errDetail').replace('{detail}', clean)
  }

  /** Format an auto-lock timeout (seconds) for display: 90 → "1m 30s". */
  function formatAutoLock(seconds: number): string {
    if (seconds <= 0) return '0'
    const m = Math.floor(seconds / 60)
    const s = seconds % 60
    if (m === 0) return `${s}s`
    if (s === 0) return `${m}m`
    return `${m}m ${s}s`
  }

  // Suggest an icon from the URL domain (1Password-style visual hint).
  useEffect(() => {
    const url = form.url ?? ''
    if (url.length === 0 || (form.icon ?? '').length > 0) return
    const host = url.replace(/^https?:\/\//i, '').split('/')[0]!.toLowerCase()
    const map: Record<string, string> = {
      github: '🐙', gitlab: '🦊', google: '🔎', 'google.com': '🔎', amazon: '📦', apple: '🍎',
      aws: '☁️', azure: '☁️', digitalocean: '🐳', docker: '🐳', npm: '📦', figma: '🎨',
      notion: '📝', slack: '💬', discord: '🎮', twitter: '🐦', facebook: '👥', instagram: '📷',
      linkedin: '💼', youtube: '▶️', netflix: '🎬', spotify: '🎵', dropbox: '📁', drive: '🗂️',
      microsoft: '🪟', 'microsoft.com': '🪟', office: '🪟', outlook: '✉️', gmail: '✉️', yahoo: '✉️',
      reddit: '👽', twitch: '🎮', steam: '🎮', epic: '🎮', origin: '🎮', pinterest: '📌',
      tiktok: '🎵', snapchat: '👻', whatsapp: '💬', telegram: '✈️', wechat: '💬', zoom: '🎥',
      teams: '💬', skype: '💬', stripe: '💳', paypal: '💰', venmo: '💰', coinbase: '🪙',
      binance: '🪙', kraken: '🪙', robinhood: '📈', fidelity: '📈', chase: '🏦', citi: '🏦',
      wellsfargo: '🏦', bankofamerica: '🏦', airbnb: '🏠', uber: '🚗', lyft: '🚗', doordash: '🍔',
      grubhub: '🍔', instacart: '🛒', ebay: '🛒', etsy: '🧶', shopify: '🛍️', wordpress: '📝',
      medium: '📝', substack: '✉️', hashnode: '💻', vercel: '▲', netlify: '🌐', heroku: '🌐',
      cloudflare: '🌐', godaddy: '🌐', namecheap: '🌐', linode: '🌐', vultr: '🌐', huggingface: '🤗',
      openai: '🤖', anthropic: '🤖', googlecloud: '☁️', firebase: '🔥', supabase: '🔥', mongodb: '🍃',
    }
    const hostBase = host.split('.')[0] ?? ''
    const icon = map[host] ?? map[hostBase] ?? ''
    if (icon) setForm(previous => ({ ...previous, icon }))
  }, [form.url, form.icon])
  useEffect(() => {
    const pw = form.password ?? ''
    if (pw.length === 0) { setPwStrength(null); return }
    const timer = window.setTimeout(() => {
      void strength(pw).then(
        r => setPwStrength({ score: r.score, verdict: r.verdict, bits: r.bits }),
        () => setPwStrength(null),
      )
    }, 250)
    return () => window.clearTimeout(timer)
  }, [form.password, strength])

  // Ctrl/Cmd+K focuses the vault search box (1Password-style quick search);
  // Ctrl/Cmd+N opens the new-entry form; Esc closes the open ⋯ overflow menu.
  useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setActiveTab('entries')
        window.setTimeout(() => searchRef.current?.focus(), 50)
      } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'n') {
        event.preventDefault()
        setActiveTab('entries')
        startCreate()
      } else if (event.key === 'Escape') {
        setOpenMenuId(null)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  /** Apply a template's field values to the current form. The form is reset
   * to its empty state first (so fields the template does not set are cleared
   * rather than leaking the previous template's values), then the template's
   * fields are applied. Secret-ish fields are never filled from a template.
   * Non-catalog kinds (wifi/server/database/identity/bank templates) map to
   * the closest catalog kind so the kind selector and store stay consistent. */
  const CATALOG_KIND: Record<string, string> = {
    wifi: 'login', server: 'ssh', database: 'ssh', identity: 'login', bank: 'card',
  }
  function applyTemplate(name: string): void {
    const tpl = tplList.find(t => t.name === name)
    if (!tpl) return
    const next: Partial<FormFields> = {}
    if (tpl.kind !== 'builtin:custom') {
      const raw = tpl.kind.replace('builtin:', '')
      next.kind = CATALOG_KIND[raw] ?? raw
    }
    for (const [key, value] of Object.entries(tpl.fields)) {
      if (key === 'password' || key === 'otpSecret' || key === 'apiKey' || key === 'secret') continue
      ;(next as Record<string, unknown>)[key] = value
    }
    // Start from a clean form so switching templates never leaves stale values
    // from the previous template behind (the user's reported UX bug).
    setForm({ ...emptyForm(), ...next })
  }

  /** Change the entry kind. When CREATING a new entry, unrelated fields from
   * the previous kind are cleared so the form does not carry stale values; when
   * EDITING an existing entry the other fields are kept (they may be valid for
   * the new kind too, and clearing would risk data loss). */
  function changeKind(kind: string): void {
    setForm(previous => {
      if (editor.status === 'creating') {
        return { ...emptyForm(), kind }
      }
      return { ...previous, kind }
    })
  }

  /** Save the current form as a reusable template. */
  async function saveAsTemplate(): Promise<void> {
    const name = window.prompt(t('tplNamePrompt'))
    if (!name) return
    const fields: Record<string, string> = {}
    for (const key of ['username', 'email', 'phone', 'host', 'port', 'url', 'notes', 'icon', 'color',
      'cardNumber', 'cardExpiry', 'cardCvv', 'cardHolder']) {
      const v = (form as Record<string, unknown>)[key]
      if (typeof v === 'string' && v.length > 0) fields[key] = v
    }
    await saveTemplate(name.trim(), form.kind ?? 'login', fields)
    await templates().then(setTplList).catch(() => {})
    setMessage(`${t('tplSaved')} ${name.trim()}`)
  }

  /** Switch the active vault and reload everything. */
  async function switchVaultTo(name: string): Promise<void> {
    setBusy(true)
    setMessage(null)
    try {
      await switchVault(name)
      await listVaults().then(setVaults)
      setQuery('')
      void backups(20).then(setBackupList).catch(() => {})
      void backupStatus().then(bk => setBackupInfo(bk)).catch(() => {})
      void refresh()
      status().then(value => setLocked(value.locked)).catch(() => {})
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Delete one backup file (confirms first). */
  async function deleteBackupFile(b: { path: string }): Promise<void> {
    if (!window.confirm(t('backupDeleteConfirm'))) return
    setBusy(true)
    setMessage(null)
    try {
      const r = await deleteBackup(b.path)
      setMessage(t('backupDeleted'))
      void backups(20).then(setBackupList).catch(() => {})
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Rename the active (or picked) vault. */
  async function runVaultRename(): Promise<void> {
    const current = vaults.find(v => v.active)?.name ?? 'default'
    const target = window.prompt(`${t('vaultRenamePrompt')} (${current})`)
    if (target === null || target.trim() === '' || target.trim() === current) return
    setBusy(true)
    setMessage(null)
    try {
      const r = await vaultRename(current, target.trim())
      setMessage(r.note)
      await listVaults().then(setVaults)
      void refresh()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Delete a picked vault (confirms first; default vault cannot be deleted). */
  async function runVaultDelete(name: string): Promise<void> {
    if (name === 'default') { setMessage(t('vaultDeleteDefault')); return }
    if (!window.confirm(t('vaultDeleteConfirm').replace('{name}', name))) return
    setBusy(true)
    setMessage(null)
    try {
      const r = await vaultDelete(name, true)
      setMessage(r.note)
      await listVaults().then(setVaults)
      void backups(20).then(setBackupList).catch(() => {})
      void refresh()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Import from Firefox (prompts for the primary password when one is set). */
  async function runFirefoxImport(): Promise<void> {
    const mp = window.prompt(t('firefoxMasterPw'))
    if (mp === null) return
    setBusy(true)
    setMessage(null)
    try {
      const r = await importFirefox(mp, false)
      setMessage(r.note)
      void refresh()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Import from Chrome / Keychain with a confirmation about keychain prompts. */
  async function runSystemImport(source: 'chrome' | 'keychain', preview: boolean): Promise<void> {
    if (source === 'keychain' && !preview) {
      const ok = window.confirm(t('keychainPromptWarn'))
      if (!ok) return
    }
    setBusy(true)
    setMessage(null)
    try {
      const r = source === 'chrome'
        ? await importChrome(false)
        : await keychainImport({ limit: 10, preview })
      setMessage(r.note)
      void refresh()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Import a 1Password 1PUX file (path entered by the user). */
  async function runImport1password(): Promise<void> {
    const path = window.prompt(t('import1passwordPrompt'))
    if (path === null || path.trim() === '') return
    setBusy(true)
    setMessage(null)
    try {
      const r = await import1password(path.trim(), false)
      setMessage(r.note)
      void refresh()
      refreshHealth()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Preview a file import (dry run) — reports counts without writing. */
  async function runImportPreview(run: () => Promise<{ note: string }>): Promise<void> {
    setBusy(true)
    setMessage(null)
    try {
      const r = await run()
      setMessage(`${t('previewLabel')} ${r.note}`)
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Preview a file-based import: prompt for the path, then dry-run. */
  async function runFilePreview(promptKey: string, run: (path: string, overwrite: boolean, dryRun: boolean) => Promise<{ note: string }>): Promise<void> {
    const path = window.prompt(t(promptKey as never))
    if (path === null || path.trim() === '') return
    await runImportPreview(() => run(path.trim(), false, true))
  }

  /** Import a password-manager CSV file (Dashlane/NordPass/Keeper). */
  async function runImportManagerCsv(): Promise<void> {
    const path = window.prompt(t('importManagerCsvPrompt'))
    if (path === null || path.trim() === '') return
    setBusy(true)
    setMessage(null)
    try {
      const r = await importManagerCsv(path.trim(), false)
      setMessage(r.note)
      void refresh()
      refreshHealth()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Two-step CSV import: prompt for the path, then show a masked row preview
   * (titles/usernames only, never passwords) with a confirm before commit —
   * 1Password/Bitwarden-style import safety. */
  async function runCsvImportPreview(): Promise<void> {
    const path = window.prompt(t('importManagerCsvPrompt'))
    if (path === null || path.trim() === '') return
    setBusy(true)
    setMessage(null)
    try {
      const p = await previewImportCsv(path.trim())
      setImportPreview({ path: path.trim(), rows: p.rows, total: p.total, skipped: p.skipped })
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Commit the previewed CSV import. */
  async function confirmCsvImport(): Promise<void> {
    if (importPreview === null) return
    setBusy(true)
    setMessage(null)
    try {
      const r = await importManagerCsv(importPreview.path, false)
      setImportPreview(null)
      setMessage(r.note)
      void refresh()
      refreshHealth()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Import an Enpass JSON export (path entered by the user). */
  async function runImportEnpass(): Promise<void> {
    const path = window.prompt(t('importEnpassPrompt'))
    if (path === null || path.trim() === '') return
    setBusy(true)
    setMessage(null)
    try {
      const r = await importEnpass(path.trim(), false)
      setMessage(r.note)
      void refresh()
      refreshHealth()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Import a Bitwarden JSON export (path entered by the user). */
  async function runImportBitwarden(): Promise<void> {
    const path = window.prompt(t('importBitwardenPrompt'))
    if (path === null || path.trim() === '') return
    setBusy(true)
    setMessage(null)
    try {
      const r = await importBitwarden(path.trim(), false)
      setMessage(r.note)
      void refresh()
      refreshHealth()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Import a Bitwarden password-protected JSON export (asks for the export passphrase). */
  async function runImportBitwardenEncrypted(): Promise<void> {
    const path = window.prompt(t('importBitwardenEncryptedPrompt'))
    if (path === null || path.trim() === '') return
    const password = window.prompt(t('importBitwardenEncryptedPasswordPrompt'))
    if (password === null) return
    setBusy(true)
    setMessage(null)
    try {
      const r = await importBitwardenEncrypted(path.trim(), password, false)
      setMessage(r.note)
      void refresh()
      refreshHealth()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Import a legacy 1Password 1PIF export. */
  async function runImport1pif(): Promise<void> {
    const path = window.prompt(t('import1pifPrompt'))
    if (path === null || path.trim() === '') return
    setBusy(true)
    setMessage(null)
    try {
      const r = await import1pif(path.trim(), false)
      setMessage(r.note)
      void refresh()
      refreshHealth()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Import a KeePass 2.x XML export. */
  async function runImportKeePassXml(): Promise<void> {
    const path = window.prompt(t('importKeePassXmlPrompt'))
    if (path === null || path.trim() === '') return
    setBusy(true)
    setMessage(null)
    try {
      const r = await importKeePassXml(path.trim(), false)
      setMessage(r.note)
      void refresh()
      refreshHealth()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Import a KeePass KDBX binary database (asks for path + optional password). */
  async function runImportKdbx(): Promise<void> {
    const path = window.prompt(t('importKdbxPrompt'))
    if (path === null || path.trim() === '') return
    const password = window.prompt(t('importKdbxPasswordPrompt')) ?? ''
    setBusy(true)
    setMessage(null)
    try {
      const r = await importKdbx(path.trim(), password, '', false)
      setMessage(r.note)
      void refresh()
      refreshHealth()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Export the vault as a 1Password 1PUX archive. */
  async function runExport1pux(): Promise<void> {
    const suggested = t('exportDefaultPath').replace('{file}', `${new Date().toISOString().slice(0, 10)}.1pux`)
    const path = window.prompt(`${t('export1puxPrompt')}\n${t('exportPathHint')}: ${suggested}`, suggested)
    if (path === null || path.trim() === '') return
    setBusy(true)
    setMessage(null)
    try {
      const r = await export1pux(path.trim())
      setMessage(`${t('exportDone')} (${r.count} ${t('entryCount').toLowerCase()}) — ${r.path}`)
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Export the vault as a Bitwarden JSON document. */
  async function runExportBitwarden(): Promise<void> {
    const suggested = t('exportDefaultPath').replace('{file}', `${new Date().toISOString().slice(0, 10)}.json`)
    const path = window.prompt(`${t('exportBitwardenPrompt')}\n${t('exportPathHint')}: ${suggested}`, suggested)
    if (path === null || path.trim() === '') return
    setBusy(true)
    setMessage(null)
    try {
      const r = await exportBitwarden(path.trim())
      setMessage(`${t('exportDone')} (${r.count} ${t('entryCount').toLowerCase()}) — ${r.path}`)
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Export entries as CSV with the user-selected columns. */
  async function runExportCsv(): Promise<void> {
    const suggested = t('exportDefaultPath').replace('{file}', `${new Date().toISOString().slice(0, 10)}.csv`)
    const path = window.prompt(`${t('exportCsvPrompt')}\n${t('exportPathHint')}: ${suggested}`, suggested)
    if (path === null || path.trim() === '') return
    if (exportFields.length === 0) { setMessage(t('exportNoFields')); return }
    setBusy(true)
    setMessage(null)
    try {
      const r = await exportCsv(path.trim(), exportFields)
      setMessage(`${t('exportDone')} (${r.count} ${t('entryCount').toLowerCase()}, ${r.fields.length} ${t('exportColumns')}) — ${r.path}`)
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Search Chrome/Keychain for the typed keyword (no secrets shown). */
  async function searchSystemStores(): Promise<void> {
    if (sysQuery.trim().length === 0) return
    setBusy(true)
    setMessage(null)
    try {
      const r = await searchSystem(sysQuery.trim(), 'all', 15)
      setSysMatches(r.matches)
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Rename a tag across all entries (Bitwarden-style tag merge). */
  async function renameTagAll(from: string): Promise<void> {
    const to = window.prompt(`${t('tagRenamePrompt')} ${from}`)
    if (!to || to.trim().length === 0 || to.trim() === from) return
    await renameTag(from, to.trim())
    await tags().then(setTagList).catch(() => {})
    void refresh()
  }

  /** Merge one duplicate into another (first keeps gaps filled), then refresh. */
  async function mergeEntries(group: Array<{ id: string; title: string }>): Promise<void> {
    if (group.length < 2) return
    setBusy(true)
    setMessage(null)
    try {
      const [first, second] = group
      await merge(second!.id, first!.id, false)
      await duplicateGroups().then(setDupList)
      void refresh()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Lock the vault immediately from the UI. */
  async function lockNow(): Promise<void> {
    setBusy(true)
    try {
      const r = await lock()
      setLocked(r.locked)
      if (r.locked) {
        // The vault is locked: clear the visible list and health data so
        // stale secrets and stats are not left on screen.
        setState({ status: 'ready', entries: [] })
        setReport(null)
        setVaultStats(null)
        setAudit([])
        setDupList([])
        setTagList([])
        setBreach(null)
        setMessage(t('lockedMsg'))
      } else {
        setMessage(t('error'))
      }
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Unlock the vault from the locked banner. */
  async function unlockNow(): Promise<void> {
    setBusy(true)
    try {
      const r = await unlock()
      setLocked(r.locked)
      if (!r.locked) {
        void refresh()
        void status().then(value => setLocked(value.locked)).catch(() => {})
      }
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Export the current security report (weak/reused/no-2FA/http/rotation)
   * as a CSV file (1Password Watchtower-style). Client-side only; the report
   * data is already loaded. */
  async function exportReportCsv(): Promise<void> {
    if (report === null) return
    const esc = (v: unknown): string => {
      const s = String(v ?? '')
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
    }
    const lines: string[] = [`dsh-vault security report,${new Date().toISOString()},score=${report.score},verdict=${report.verdict}`]
    lines.push('')
    lines.push('weak passwords,title')
    for (const w of report.weak as Array<{ title?: string; id?: string }>) lines.push(`weak,${esc(w.title ?? w.id ?? '')}`)
    lines.push('')
    lines.push('reused passwords,title')
    for (const r of report.reused as Array<{ title?: string; id?: string }>) lines.push(`reused,${esc(r.title ?? r.id ?? '')}`)
    lines.push('')
    lines.push('missing 2FA,title')
    for (const n of report.no2fa as Array<{ title?: string; id?: string }>) lines.push(`no-2fa,${esc(n.title ?? n.id ?? '')}`)
    lines.push('')
    lines.push('http sites,title')
    for (const h of report.httpSites as Array<{ title?: string; id?: string }>) lines.push(`http,${esc(h.title ?? h.id ?? '')}`)
    lines.push('')
    lines.push('rotation due,title')
    for (const r of report.rotation as Array<{ title?: string; id?: string }>) lines.push(`rotation,${esc(r.title ?? r.id ?? '')}`)
    const blob = new Blob(['\uFEFF' + lines.join('\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `dsh-vault-security-report-${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    setMessage(t('reportExported'))
  }

  /** Run a Watchtower-style breach scan and show the result. */
  async function runBreachCheck(): Promise<void> {
    setBusy(true)
    setMessage(null)
    try {
      const result = await breachCheck(true)
      setBreach(result)
      if (result.pwned.length === 0 && result.weak.length === 0) {
        setMessage(result.offline ? t('breachOkOffline') : t('breachOk'))
      }
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Run an encrypted backup now and refresh the backup-age badge + list. */
  async function backupNow(): Promise<void> {
    setBusy(true)
    setMessage(null)
    try {
      const result = await backup()
      setBackupInfo({ daysSinceBackup: 0, backups: result.kept })
      setMessage(`${t('backupDone')} (${result.kept} kept, ${result.pruned} pruned)`)
      void backups(20).then(setBackupList).catch(() => {})
      void refresh()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Restore the vault from a backup file (asks for confirmation first). */
  async function restoreBackupFrom(b: { path: string; at: number }): Promise<void> {
    const mode = window.confirm(t('backupRestoreModeMerge'))
      ? 'merge'
      : window.confirm(t('backupRestoreModeReplace')) ? 'replace' : null
    if (mode === null) return
    setBusy(true)
    setMessage(null)
    try {
      const result = await restoreBackup(b.path, mode)
      setMessage(result.note)
      setBackupInfo(null)
      void backups(20).then(setBackupList).catch(() => {})
      void refresh()
      if (result.safetyBackup !== '') setMessage(`${result.note} — ${t('backupSafetyHint')} ${result.safetyBackup}`)
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Reload the sessions lists (open windows + saved sessions). */
  const refreshSessions = useCallback((): void => {
    void sessionListOpen().then(setOpenSessions).catch(() => {})
    void sessionListSaved().then(setSavedSessions).catch(() => {})
  }, [sessionListOpen, sessionListSaved])

  /** Open a browser window for manual login, then show the collect hint. */
  async function runSessionOpen(): Promise<void> {
    if (readonly) { setMessage(t('sessionReadOnly')); return }
    const url = sessionUrl.trim()
    if (url.length === 0) { setMessage(t('sessionUrlPrompt')); return }
    setBusy(true)
    setMessage(null)
    try {
      const result = await sessionOpen(url)
      setMessage(t('sessionNoteOpen').replace('{url}', result.url))
      refreshSessions()
    } catch {
      setMessage(t('sessionOpenFailed'))
    } finally {
      setBusy(false)
    }
  }

  /** Collect cookies from an open window and save them under a title. */
  async function runSessionCollect(sessionId: string, fallbackUrl: string): Promise<void> {
    if (readonly) { setMessage(t('sessionReadOnly')); return }
    let title = sessionTitle.trim()
    if (title.length === 0) {
      const asked = window.prompt(`${t('sessionSaveTitle')} ${t('sessionNamePlaceholder')}`)
      if (asked === null) return
      title = asked.trim()
      if (title.length === 0) return
    }
    setBusy(true)
    setMessage(null)
    try {
      const collected = await sessionCollect(sessionId, fallbackUrl)
      if (collected.count === 0) { setMessage(t('sessionNoteCollect').replace('{n}', '0')); return }
      const saved = await sessionSave({ title, cookies: collected.cookies, url: fallbackUrl, overwrite: true })
      setMessage(t('sessionSaved').replace('{n}', String(saved.saved)))
      setSessionTitle('')
      refreshSessions()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Close a browser window. */
  async function runSessionClose(sessionId: string): Promise<void> {
    setBusy(true)
    try {
      await sessionClose(sessionId)
      refreshSessions()
    } finally {
      setBusy(false)
    }
  }

  /** Copy a saved session as a Cookie header (or jar) to the clipboard. */
  async function runSessionExport(id: string, format: 'header' | 'netscape' | 'playwright'): Promise<void> {
    setBusy(true)
    setMessage(null)
    try {
      const exported = await sessionExport(id, format)
      await navigator.clipboard.writeText(exported.text)
      setCopiedId(id)
      window.setTimeout(() => setCopiedId(current => current === id ? null : current), 1600)
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Show the cookie detail of a saved session. */
  async function runSessionDetail(id: string): Promise<void> {
    setBusy(true)
    try {
      const detail = await sessionGet(id)
      setSessionDetail(detail)
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Remove expired cookies from a saved session (confirms first). */
  async function runSessionPrune(id: string): Promise<void> {
    if (!window.confirm(t('sessionPruneConfirm'))) return
    setBusy(true)
    setMessage(null)
    try {
      const result = await sessionPrune(id, false)
      setMessage(result.note)
      refreshSessions()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Generate a one-time recovery code and show it once (confirm first). */
  async function runRecoveryCode(): Promise<void> {
    if (!window.confirm(t('recoveryCodeConfirm'))) return
    setBusy(true)
    setMessage(null)
    try {
      const r = await recoveryCode()
      window.alert(`${t('recoveryCodeAlert')}\n\n${r.code}\n\n${r.note}`)
      setMessage(t('recoveryCodeSet'))
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Verify a recovery code typed by the user. */
  async function runVerifyRecovery(): Promise<void> {
    const code = window.prompt(t('recoveryCodeVerifyPrompt'))
    if (code === null || code.trim() === '') return
    setBusy(true)
    setMessage(null)
    try {
      const r = await verifyRecovery(code.trim())
      setMessage(r.verified ? t('recoveryVerified') : t('recoveryNotVerified'))
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Save cookies pasted as JSON / header text. */
  async function runSessionImport(): Promise<void> {
    if (readonly) { setMessage(t('sessionReadOnly')); return }
    const title = sessionPasteTitle.trim()
    const raw = sessionPaste.trim()
    if (title.length === 0 || raw.length === 0) { setMessage(t('sessionImportPastePrompt')); return }
    setBusy(true)
    setMessage(null)
    try {
      const parsed = parsePastedCookiesClient(raw)
      if (parsed.length === 0) { setMessage(t('sessionImportPastePrompt')); return }
      const saved = await sessionSave({ title, cookies: parsed, overwrite: true })
      setMessage(t('sessionSaved').replace('{n}', String(saved.saved)))
      setSessionPaste('')
      setSessionPasteTitle('')
      refreshSessions()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Client-side cookie parser (mirrors the host parsePastedCookies). */
  function parsePastedCookiesClient(text: string): unknown[] {
    const trimmed = text.trim()
    if (trimmed.length === 0) return []
    const out: unknown[] = []
    if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed) as unknown
        const rows = Array.isArray(parsed) ? parsed : [parsed]
        for (const row of rows) {
          if (typeof row !== 'object' || row === null) continue
          const r = row as Record<string, unknown>
          if (typeof r.name !== 'string' || typeof r.value !== 'string' || typeof r.domain !== 'string') continue
          out.push({
            name: r.name, value: r.value, domain: r.domain,
            path: typeof r.path === 'string' ? r.path : '/',
            expires: typeof r.expires === 'number' ? r.expires : -1,
            httpOnly: r.httpOnly === true, secure: r.secure === true,
            ...(r.sameSite === 'Strict' || r.sameSite === 'Lax' || r.sameSite === 'None' ? { sameSite: r.sameSite } : {}),
          })
        }
      } catch { return [] }
    } else {
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

  useEffect(() => {
    let current = true
    void config().then(
      value => { if (current) setPolicy(value) },
      () => { /* policy is informational; ignore failures */ },
    )
    void status().then(
      value => { if (current) setLocked(value.locked) },
      () => { /* ignore */ },
    )
    void listVaults().then(setVaults).catch(() => {})
    void templates().then(setTplList).catch(() => {})
    void watchtower().then(list => {
      const map: Record<string, { score: number; verdict: string; flags: string[] }> = {}
      for (const w of list) map[w.id] = { score: w.score, verdict: w.verdict, flags: w.flags }
      setWatchMap(map)
    }).catch(() => {})
    refreshSessions()
    return () => { current = false }
  }, [config, status, listVaults, templates, refreshSessions])

  /** Re-fetch the dashboard metadata (rotation/health/stats/recent/tags/audit/
   * trash…) so badges, filters and counts stay current after writes. */
  const refreshMeta = useCallback((): void => {
    void Promise.all([
      stats().catch(() => null),
      backupStatus().catch(() => null),
      rotation().catch(() => []),
      health().catch(() => null),
      recent().catch(() => []),
      history().catch(() => []),
      duplicates().catch(() => null),
    ]).then(([st, bk, rot, hl, rc, hst, dp]) => {
      if (dp !== null && typeof dp === 'object' && (dp as { groups?: number }).groups !== undefined) {
        setDupGroups((dp as { groups: number }).groups)
      }
      if (Array.isArray(hst)) setRecentEvents(hst as Array<Record<string, unknown>>)
      duplicateGroups().then(setDupList).catch(() => {})
      verifyAll().then(setAudit).catch(() => {})
      tags().then(setTagList).catch(() => {})
      generatorHistory().then(setGenHistory).catch(() => {})
      backups(20).then(setBackupList).catch(() => {})
      trash().then(setTrashEntries).catch(() => {})
      if (st !== null) setVaultStats(st as Record<string, unknown>)
      if (bk !== null) setBackupInfo(bk)
      setReport({ rotation: (rot ?? []) as unknown[], weak: ((hl?.weak ?? []) as unknown[]), reused: ((hl?.reused ?? []) as unknown[]), strength: (hl?.strength ?? null) as { weak: number; fair: number; strong: number } | null, no2fa: ((hl?.no2fa ?? []) as unknown[]), httpSites: ((hl?.httpSites ?? []) as unknown[]), score: Number(hl?.score ?? 100), verdict: String(hl?.verdict ?? 'good') })
      const due: Record<string, { due: string; daysLeft: number }> = {}
      for (const item of (rot ?? []) as Array<{ id?: string; due?: string; daysLeft?: number }>) {
        if (item.id !== undefined && item.due !== undefined) due[item.id] = { due: item.due, daysLeft: item.daysLeft ?? 0 }
      }
      setDueMap(due)
      setRecentEntries((rc ?? []) as Array<Record<string, unknown>>)
    })
  }, [stats, backupStatus, rotation, health, recent, duplicates, duplicateGroups, verifyAll, tags, generatorHistory, backups])

  const refresh = useMemo(() => async () => {
    setState({ status: 'loading' })
    try {
      const entries = query.trim().length === 0
        ? await list()
        : await search(query.trim())
      setState({ status: 'ready', entries })
      setVisibleCount(50)
      status().then(value => setLocked(value.locked)).catch(() => {})
      // Keep badges/filters/counts (due, health, stats, trash, …) in sync
      // after writes — previously they only updated on mount or focus.
      refreshMeta()
    } catch (err) {
      // A locked vault makes list() throw; surface the locked banner instead
      // of a generic failure (the user can unlock, not retry). Even when
      // status() itself fails (e.g. an older host), a lock-shaped error still
      // flips the locked flag so write actions stay disabled.
      const st = await status().catch(() => null)
      const raw = err instanceof Error ? err.message : String(err ?? '')
      const lockError = (st !== null && st.locked) || /vault is locked/i.test(raw)
      if (lockError) {
        setLocked(true)
        setState({ status: 'ready', entries: [] })
      } else {
        setState({ status: 'error', reason: errText(err) })
      }
    }
  }, [list, search, query, refreshMeta])

  useEffect(() => {
    let current = true
    const timer = window.setTimeout(() => {
      void refresh().then(
        () => { /* state already set inside refresh */ },
        () => { if (current) setState({ status: 'error' }) },
      )
    }, 250)
    return () => { current = false; window.clearTimeout(timer) }
    // refresh is memoized on query (debounced); list/search are stable.
  }, [refresh])

  // TOTP countdown: tick every second so the progress ring stays live, and
  // auto-refresh any code whose 30s window just expired.
  useEffect(() => {
    const timer = window.setInterval(() => setNowTick(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    for (const [id, info] of Object.entries(totpMap)) {
      if (info.until > 0 && nowTick >= info.until && info.code !== t('error')) {
        void totp(id).then(
          result => setTotpMap(previous => ({
            ...previous,
            [id]: { code: result.code, until: Date.now() + result.secondsRemaining * 1000 },
          })),
          () => { /* keep the last code; next window retries */ },
        )
      }
    }
  }, [nowTick, totpMap, totp])

  // KeePassXC #9247-style inline TOTP: auto-fetch the current code for every
  // entry that carries an otpSecret, so the row shows live digits without a
  // menu click. Batched (max 25 per pass) so huge vaults never burst requests;
  // entries already cached with a live window are skipped. The ticker above
  // keeps them fresh across 30s boundaries.
  useEffect(() => {
    if (state.status !== 'ready') return
    const targets = state.entries
      .filter(e => e.hasOtp === true)
      .filter(e => {
        const info = totpMap[e.id]
        return info === undefined || info.until <= 0 || info.code === t('error')
      })
      .slice(0, 25)
    for (const e of targets) {
      void totp(e.id).then(
        result => setTotpMap(previous => ({ ...previous, [e.id]: { code: result.code, until: Date.now() + result.secondsRemaining * 1000 } })),
        () => { /* secret removed or vault locked; row simply shows no code */ },
      )
    }
  }, [state.status === 'ready' ? state.entries : null, totpMap, totp, t])

  // Load attachments when an entry is expanded.
  useEffect(() => {
    if (expandedId === null) return
    let current = true
    void attachments(expandedId).then(r => {
      if (current && r.found) setAttachmentsMap(prev => ({ ...prev, [expandedId]: r.attachments }))
    }).catch(() => {})
    return () => { current = false }
  }, [expandedId, attachments])

  /** Recompute just the health report (weak/reused/no-2FA/rotation) after a
   * write so the toolbar badges stay current without a full reload. */
  const refreshHealth = useCallback(() => {
    void health().then(hl => {
      setReport(previous => ({
        ...(previous ?? { rotation: [], weak: [], reused: [], strength: null, no2fa: [], httpSites: [], score: 100, verdict: 'good' }),
        weak: (hl?.weak ?? []) as unknown[],
        reused: (hl?.reused ?? []) as unknown[],
        strength: (hl?.strength ?? null) as { weak: number; fair: number; strong: number } | null,
        no2fa: ((hl?.no2fa ?? []) as unknown[]),
        httpSites: ((hl?.httpSites ?? []) as unknown[]),
        score: Number(hl?.score ?? 100),
        verdict: String(hl?.verdict ?? 'good'),
      }))
    }).catch(() => {})
    void history().then(events => setRecentEvents((events ?? []) as Array<Record<string, unknown>>)).catch(() => {})
  }, [health, history])

  // Vault health & meta: load once on mount (stats, backup age, rotation,
  // weak/reused scan, recent activity) and refresh on window focus.
  useEffect(() => {
    let current = true
    refreshMeta()
    const onFocus = (): void => { if (current) refreshMeta() }
    window.addEventListener('focus', onFocus)
    return () => { current = false; window.removeEventListener('focus', onFocus) }
  }, [refreshMeta])

  /** Open the editor for a new entry. */
  function startCreate(): void {
    setForm(emptyForm())
    setTagsDraft('')
    setFieldsDraft('')
    setMessage(null)
    setEditor({ status: 'creating' })
  }

  /** Record a completed search term (most-recent first, deduped, ≤8). */
  function rememberSearch(term: string): void {
    const next = [term, ...recentSearches.filter(s => s.toLowerCase() !== term.toLowerCase())].slice(0, 8)
    setRecentSearches(next)
    try {
      window.sessionStorage.setItem('dsh-vault-recent-searches', JSON.stringify(next))
    } catch { /* storage may be unavailable */ }
  }

  /** Open the editor for an existing entry (fetches full secrets). */
  async function startEdit(id: string): Promise<void> {
    setBusy(true)
    setMessage(null)
    try {
      const result = await get(id)
      if (!result.found || result.entry === undefined) {
        setMessage(t('entryNotFound'))
        return
      }
      const entry = result.entry
      setForm({
        title: entry.title ?? '',
        kind: entry.kind ?? 'login',
        username: entry.username ?? '',
        email: entry.email ?? '',
        phone: entry.phone ?? '',
        password: entry.password ?? '',
        host: entry.host ?? '',
        port: entry.port ?? '',
        privateKey: entry.privateKey ?? '',
        apiKey: entry.apiKey ?? '',
        secret: entry.secret ?? '',
        accessToken: entry.accessToken ?? '',
        refreshToken: entry.refreshToken ?? '',
        otpSecret: entry.otpSecret ?? '',
        url: entry.url ?? '',
        notes: entry.notes ?? '',
        icon: entry.icon ?? '',
        color: entry.color ?? '',
        expiresAt: entry.expiresAt,
        rotationDays: entry.rotationDays,
        sensitivity: entry.sensitivity,
        favorite: entry.favorite ?? false,
      })
      setTagsDraft((entry.tags ?? []).join(', '))
      setFieldsDraft(entry.fields !== undefined ? Object.entries(entry.fields).map(([k, v]) => `${k}=${String(v)}`).join('\n') : '')
      setEditor({ status: 'editing', entry })
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Save the current form (create or update). */
  async function save(): Promise<void> {
    if (!(form.title ?? '').trim()) {
      setMessage(t('errTitleEmpty'))
      return
    }
    // Port must be a number in 1–65535 when provided (inline validation).
    if (form.port !== undefined && form.port !== '' && !/^\d{1,5}$/.test(form.port.trim())) {
      setMessage(t('errInvalidPort'))
      return
    }
    if (form.port !== undefined && form.port !== '' && Number(form.port) > 65535) {
      setMessage(t('errInvalidPort'))
      return
    }
    // Editing an existing entry and actually typing a new password: confirm
    // (Bitwarden-style). An empty form password (entry had none, or the user
    // cleared it) is not a change, so it never prompts.
    const entryPw = editor.status === 'editing' ? (editor.entry?.password ?? '') : ''
    const typedPw = (form.password ?? '').trim()
    if (editor.status === 'editing' && typedPw.length > 0 && typedPw !== entryPw) {
      if (!window.confirm(t('pwChangeConfirm'))) return
    }
    setBusy(true)
    setMessage(null)
    try {
      const tags = tagsDraft.split(',').map(x => x.trim()).filter(x => x.length > 0)
      const fields: Record<string, string> = {}
      for (const line of fieldsDraft.split('\n')) {
        const trimmed = line.trim()
        if (trimmed.length === 0) continue
        const eq = trimmed.indexOf('=')
        if (eq <= 0) continue
        fields[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim()
      }
      const patch: VaultPatch = {
        title: (form.title ?? '').trim(),
        ...(form.kind !== undefined ? { kind: form.kind } : {}),
        ...(form.username !== undefined ? { username: form.username } : {}),
        ...(form.email !== undefined ? { email: form.email } : {}),
        ...(form.phone !== undefined ? { phone: form.phone } : {}),
        ...(form.password !== undefined ? { password: form.password } : {}),
        ...(form.host !== undefined ? { host: form.host } : {}),
        ...(form.port !== undefined ? { port: form.port } : {}),
        ...(form.privateKey !== undefined ? { privateKey: form.privateKey } : {}),
        ...(form.apiKey !== undefined ? { apiKey: form.apiKey } : {}),
        ...(form.secret !== undefined ? { secret: form.secret } : {}),
        ...(form.accessToken !== undefined ? { accessToken: form.accessToken } : {}),
        ...(form.refreshToken !== undefined ? { refreshToken: form.refreshToken } : {}),
        ...(form.otpSecret !== undefined ? { otpSecret: form.otpSecret } : {}),
        ...(form.url !== undefined ? { url: form.url } : {}),
        ...(form.notes !== undefined ? { notes: form.notes } : {}),
        ...(form.icon !== undefined ? { icon: form.icon } : {}),
        ...(form.color !== undefined ? { color: form.color } : {}),
        ...(form.expiresAt !== undefined ? { expiresAt: form.expiresAt } : {}),
        ...(form.rotationDays !== undefined ? { rotationDays: form.rotationDays } : {}),
        ...(form.sensitivity !== undefined ? { sensitivity: form.sensitivity } : {}),
        ...(form.favorite !== undefined ? { favorite: form.favorite } : {}),
        // Always send tags: an empty array clears them, and the host store
        // treats empty string values as "clear this field" too.
        tags,
        fields,
      }
      if (editor.status === 'creating') {
        await add(patch as VaultPatch & { title: string })
        setMessage(t('savedNew'))
      } else if (editor.status === 'editing') {
        await update(editor.entry.id, patch)
        setMessage(t('savedUpdated'))
      }
      setEditor({ status: 'closed' })
      await refresh()
      refreshHealth()
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Delete an entry after confirmation. */
  async function removeEntry(id: string): Promise<void> {
    if (!window.confirm(t('deleteConfirm'))) return
    const title = state.status === 'ready' ? state.entries.find(e => e.id === id)?.title ?? '' : ''
    setBusy(true)
    try {
      await remove(id)
      await refresh()
      refreshHealth()
      // Keep the trash tab in sync so the just-deleted entry shows up there.
      await trash().then(setTrashEntries).catch(() => {})
      setMessage(title !== '' ? t('deletedWithTitle').replace('{name}', title) : t('deleted'))
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Toggle batch-select mode (Bitwarden-style bulk operations). */
  function toggleSelectMode(): void {
    setSelectMode(m => {
      const next = !m
      if (!next) setSelectedIds(new Set())
      return next
    })
  }

  /** Delete all selected entries after one confirmation (bulk operation). */
  async function removeSelected(): Promise<void> {
    if (selectedIds.size === 0) return
    if (!window.confirm(t('bulkDeleteConfirm').replace('{n}', String(selectedIds.size)))) return
    const count = selectedIds.size
    setBusy(true)
    try {
      await Promise.all([...selectedIds].map(id => remove(id)))
      setSelectedIds(new Set())
      setSelectMode(false)
      await refresh()
      refreshHealth()
      // Keep the trash tab in sync (bulk delete moves every entry to trash).
      await trash().then(setTrashEntries).catch(() => {})
      setMessage(t('bulkDeleted').replace('{n}', String(count)))
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Bulk favorite/unfavorite the selected entries (1Password-style mass
   * tagging of pins). Uses the existing setFavorite remote in parallel, then
   * a single refresh so the ★ 收藏 view updates immediately. */
  async function bulkSetFavorite(favorite: boolean): Promise<void> {
    const count = selectedIds.size
    if (count === 0) return
    setBusy(true)
    try {
      await Promise.all([...selectedIds].map(id => setFavorite(id, favorite)))
      setSelectedIds(new Set())
      setSelectMode(false)
      await refresh()
      refreshMeta()
      setMessage(favorite ? t('bulkFavorited').replace('{n}', String(count)) : t('bulkUnfavorited').replace('{n}', String(count)))
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Append one tag to every selected entry (1Password Bulk Tagging-style). */
  async function bulkAddTag(): Promise<void> {
    const count = selectedIds.size
    if (count === 0) return
    const asked = window.prompt(t('bulkTagPrompt'))
    if (asked === null) return
    const tag = asked.trim().replace(/^#/, '')
    if (tag.length === 0) return
    setBusy(true)
    try {
      await Promise.all([...selectedIds].map(async id => {
        const r = await get(id)
        if (!r.found || r.entry === undefined) return
        const tags = r.entry.tags ?? []
        if (tags.includes(tag)) return
        await update(id, { tags: [...tags, tag] })
      }))
      setSelectedIds(new Set())
      setSelectMode(false)
      await refresh()
      refreshMeta()
      setMessage(t('bulkTagged').replace('{n}', String(count)))
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Clone an entry (Bitwarden/KeePassXC-style): copy every editable field
   * into a new entry with a localized title suffix. Attachments and password
   * history stay with the original; the copy gets its own timestamps. */
  async function cloneEntry(id: string): Promise<void> {
    setBusy(true)
    try {
      const r = await get(id)
      if (!r.found || r.entry === undefined) {
        setMessage(t('entryNotFound'))
        return
      }
      const e = r.entry
      const patch = {
        title: `${e.title}${t('cloneSuffix')}`,
        ...(e.kind !== undefined ? { kind: e.kind } : {}),
        ...(e.username !== undefined ? { username: e.username } : {}),
        ...(e.email !== undefined ? { email: e.email } : {}),
        ...(e.phone !== undefined ? { phone: e.phone } : {}),
        ...(e.password !== undefined ? { password: e.password } : {}),
        ...(e.host !== undefined ? { host: e.host } : {}),
        ...(e.port !== undefined ? { port: e.port } : {}),
        ...(e.privateKey !== undefined ? { privateKey: e.privateKey } : {}),
        ...(e.apiKey !== undefined ? { apiKey: e.apiKey } : {}),
        ...(e.secret !== undefined ? { secret: e.secret } : {}),
        ...(e.accessToken !== undefined ? { accessToken: e.accessToken } : {}),
        ...(e.refreshToken !== undefined ? { refreshToken: e.refreshToken } : {}),
        ...(e.expiresAt !== undefined ? { expiresAt: e.expiresAt } : {}),
        ...(e.rotationDays !== undefined ? { rotationDays: e.rotationDays } : {}),
        ...(e.sensitivity !== undefined ? { sensitivity: e.sensitivity } : {}),
        ...(e.favorite !== undefined ? { favorite: e.favorite } : {}),
        ...(e.otpSecret !== undefined ? { otpSecret: e.otpSecret } : {}),
        ...(e.url !== undefined ? { url: e.url } : {}),
        ...(e.notes !== undefined ? { notes: e.notes } : {}),
        ...(e.tags !== undefined ? { tags: e.tags } : {}),
        ...(e.icon !== undefined ? { icon: e.icon } : {}),
        ...(e.color !== undefined ? { color: e.color } : {}),
        ...(e.fields !== undefined ? { fields: e.fields } : {}),
      }
      const added = await add(patch)
      await refresh()
      refreshHealth()
      setMessage(t('clonedWithTitle').replace('{name}', added.title))
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Attach a file picked in the browser to an entry (base64 → host). */
  function attachFile(id: string, file: File | undefined): void {
    if (file === undefined) return
    setBusy(true)
    const reader = new FileReader()
    reader.onload = () => {
      const dataBase64 = String(reader.result ?? '').split(',')[1] ?? ''
      void attach(id, file.name, dataBase64, file.type.length > 0 ? file.type : undefined).then(r => {
        if (!r.attached) setMessage(t('entryNotFound'))
        else void attachments(id).then(rr => { if (rr.found) setAttachmentsMap(prev => ({ ...prev, [id]: rr.attachments })) })
        setBusy(false)
      }, () => setBusy(false))
    }
    reader.onerror = () => setBusy(false)
    reader.readAsDataURL(file)
  }

  /** Download one attachment back to disk (base64 → Blob → save). */
  async function downloadAttachmentFile(id: string, name: string): Promise<void> {
    setBusy(true)
    try {
      const r = await downloadAttachment(id, name)
      if (!r.found || r.dataBase64 === undefined || r.name === undefined) {
        setMessage(t('attachmentNotFound'))
        return
      }
      const binary = atob(r.dataBase64)
      const bytes = new Uint8Array(binary.length)
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
      const blob = new Blob([bytes], { type: r.mime ?? 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = r.name
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Show an entry's password history (1Password-style) and allow rollback. */
  async function showPasswordHistory(id: string): Promise<void> {
    setBusy(true)
    try {
      const h = await passwordHistory(id)
      setPwHistory(h)
      setPwHistoryFor(id)
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Roll the entry's password back to a history point. */
  async function rollbackPassword(at: number): Promise<void> {
    if (pwHistoryFor === null) return
    if (!window.confirm(t('pwRollbackConfirm'))) return
    setBusy(true)
    try {
      const r = await passwordRollback(pwHistoryFor, at)
      if (r.rolledBack) {
        setMessage(t('pwRolledBack'))
        setPwHistory(null)
        setPwHistoryFor(null)
        void refresh()
        refreshHealth()
      } else {
        setMessage(t('pwRollbackFailed'))
      }
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Export the audit log (respecting the current filter) as a CSV file. */
  function exportAuditLog(): void {
    const rows = recentEvents
      .filter(ev => auditFilter === '' || String(ev.action ?? '') === auditFilter)
      .map(ev => {
        const ts = Number((ev as Record<string, unknown>).at)
        const when = Number.isFinite(ts) && ts > 0 ? new Date(ts).toLocaleString() : ''
        return `${String(ev.action ?? '')},${String(ev.title ?? ev.id ?? '')},${when}`
      })
    if (rows.length === 0) return
    const blob = new Blob(['\uFEFFaction,entry,time\n' + rows.join('\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `dsh-vault-audit-${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }
  const clipboardTimer = useRef<number | null>(null)
  const CLIPBOARD_CLEAR_MS = 30_000

  async function copyValue(id: string, value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value)
    } catch {
      // Clipboard may be blocked; fall back to a temporary textarea.
      const textarea = document.createElement('textarea')
      textarea.value = value
      document.body.appendChild(textarea)
      textarea.select()
      document.execCommand('copy')
      textarea.remove()
    }
    setCopiedId(id)
    window.setTimeout(() => setCopiedId(null), 3000)
    // Auto-clear the clipboard after 30s (1Password/Bitwarden-style), so a
    // copied secret does not linger for anyone using the machine later. Only
    // clear when the clipboard still holds the value we copied — if the user
    // copied something else meanwhile, never wipe their content.
    if (clipboardTimer.current !== null) window.clearTimeout(clipboardTimer.current)
    const copied = value
    clipboardTimer.current = window.setTimeout(() => {
      clipboardTimer.current = null
      void navigator.clipboard.readText().then(current => {
        if (current === copied) void navigator.clipboard.writeText('').catch(() => {})
      }).catch(() => {})
    }, CLIPBOARD_CLEAR_MS)
  }

  /** Fetch and show the otpauth URI for an entry (for adding to another device). */
  async function showTotpUri(id: string): Promise<void> {
    setBusy(true)
    try {
      const r = await totpUri(id)
      setUriMap(previous => ({ ...previous, [id]: previous[id] === r.uri ? '' : r.uri }))
    } catch (err) {
      setMessage(errText(err))
    } finally {
      setBusy(false)
    }
  }

  /** Fetch and display a TOTP code for an entry with an otpSecret. */
  async function showTotp(id: string): Promise<void> {
    setBusy(true)
    try {
      const result = await totp(id)
      setTotpMap(previous => ({ ...previous, [id]: { code: result.code, until: Date.now() + result.secondsRemaining * 1000 } }))
      // Auto-copy the code (Bitwarden/1Password-style one-tap flow).
      void copyValue(id, result.code)
    } catch {
      setTotpMap(previous => ({ ...previous, [id]: { code: t('error'), until: 0 } }))
    } finally {
      setBusy(false)
    }
  }

  /** Relative time like "5m ago" / "2d ago". */
  function relTime(epoch: unknown): string {
    const n = Number(epoch)
    if (!Number.isFinite(n) || n <= 0) return ''
    const secs = Math.max(0, Math.floor((Date.now() - n) / 1000))
    if (secs < 60) return `${secs}s`
    if (secs < 3600) return `${Math.floor(secs / 60)}m`
    if (secs < 86400) return `${Math.floor(secs / 3600)}h`
    return `${Math.floor(secs / 86400)}d`
  }

  /** Card-expiry reminder badge: "卡到期 MM/YY" when within 3 months or past.
   * Returns '' when there is no expiry or it is far away. */
  function cardExpiryBadge(entry: VaultSummaryWire): string {
    const raw = entry.cardExpiry
    if (raw === undefined || raw === '') return ''
    const m = /^(\d{2})\/(\d{2,4})$/.exec(raw.trim())
    if (!m) return ''
    const month = Number(m[1]) - 1
    const year = Number(m[2]) + (m[2]!.length === 2 ? 2000 : 0)
    const end = new Date(year, month + 1, 0, 23, 59, 59) // last day of month
    if (Number.isNaN(end.getTime())) return ''
    const now = Date.now()
    const monthsLeft = (end.getTime() - now) / (30 * 24 * 3600 * 1000)
    if (end.getTime() < now) return t('cardExpired') + ' ' + raw.trim()
    if (monthsLeft <= 3) return t('cardExpiring') + ' ' + raw.trim()
    return ''
  }

  /** Human-friendly value formatting for the expanded detail box. */
  function formatDetail(key: string, value: unknown): string {
    if (key === 'expiresAt' || key === 'updatedAt' || key === 'createdAt') {
      const n = Number(value)
      return Number.isFinite(n) && n > 0 ? new Date(n).toISOString().slice(0, 16).replace('T', ' ') : String(value)
    }
    if (key === 'sensitivity' && value === 'high') return t('sensitivityHigh')
    if (key === 'kind') return t(KIND_KEYS[String(value)] ?? 'kindCustom')
    if (Array.isArray(value)) return value.join(', ')
    if (key === 'fields' && typeof value === 'object' && value !== null) {
      return Object.entries(value as Record<string, string>).map(([k, v]) => `${k}: ${String(v)}`).join(', ')
    }
    if (typeof value === 'object' && value !== null) return JSON.stringify(value)
    return String(value)
  }

  /** Field-set summary line for one entry (non-secret). */
  function kindIcon(kind?: string): string {
    switch (kind ?? 'login') {
      case 'ssh': return '🖥️'
      case 'api-key': return '🔑'
      case 'oauth': return '🔐'
      case 'secret': return '🤫'
      case 'cookie': return '🍪'
      case 'card': return '💳'
      case 'custom': return '🧩'
      default: return '👤'
    }
  }

  function passwordAge(entry: VaultSummaryWire): string {
    const up = entry.updatedAt
    if (up === undefined || up <= 0) return ''
    const days = Math.max(0, Math.floor((Date.now() - up) / 86_400_000))
    if (days === 0) return t('ageToday')
    return `${days}d`
  }

  function identityLine(entry: VaultSummaryWire): string {
    const parts = [
      entry.kind !== undefined ? t(KIND_KEYS[entry.kind] ?? 'kindCustom') : t('kindLogin'),
      entry.username,
      entry.email,
      entry.phone,
      entry.host !== undefined ? `${entry.host}${entry.port !== undefined ? `:${entry.port}` : ''}` : undefined,
      entry.url,
    ].filter((value): value is string => value !== undefined && value.length > 0)
    return parts.join(' · ')
  }

  return (
    <section className={css.section} aria-labelledby="vault-heading">
      <h2 id="vault-heading">{t('heading')}</h2>
      <p className={css.intro}>{t('intro')}</p>

      {locked && (
        <div className={css.lockedBanner} role="alert">
          <p>{t('lockedBanner')}</p>
          <button type="button" className={css.backupButton} onClick={() => void unlockNow()} disabled={busy}>{t('unlock')}</button>
        </div>
      )}

      <nav className={css.tabs} aria-label={t('sectionTabs')}>
        {(['entries', 'security', 'transfer', 'backup', 'permissions', 'sessions', 'audit', 'trash'] as const).map(tab => (
          <button
            key={tab}
            type="button"
            className={`${css.tab}${activeTab === tab ? ` ${css.tabActive}` : ''}`}
            onClick={() => setActiveTab(tab)}
          >{t(TAB_KEYS[tab]!)}</button>
        ))}
      </nav>

      {activeTab === 'entries' && (<div className={css.tabPane}>
      <div className={css.toolbar}>
        {locked && (
          <span className={css.lockedTag}>{t('lockedShort')}</span>
        )}
        {vaults.length > 0 && (
          <select
            className={css.kindFilter}
            value={vaults.find(v => v.active)?.name ?? ''}
            onChange={event => void switchVaultTo(event.target.value)}
            aria-label={t('vaultSelect')}
            disabled={locked}
          >
            {vaults.map(v => (
              <option key={v.name} value={v.name}>{v.name}{v.active ? ' *' : ''}{v.entries !== undefined ? ` (${v.entries})` : ''}</option>
            ))}
          </select>
        )}
        <button type="button" className={css.dupMerge} onClick={() => void runVaultRename()} disabled={busy || locked} title={t('vaultRename')}>{t('vaultRename')}</button>
        {vaults.filter(v => v.name !== 'default').map(v => (
          <button key={v.name} type="button" className={css.dangerButton} onClick={() => void runVaultDelete(v.name)} disabled={busy || locked} title={t('vaultDelete')}>{t('vaultDelete')} {v.name}</button>
        ))}
        <label className={css.searchBox}>
          <span className={css.srOnly}>{t('searchPlaceholder')}</span>
          <input
            id={searchId}
            ref={searchRef}
            type="search"
            placeholder={t('searchPlaceholder')}
            value={query}
            onChange={event => setQuery(event.target.value)}
            onKeyDown={event => {
              if (event.key === 'Escape') { setQuery(''); setKindFilter(''); setTagFilter('') }
              if (event.key === 'Enter' && query.trim().length > 0) rememberSearch(query.trim())
            }}
            disabled={locked}
          />
          {query.length > 0 && (
            <button type="button" className={css.clearButton} onClick={() => setQuery('')} aria-label={t('clearSearch')}>×</button>
          )}
        </label>
        <select className={css.kindFilter} value={kindFilter} onChange={e => setKindFilter(e.target.value)} aria-label={t('fieldKind')}>
          <option value="">{t('allKinds')}</option>
          {Object.entries(KIND_KEYS).map(([value, key]) => (
            <option key={value} value={value}>{t(key)}</option>
          ))}
        </select>
        <select className={css.kindFilter} value={tagFilter} onChange={e => setTagFilter(e.target.value)} aria-label={t('fieldTags')}>
          <option value="">{t('allTags')}</option>
          {[...new Set(state.status === 'ready' ? state.entries.flatMap(e => e.tags ?? []) : [])].sort().map(tag => (
            <option key={tag} value={tag}>{tag}</option>
          ))}
        </select>
        <button
          type="button"
          className={css.favToggle}
          onClick={() => setTagManagerOpen(value => !value)}
          aria-pressed={tagManagerOpen}
          title={t('tagManagerHint')}
        >🏷 {t('tagManager')}</button>
        <select
          className={css.sortButton}
          value={sortBy}
          onChange={event => setSortBy(event.target.value as 'alpha' | 'recent' | 'created' | 'favorite' | 'smart')}
          aria-label={t('sortBy')}
        >
          <option value="alpha">{t('sortAlpha')}</option>
          <option value="recent">{t('sortRecent')}</option>
          <option value="created">{t('sortCreated')}</option>
          <option value="favorite">{t('sortFavorite')}</option>
          <option value="smart">{t('sortSmart')}</option>
        </select>
        <button
          type="button"
          className={`${css.favToggle}${favOnly ? ` ${css.favActive}` : ''}`}
          onClick={() => setFavOnly(value => !value)}
          aria-pressed={favOnly}
          title={t('favOnlyHint')}
        >★ {t('favOnly')}</button>
        <button
          type="button"
          className={`${css.favToggle}${dueOnly ? ` ${css.favActive}` : ''}`}
          onClick={() => setDueOnly(value => !value)}
          aria-pressed={dueOnly}
          title={t('dueOnlyHint')}
        >⏰ {t('dueOnly')}</button>
        {report !== null && (report.weak.length > 0 || report.reused.length > 0 || report.no2fa.length > 0 || report.httpSites.length > 0 || report.rotation.length > 0) && (
          <span className={css.healthSummary} title={t('healthSummaryHint')}>
            {report.weak.length > 0 && <span className={`${css.badge} ${css.badgeDanger}`}>{t('reportWeak')}: {report.weak.length}</span>}
            {report.reused.length > 0 && <span className={`${css.badge} ${css.badgeDanger}`}>{t('reportReused')}: {report.reused.length}</span>}
            {report.no2fa.length > 0 && <span className={`${css.badge} ${css.badgeWarn}`}>{t('no2fa')}: {report.no2fa.length}</span>}
            {report.httpSites.length > 0 && <span className={`${css.badge} ${css.badgeWarn}`}>{t('httpSites')}: {report.httpSites.length}</span>}
            {report.rotation.length > 0 && <span className={`${css.badge} ${css.badgeWarn}`}>{t('reportRotation')}: {report.rotation.length}</span>}
          </span>
        )}
        {report !== null && report.weak.length === 0 && report.reused.length === 0 && report.no2fa.length === 0 && report.httpSites.length === 0 && report.rotation.length === 0 && (
          <span className={`${css.badge} ${css.badgeOk}`} title={t('healthSummaryHint')}>{t('healthOk')} ✓</span>
        )}
        <button type="button" className={css.addButton} onClick={startCreate} disabled={busy || readonly || locked}>
          + {t('add')}
        </button>
        {!readonly && !locked && (
          <button type="button" className={selectMode ? `${css.dupMerge} ${css.selectActive}` : css.dupMerge} onClick={toggleSelectMode} disabled={busy}>
            {selectMode ? t('bulkDone') : t('bulkSelect')}
          </button>
        )}
      </div>
      {tagManagerOpen && (
        <div className={css.tagManager}>
          <div className={css.tagManagerHead}>
            <span className={css.reportTitle}>{t('tagManager')}</span>
            <button type="button" className={css.recentClear} onClick={() => setTagManagerOpen(false)}>{t('cancel')}</button>
          </div>
          {tagList.length === 0 && <p className={css.reportSub}>{t('noTags')}</p>}
          {tagList.map(tag => (
            <div key={tag.name} className={css.tagRow}>
              <span className={css.tagName}>🏷 {tag.name} <span className={css.tagCount}>({tag.count})</span></span>
              <span className={css.tagActions}>
                <button
                  type="button"
                  className={css.dupMerge}
                  disabled={busy || readonly || locked}
                  onClick={() => {
                    const asked = window.prompt(`${t('tagRenamePrompt')} ${tag.name}`, tag.name)
                    if (asked === null || asked.trim() === '' || asked.trim() === tag.name) return
                    setBusy(true)
                    void renameTag(tag.name, asked.trim()).then(() => {
                      void tags().then(setTagList).catch(() => {})
                      void refreshMeta()
                      setBusy(false)
                    }, () => setBusy(false))
                  }}
                >{t('tagRename')}</button>
                <button
                  type="button"
                  className={css.dangerButton}
                  disabled={busy || readonly || locked}
                  onClick={() => {
                    if (!window.confirm(t('tagRemoveConfirm').replace('{name}', tag.name))) return
                    setBusy(true)
                    void removeTag(tag.name).then(r => {
                      void tags().then(setTagList).catch(() => {})
                      void refreshMeta()
                      setMessage(t('tagRemoved').replace('{n}', String(r.removed)))
                      setBusy(false)
                    }, () => setBusy(false))
                  }}
                >{t('tagRemove')}</button>
              </span>
            </div>
          ))}
        </div>
      )}
      {selectMode && (
        <div className={css.bulkBar}>
          <label className={css.bulkItem}>
            <input
              type="checkbox"
              checked={state.status === 'ready' && state.entries.length > 0 && [...state.entries].every(e => selectedIds.has(e.id))}
              onChange={event => {
                if (state.status !== 'ready') return
                const ids = new Set(selectedIds)
                for (const e of state.entries) {
                  if (event.target.checked) ids.add(e.id)
                  else ids.delete(e.id)
                }
                setSelectedIds(ids)
              }}
            />
            <span>{t('bulkSelectAll')}</span>
          </label>
          <span className={css.bulkCount}>{t('bulkSelected')}: {selectedIds.size}</span>
          <button type="button" className={css.dupMerge} onClick={() => void bulkSetFavorite(true)} disabled={busy || selectedIds.size === 0}>{t('bulkFavorite')}</button>
          <button type="button" className={css.dupMerge} onClick={() => void bulkSetFavorite(false)} disabled={busy || selectedIds.size === 0}>{t('bulkUnfavorite')}</button>
          <button type="button" className={css.dupMerge} onClick={() => void bulkAddTag()} disabled={busy || readonly || locked || selectedIds.size === 0}>{t('bulkTag')}</button>
          <button type="button" className={css.dangerButton} onClick={() => void removeSelected()} disabled={busy || selectedIds.size === 0}>{t('bulkDelete')}</button>
        </div>
      )}
      </div>)}

      {message !== null && <p role="alert" className={css.error}>{message}</p>}

      {pwHistory !== null && (
        <div className={css.pwHistBox} role="dialog" aria-label={t('pwHistory')}>
          <p className={css.reportTitle}>{t('pwHistory')}</p>
          {pwHistory.length === 0 && <p className={css.reportSub}>{t('pwHistoryEmpty')}</p>}
          {pwHistory.map((h, i) => (
            <div key={i} className={css.pwHistRow}>
              <code className={css.pwHistPwd}>{pwHistRevealed === i ? h.password : '••••••••'}</code>
              <button
                type="button"
                className={css.revealButton}
                title={t('pwHistoryHint')}
                onClick={() => setPwHistRevealed(pwHistRevealed === i ? null : i)}
              >{pwHistRevealed === i ? t('hide') : t('show')}</button>
              <span className={css.pwHistTime}>{relTime(h.at)}</span>
              <button
                type="button"
                className={css.dupMerge}
                disabled={busy || readonly || locked}
                onClick={() => void rollbackPassword(h.at)}
              >{t('pwRollback')}</button>
            </div>
          ))}
          <button type="button" className={css.backupButton} onClick={() => { setPwHistory(null); setPwHistoryFor(null) }}>{t('cancel')}</button>
        </div>
      )}

      {state.status === 'loading' && <p className={css.status}>{t('loading')}</p>}
      {state.status === 'error' && (
        <p role="alert" className={css.error}>
          {state.reason ?? t('error')}{' '}
          <button type="button" className={css.retryButton} onClick={() => void refresh()}>{t('retry')}</button>
        </p>
      )}
      {activeTab === 'entries' && (<div className={css.tabPane}>
      {state.status === 'ready' && state.entries.length > 0 && (
        <div className={css.healthBar}>
          <span className={css.badge}>{t('entryCount')}: {state.entries.length}</span>
          {(() => {
            const byKind = new Map<string, number>()
            for (const e of state.entries) {
              const k = e.kind ?? 'login'
              byKind.set(k, (byKind.get(k) ?? 0) + 1)
            }
            return [...byKind.entries()].map(([k, n]) => (
              <span key={k} className={css.badge}>{t(KIND_KEYS[k] ?? 'kindCustom')}: {n}</span>
            ))
          })()}
          {vaultStats !== null && typeof vaultStats.withTotp === 'number' && vaultStats.withTotp > 0 && (
            <span className={css.badge}>TOTP: {String(vaultStats.withTotp)}</span>
          )}
          {query.trim().length > 0 && state.status === 'ready' && (
            <span className={css.badge}>{t('searchResultsCount').replace('{n}', String(filteredCount(state.entries, kindFilter, tagFilter, favOnly, dueOnly, dueMap)))}</span>
          )}
          {recentSearches.length > 0 && (
            <span className={css.recentSearch}>
              <span className={css.recentLabel}>{t('recentSearches')}:</span>
              {recentSearches.map(term => (
                <button key={term} type="button" className={css.recentChip} onClick={() => setQuery(term)} title={t('recentSearchHint')}>{term}</button>
              ))}
              <button type="button" className={css.recentClear} onClick={() => { setRecentSearches([]); try { window.sessionStorage.removeItem('dsh-vault-recent-searches') } catch { /* noop */ } }}>{t('clearRecent')}</button>
            </span>
          )}
        </div>
      )}
      {state.status === 'ready' && state.entries.length === 0 && (
        <div className={css.emptyBox}>
          {query.trim().length > 0 || kindFilter !== '' || tagFilter !== '' ? (
            <>
              <p className={css.empty}>{t('noFiltered')}</p>
              <p className={css.emptyHint}>{t('noFilteredHint')}</p>
              <button type="button" className={css.addButton} onClick={() => { setQuery(''); setKindFilter(''); setTagFilter('') }}>{t('clearFilters')}</button>
            </>
          ) : (
            <>
              <p className={css.empty}>{t('empty')}</p>
              <p className={css.emptyHint}>{readonly ? t('emptyHintReadonly') : t('emptyHint')}</p>
              {!readonly && !locked && (
                <button type="button" className={css.addButton} onClick={startCreate}>{t('quickAdd')}</button>
              )}
            </>
          )}
        </div>
      )}
      </div>)}

      {activeTab === 'security' && (<div className={css.tabPane}>
      {recentEntries.length > 0 && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('recentlyAdded')}</p>
          {recentEntries.map((e, i) => (
            <p key={i} className={css.reportLine}>{String(e.title ?? '')}{relTime((e as Record<string, unknown>).updatedAt) !== '' && ` · ${relTime((e as Record<string, unknown>).updatedAt)}`}</p>
          ))}
        </div>
      )}

      {report !== null && (report.rotation.length > 0 || report.weak.length > 0 || report.reused.length > 0) && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('reportTitle')}</p>
          {report.rotation.length > 0 && (
            <>
              <p className={css.reportLine}>{t('reportRotation')}: {report.rotation.length}</p>
              {(report.rotation as Array<{ title?: string; due?: string; daysLeft?: number }>).slice(0, 8).map((item, i) => (
                <p key={i} className={css.reportSub}>
                  · {String(item.title ?? '?')}{item.due === 'expired' ? ` (${t('dueExpired')})` : item.due === 'soon' ? ` (${t('dueExpiring')} ${item.daysLeft ?? 0}d)` : ` (${t('dueNow')})`}
                </p>
              ))}
            </>
          )}
          {report.weak.length > 0 && (
            <>
              <p className={css.reportLine}>{t('reportWeak')}: {report.weak.length}</p>
              {(report.weak as Array<{ title?: string }>).slice(0, 5).map((item, i) => (
                <p key={i} className={css.reportSub}>· {String(item.title ?? '?')}</p>
              ))}
            </>
          )}
          {report.reused.length > 0 && (
            <>
              <p className={css.reportLine}>{t('reportReused')}: {report.reused.length}</p>
              {(report.reused as Array<{ entries?: Array<{ title?: string }> }>).slice(0, 3).map((group, i) => (
                <p key={i} className={css.reportSub}>
                  · {(group.entries ?? []).slice(0, 3).map(e => String(e.title ?? '?')).join(' / ')}
                </p>
              ))}
            </>
          )}
          {report.no2fa.length > 0 && (
            <>
              <p className={css.reportLine}>{t('no2fa')}: {report.no2fa.length}</p>
              {(report.no2fa as Array<{ title?: string }>).slice(0, 5).map((item, i) => (
                <p key={i} className={css.reportSub}>· {String(item.title ?? '?')}</p>
              ))}
            </>
          )}
          {report.httpSites.length > 0 && (
            <>
              <p className={css.reportLine}>{t('httpSites')}: {report.httpSites.length}</p>
              {(report.httpSites as Array<{ title?: string }>).slice(0, 5).map((item, i) => (
                <p key={i} className={css.reportSub}>· {String(item.title ?? '?')}</p>
              ))}
            </>
          )}
        </div>
      )}

      {audit.length > 0 && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('auditTitle')} ({audit.length})</p>
          {audit.slice(0, 6).map(item => (
            <div key={item.id} className={css.auditRow}>
              <span className={css.dupNames}>{item.title}</span>
              <span className={css.auditIssues}>{item.issues.join('; ')}</span>
              <button
                type="button"
                className={css.dupMerge}
                onClick={() => void startEdit(item.id)}
                disabled={busy}
              >{t('auditEdit')}</button>
            </div>
          ))}
        </div>
      )}

      </div>)}

      {activeTab === 'transfer' && (<div className={css.tabPane}>
      <div className={css.reportBox}>
        <p className={css.reportTitle}>{t('systemSearch')}</p>
        <div className={css.dupGroup}>
          <input
            className={css.searchBox}
            type="search"
            placeholder={t('sysSearchPlaceholder')}
            value={sysQuery}
            onChange={event => setSysQuery(event.target.value)}
            onKeyDown={event => { if (event.key === 'Enter') void searchSystemStores() }}
          />
          <button type="button" className={css.dupMerge} onClick={() => void searchSystemStores()} disabled={busy}>{t('sysSearchGo')}</button>
        </div>
        {sysMatches.length > 0 && (
          <div>
            {sysMatches.map((m, i) => (
              <p key={i} className={css.reportSub}>[{m.source}] {m.name} · {m.username}</p>
            ))}
          </div>
        )}
      </div>

      <div className={css.reportBox}>
        <p className={css.reportTitle}>{t('systemImport')}</p>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('importChromeDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runSystemImport('chrome', false)} disabled={busy || readonly || locked}>{t('importChrome')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('importFirefoxDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runFirefoxImport()} disabled={busy || readonly || locked}>{t('importFirefox')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('importKeychainDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runSystemImport('keychain', true)} disabled={busy || readonly || locked}>{t('keychainPreview')}</button>
          <button type="button" className={css.dupMerge} onClick={() => void runSystemImport('keychain', false)} disabled={busy || readonly || locked}>{t('importKeychain')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('import1passwordDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runImport1password()} disabled={busy || readonly || locked}>{t('import1password')}</button>
          <button type="button" className={css.dupMerge} onClick={() => void runFilePreview('import1passwordPrompt', import1password)} disabled={busy || readonly || locked}>{t('preview')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('importManagerCsvDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runCsvImportPreview()} disabled={busy || readonly || locked}>{t('importManagerCsv')}</button>
          <button type="button" className={css.dupMerge} onClick={() => void runFilePreview('importManagerCsvPrompt', importManagerCsv)} disabled={busy || readonly || locked}>{t('preview')}</button>
        </div>
        {importPreview !== null && (
          <div className={css.previewBox}>
            <p className={css.reportTitle}>{t('previewImportTitle')}</p>
            <p className={css.reportSub}>{t('previewImportRows').replace('{n}', String(importPreview.total)).replace('{m}', String(importPreview.skipped))}</p>
            <div className={css.previewScroll}>
              <table className={css.previewTable}>
                <thead>
                  <tr>
                    <th>{t('fieldTitle')}</th>
                    <th>{t('fieldKind')}</th>
                    <th>{t('fieldUsername')}</th>
                    <th>{t('fieldPassword')}</th>
                  </tr>
                </thead>
                <tbody>
                  {importPreview.rows.map((row, i) => (
                    <tr key={i}>
                      <td>{row.title}</td>
                      <td>{t(KIND_KEYS[row.kind] ?? 'kindLogin')}</td>
                      <td>{row.username}</td>
                      <td>{row.hasPassword ? '●' : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className={css.dupGroup}>
              <button type="button" className={css.actionPrimary} onClick={() => void confirmCsvImport()} disabled={busy || readonly || locked || importPreview.rows.length === 0}>{t('confirmImport').replace('{n}', String(importPreview.rows.length))}</button>
              <button type="button" className={css.dupMerge} onClick={() => setImportPreview(null)} disabled={busy}>{t('cancel')}</button>
            </div>
          </div>
        )}
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('importEnpassDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runImportEnpass()} disabled={busy || readonly || locked}>{t('importEnpass')}</button>
          <button type="button" className={css.dupMerge} onClick={() => void runFilePreview('importEnpassPrompt', importEnpass)} disabled={busy || readonly || locked}>{t('preview')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('importBitwardenDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runImportBitwarden()} disabled={busy || readonly || locked}>{t('importBitwarden')}</button>
          <button type="button" className={css.dupMerge} onClick={() => void runFilePreview('importBitwardenPrompt', importBitwarden)} disabled={busy || readonly || locked}>{t('preview')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('importBitwardenEncryptedDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runImportBitwardenEncrypted()} disabled={busy || readonly || locked}>{t('importBitwardenEncrypted')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('import1pifDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runImport1pif()} disabled={busy || readonly || locked}>{t('import1pif')}</button>
          <button type="button" className={css.dupMerge} onClick={() => void runFilePreview('import1pifPrompt', import1pif)} disabled={busy || readonly || locked}>{t('preview')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('importKeePassXmlDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runImportKeePassXml()} disabled={busy || readonly || locked}>{t('importKeePassXml')}</button>
          <button type="button" className={css.dupMerge} onClick={() => void runFilePreview('importKeePassXmlPrompt', importKeePassXml)} disabled={busy || readonly || locked}>{t('preview')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('importKdbxDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runImportKdbx()} disabled={busy || readonly || locked}>{t('importKdbx')}</button>
        </div>
      </div>

      <div className={css.reportBox}>
        <p className={css.reportTitle}>{t('exportTitle')}</p>
        <p className={css.reportSub}>{t('exportHint')}</p>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('export1puxDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runExport1pux()} disabled={busy || readonly || locked}>{t('export1pux')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('exportBitwardenDesc')}</span>
          <button type="button" className={css.dupMerge} onClick={() => void runExportBitwarden()} disabled={busy || readonly || locked}>{t('exportBitwarden')}</button>
        </div>
        <div className={css.dupGroup}>
          <span className={css.dupNames}>{t('exportCsvDesc')}</span>
          <div className={css.exportChips}>
            {CSV_EXPORT_FIELDS.map(f => (
              <label key={f.key} className={css.exportChip}>
                <input
                  type="checkbox"
                  checked={exportFields.includes(f.key)}
                  onChange={event => setExportFields(prev => event.target.checked ? [...prev, f.key] : prev.filter(k => k !== f.key))}
                />
                <span>{t(f.label)}</span>
              </label>
            ))}
          </div>
          <button type="button" className={css.dupMerge} onClick={() => void runExportCsv()} disabled={busy || readonly || locked || exportFields.length === 0}>{t('exportCsv')}</button>
        </div>
      </div>
      </div>)}

      {activeTab === 'backup' && (<div className={css.tabPane}>
      <div className={css.reportBox}>
        <p className={css.reportTitle}>{t('backupTitle')}</p>
        <p className={css.reportSub}>{t('backupHint')}</p>
        {backupInfo !== null && (
          <p className={css.reportSub}>{t('healthBackup')}: {backupInfo.daysSinceBackup}d ({backupInfo.backups})</p>
        )}
        <button type="button" className={css.backupButton} onClick={() => void backupNow()} disabled={busy}>
          {t('backupNow')}
        </button>
      </div>

      {backupList.length > 0 && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('recentBackups')} ({backupList.length})</p>
          {backupList.map(b => (
            <div key={b.path} className={css.dupGroup}>
              <span className={css.dupNames}>
                {b.vaultName !== '' ? `${b.vaultName} · ` : ''}{new Date(b.at).toLocaleString()}
                {b.size !== undefined && b.size > 0 ? ` · ${formatSize(b.size)}` : ''}
              </span>
              <button
                type="button"
                className={css.dupMerge}
                onClick={() => void restoreBackupFrom(b)}
                disabled={busy || readonly || locked}
                title={t('backupRestoreHint')}
              >{t('backupRestore')}</button>
              <button
                type="button"
                className={css.dangerButton}
                onClick={() => void deleteBackupFile(b)}
                disabled={busy || readonly || locked}
                title={t('backupDelete')}
              >{t('backupDelete')}</button>
            </div>
          ))}
        </div>
      )}
      {backupList.length === 0 && (
        <p className={css.empty}>{t('noBackups')}</p>
      )}
      </div>)}

      {activeTab === 'sessions' && (<div className={css.tabPane}>
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('tabSessions')}</p>
          <p className={css.reportSub}>{t('sessionsIntro')}</p>
          <label className={css.field}>
            <span>{t('sessionUrlPrompt')}</span>
            <input
              type="text"
              value={sessionUrl}
              onChange={event => setSessionUrl(event.target.value)}
              placeholder={t('sessionUrlPlaceholder')}
              disabled={busy || readonly || locked}
            />
          </label>
          <button type="button" className={css.backupButton} onClick={() => void runSessionOpen()} disabled={busy || readonly || locked}>
            {t('sessionOpen')}
          </button>
          <p className={css.reportSub}>{t('sessionOpenHint')}</p>
        </div>

        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('sessionOpenList')} ({openSessions.length})</p>
          {openSessions.length === 0 && (<p className={css.empty}>{t('sessionNoOpen')}</p>)}
          {openSessions.map(s => (
            <div key={s.sessionId} className={css.dupGroup}>
              <span className={css.dupNames}>{s.url} — {t('sessionNamePlaceholder')}</span>
              <label className={css.field}>
                <input
                  type="text"
                  value={sessionTitle}
                  onChange={event => setSessionTitle(event.target.value)}
                  placeholder={t('sessionNamePlaceholder')}
                  disabled={busy || readonly || locked}
                />
              </label>
              <button
                type="button"
                className={css.dupMerge}
                onClick={() => void runSessionCollect(s.sessionId, s.url)}
                disabled={busy || readonly || locked}
                title={t('sessionCollect')}
              >{t('sessionCollect')}</button>
              <button
                type="button"
                className={css.dangerButton}
                onClick={() => void runSessionClose(s.sessionId)}
                disabled={busy}
                title={t('sessionClose')}
              >{t('sessionClose')}</button>
            </div>
          ))}
        </div>

        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('sessionSavedList')} ({savedSessions.length})</p>
          {savedSessions.length === 0 && (<p className={css.empty}>{t('sessionEmpty')}</p>)}
          {savedSessions.map(s => (
            <div key={s.id} className={css.dupGroup}>
              <span className={css.dupNames}>{s.title} — {s.cookieCount} {t('sessionCookie')}{(s.expiredCount ?? 0) > 0 ? ` · ${s.expiredCount} ${t('sessionExpired')}` : ''}{(s.expiringSoon ?? 0) > 0 ? ` · ${s.expiringSoon} ${t('sessionExpiringSoon')}` : ''}{s.url !== undefined ? ` · ${s.url}` : ''}</span>
              <button
                type="button"
                className={css.dupMerge}
                onClick={() => void runSessionExport(s.id, 'header')}
                disabled={busy}
                title={t('sessionExport')}
              >{copiedId === s.id ? t('sessionCopied') : t('sessionExport')}</button>
              <button
                type="button"
                className={css.dupMerge}
                onClick={() => void runSessionExport(s.id, 'netscape')}
                disabled={busy}
                title={t('sessionExportJar')}
              >{t('sessionExportJar')}</button>
              <button
                type="button"
                className={css.dupMerge}
                onClick={() => void runSessionExport(s.id, 'playwright')}
                disabled={busy}
                title={t('sessionExportPlaywright')}
              >{t('sessionExportPlaywright')}</button>
              <button
                type="button"
                className={css.dupMerge}
                onClick={() => void runSessionDetail(s.id)}
                disabled={busy}
                title={t('sessionView')}
              >{t('sessionView')}</button>
              <button
                type="button"
                className={css.dupMerge}
                onClick={() => void runSessionPrune(s.id)}
                disabled={busy || readonly || locked || (s.expiredCount ?? 0) === 0}
                title={t('sessionPrune')}
              >{t('sessionPrune')}</button>
              <button
                type="button"
                className={css.dangerButton}
                onClick={() => void remove(s.id)}
                disabled={busy || readonly || locked}
                title={t('sessionDelete')}
              >{t('sessionDelete')}</button>
            </div>
          ))}
        </div>

        {sessionDetail !== null && (
          <div className={css.reportBox}>
            <p className={css.reportTitle}>{t('sessionDetailTitle')} — {sessionDetail.title}</p>
            <p className={css.reportSub}>{sessionDetail.notes ?? ''}</p>
            {sessionDetail.cookies.map((c, index) => {
              const cookie = c as { name?: string; value?: string; domain?: string; path?: string; expires?: number; httpOnly?: boolean; secure?: boolean; sameSite?: string }
              const expiry = typeof cookie.expires === 'number' && cookie.expires >= 0
                ? new Date(cookie.expires * 1000).toLocaleString() : t('sessionSessionCookie')
              const nowSec = Math.floor(Date.now() / 1000)
              const isExpired = typeof cookie.expires === 'number' && cookie.expires > 0 && cookie.expires <= nowSec
              const expiring = typeof cookie.expires === 'number' && cookie.expires > nowSec && cookie.expires <= nowSec + 7 * 86_400
              return (
                <div key={`${index}-${cookie.name}`} className={css.auditRow}>
                  <span className={css.dupNames}>{cookie.name} = {cookie.value}</span>
                  <span className={css.reportSub}>{t('sessionDomain')}: {cookie.domain}{cookie.httpOnly === true ? ' · HttpOnly' : ''}{cookie.secure === true ? ' · Secure' : ''} · {t('sessionExpires')}: {expiry}{isExpired ? ` · ${t('sessionExpired')}` : ''}{expiring ? ` · ${t('sessionExpiringSoon')}` : ''}</span>
                </div>
              )
            })}
          </div>
        )}

        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('sessionImportPaste')}</p>
          <label className={css.field}>
            <span>{t('sessionImportPasteTitle')}</span>
            <input
              type="text"
              value={sessionPasteTitle}
              onChange={event => setSessionPasteTitle(event.target.value)}
              placeholder={t('sessionNamePlaceholder')}
              disabled={busy || readonly || locked}
            />
          </label>
          <label className={css.field}>
            <span>{t('sessionImportPastePrompt')}</span>
            <textarea
              value={sessionPaste}
              onChange={event => setSessionPaste(event.target.value)}
              rows={4}
              disabled={busy || readonly || locked}
            />
          </label>
          <button type="button" className={css.backupButton} onClick={() => void runSessionImport()} disabled={busy || readonly || locked}>
            {t('sessionImport')}
          </button>
        </div>
      </div>)}

      {activeTab === 'permissions' && (<div className={css.tabPane}>
      {policy !== null && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('permTitle')}</p>
          <div className={css.policyBar}>
            <label className={css.policyField}>
              <span>{t('modeLabel')}</span>
              <select
                value={policy.accessMode}
                disabled={busy}
                onChange={event => {
                  const next = event.target.value as 'readonly' | 'ask' | 'auto'
                  setBusy(true)
                  setMessage(null)
                  void setAccessMode(next).then(
                    value => { setPolicy(value); setBusy(false) },
                    (err) => { setMessage(errText(err)); setBusy(false) },
                  )
                }}
              >
                <option value="readonly">{t('modeReadonly')}</option>
                <option value="ask">{t('modeAsk')}</option>
                <option value="auto">{t('modeAuto')}</option>
              </select>
            </label>
            <label className={css.policyField}>
              <span>{t('autoCaptureLabel')}</span>
              <input
                type="checkbox"
                checked={policy.autoCapture}
                disabled={busy}
                onChange={event => {
                  const next = event.target.checked
                  setBusy(true)
                  setMessage(null)
                  void setAutoCapture(next).then(
                    value => { setPolicy(value); setBusy(false) },
                    (err) => { setMessage(errText(err)); setBusy(false) },
                  )
                }}
              />
            </label>
            <label className={css.policyField}>
              <span>{t('autoLockLabel')}</span>
              <select
                value={policy.autoLockSeconds}
                disabled={busy}
                onChange={event => {
                  const next = Number(event.target.value)
                  setBusy(true)
                  setMessage(null)
                  void setAutoLock(next).then(
                    value => { setPolicy(previous => previous ? { ...previous, autoLockSeconds: value.seconds } : previous); setBusy(false) },
                    (err) => { setMessage(errText(err)); setBusy(false) },
                  )
                }}
              >
                <option value={0}>{t('autoLockNever')}</option>
                <option value={60}>{t('autoLock1m')}</option>
                <option value={300}>{t('autoLock5m')}</option>
                <option value={900}>{t('autoLock15m')}</option>
                <option value={1800}>{t('autoLock30m')}</option>
                <option value={3600}>{t('autoLock1h')}</option>
              </select>
            </label>
            <p className={policy.accessMode === 'readonly' ? css.modeReadonly : policy.accessMode === 'ask' ? css.modeAsk : css.modeAuto}>
              {policy.accessMode === 'readonly'
                ? t('modeReadonlyHint')
                : policy.accessMode === 'ask'
                  ? t('modeAskHint')
                  : t('modeAutoHint')}
              {policy.autoCapture ? ` · ${t('autoCaptureOn')}` : ` · ${t('autoCaptureOff')}`}
              {policy.autoLockSeconds > 0 ? ` · ${t('autoLockHint')}: ${formatAutoLock(policy.autoLockSeconds)}` : ` · ${t('autoLockNeverHint')}`}
            </p>
          </div>
        </div>
      )}

      {tagList.length > 0 && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('tagManage')} ({tagList.length})</p>
          {tagList.slice(0, 8).map(tag => (
            <div key={tag.name} className={css.dupGroup}>
              <span className={css.dupNames}>{tag.name} ({tag.count})</span>
              <button
                type="button"
                className={css.dupMerge}
                onClick={() => void renameTagAll(tag.name)}
                disabled={busy || readonly || locked}
              >{t('tagRename')}</button>
            </div>
          ))}
        </div>
      )}

      {dupList.length > 0 && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('dupTitle')} ({dupList.length})</p>
          {dupList.slice(0, 5).map((group, gi) => (
            <div key={gi} className={css.dupGroup}>
              <span className={css.dupNames}>{group.map(g => g.title).join(' / ')}</span>
              <button
                type="button"
                className={css.dupMerge}
                onClick={() => void mergeEntries(group)}
                disabled={busy || readonly || locked}
              >{t('dupMerge')}</button>
            </div>
          ))}
        </div>
      )}
      </div>)}

      {activeTab === 'audit' && (<div className={css.tabPane}>
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('recentActivity')}</p>
          <div className={css.toolbar}>
            <select className={css.kindFilter} value={auditFilter} onChange={e => setAuditFilter(e.target.value)} aria-label={t('auditFilter')}>
              <option value="">{t('auditAll')}</option>
              <option value="add">{t('auditAdd')}</option>
              <option value="update">{t('auditUpdate')}</option>
              <option value="delete">{t('auditDelete')}</option>
              <option value="restore">{t('auditRestore')}</option>
            </select>
            <button type="button" className={css.dupMerge} onClick={exportAuditLog} disabled={recentEvents.length === 0}>{t('auditExport')}</button>
          </div>
          {recentEvents.length === 0 && <p className={css.empty}>{t('recentActivityEmpty')}</p>}
          {recentEvents.filter(ev => auditFilter === '' || String(ev.action ?? '') === auditFilter).slice(0, 30).map((ev, i) => {
            const action = String(ev.action ?? '')
            const icon = action === 'add' ? '➕' : action === 'delete' ? '🗑️' : action === 'restore' ? '♻️' : action === 'purge' ? '🔥' : action === 'update' ? '✏️' : '•'
            const cls = action === 'delete' || action === 'purge' ? css.histDanger : action === 'add' ? css.histAdd : action === 'update' ? css.histUpdate : css.histNeutral
            const ts = Number((ev as Record<string, unknown>).at)
            const when = Number.isFinite(ts) && ts > 0 ? new Date(ts).toLocaleString() : ''
            const evTitle = String(ev.title ?? ev.id ?? '')
            return (
              <p key={i} className={`${css.reportLine} ${cls}`}>
                {icon} {action} · <button type="button" className={css.histLink} onClick={() => { setActiveTab('entries'); setQuery(evTitle); }} title={t('auditJumpHint')}>{evTitle}</button>{when !== '' && ` · ${when}`}
              </p>
            )
          })}
        </div>
      </div>)}

      {activeTab === 'trash' && (<div className={css.tabPane}>
      {trashEntries.length === 0 && <p className={css.empty}>{t('trashEmpty')}</p>}
      {trashEntries.length > 0 && (
        <ul className={css.list}>
          {trashEntries.map(entry => (
            <li key={entry.id} className={css.row}>
              <div className={css.rowMain}>
                <span className={css.title}>{entry.title}</span>
                <span className={css.identity}>{t('trashed')}</span>
              </div>
              <div className={css.rowActions}>
                <button
                  type="button"
                  onClick={() => { void restore(entry.id).then(() => { void trash().then(setTrashEntries); void refresh(); refreshHealth() }) }}
                  disabled={busy || readonly || locked}
                >{t('restore')}</button>
                <button
                  type="button"
                  className={css.dangerButton}
                  onClick={() => {
                    if (!window.confirm(t('purgeOneConfirm').replace('{name}', entry.title))) return
                    void purge(entry.id).then(() => { void trash().then(setTrashEntries); void refresh() })
                  }}
                  disabled={busy || readonly || locked}
                >{t('purge')}</button>
              </div>
            </li>
          ))}
        </ul>
      )}
      {trashEntries.length > 0 && (
        <>
          <button
            type="button"
            className={css.trashButton}
            onClick={() => {
              setBusy(true)
              void undeleteAll().then(() => {
                void trash().then(setTrashEntries)
                void refresh()
                refreshHealth()
                setBusy(false)
              }, () => setBusy(false))
            }}
            disabled={busy || readonly || locked}
          >{t('restoreAll')}</button>
          <button
            type="button"
            className={css.dangerButton}
            onClick={() => {
              if (!window.confirm(t('clearTrashConfirm'))) return
              setBusy(true)
              void Promise.all(trashEntries.map(e => purge(e.id))).then(() => {
                void trash().then(setTrashEntries)
                void refresh()
                setBusy(false)
              }, () => setBusy(false))
            }}
            disabled={busy || readonly || locked}
          >{t('clearTrash')}</button>
        </>
      )}
      </div>)}

      {activeTab === 'entries' && (<div className={css.tabPane}>
      {state.status === 'ready' && filteredCount(state.entries, kindFilter, tagFilter, favOnly, dueOnly, dueMap) > visibleCount && (
        <button
          type="button"
          className={css.trashButton}
          onClick={() => setVisibleCount(count => count + 50)}
        >{t('loadMore')} ({filteredCount(state.entries, kindFilter, tagFilter, favOnly, dueOnly, dueMap) - visibleCount})</button>
      )}

      {state.status === 'ready' && state.entries.length > 0 && (
        <>
        <p className={css.resultCount}>
          {t('resultCount')}: {filteredCount(state.entries, kindFilter, tagFilter, favOnly, dueOnly, dueMap)}
          {(() => {
            const byKind = new Map<string, number>()
            for (const e of state.entries) {
              if ((kindFilter === '' || e.kind === kindFilter) && (tagFilter === '' || (e.tags ?? []).includes(tagFilter))) {
                const k = e.kind ?? 'login'
                byKind.set(k, (byKind.get(k) ?? 0) + 1)
              }
            }
            return [...byKind.entries()].map(([k, n]) => (
              <span key={k} className={css.kindChip}>{t(KIND_KEYS[k] ?? 'kindCustom')} {n}</span>
            ))
          })()}
        </p>
        <ul className={css.list}>
          {filteredCount(state.entries, kindFilter, tagFilter, favOnly, dueOnly, dueMap) === 0 && (
            <li className={css.empty}>{t('noFiltered')}</li>
          )}
          {state.entries.filter(entry => (kindFilter === '' || entry.kind === kindFilter) && (tagFilter === '' || (entry.tags ?? []).includes(tagFilter)) && (!favOnly || (entry as VaultSummaryWire & { favorite?: boolean }).favorite === true) && (!dueOnly || dueMap[entry.id] !== undefined)).sort((a, b) => sortBy === 'alpha' ? a.title.localeCompare(b.title) : sortBy === 'recent' ? (b.updatedAt ?? 0) - (a.updatedAt ?? 0) : sortBy === 'created' ? (b.createdAt ?? 0) - (a.createdAt ?? 0) : ((a as VaultSummaryWire & { favorite?: boolean }).favorite === true ? 0 : 1) - ((b as VaultSummaryWire & { favorite?: boolean }).favorite === true ? 0 : 1) || (b.updatedAt ?? 0) - (a.updatedAt ?? 0) || a.title.localeCompare(b.title)).slice(0, visibleCount).map(entry => {
            const totpInfo = totpMap[entry.id]
            const remaining = totpInfo !== undefined && totpInfo.until > 0 ? Math.max(0, Math.ceil((totpInfo.until - nowTick) / 1000)) : undefined
            const frac = remaining !== undefined ? remaining / 30 : 0
            const code = totpInfo?.code
            return (
              <li key={entry.id} className={`${css.row}${dueMap[entry.id] !== undefined ? ` ${dueMap[entry.id]!.due === 'expired' ? css.rowExpired : css.rowDue}` : ''}${selectedIds.has(entry.id) ? ` ${css.rowSelected}` : ''}`}>
                {selectMode && (
                  <input
                    type="checkbox"
                    className={css.rowCheck}
                    checked={selectedIds.has(entry.id)}
                    onChange={event => {
                      setSelectedIds(prev => {
                        const next = new Set(prev)
                        if (event.target.checked) next.add(entry.id)
                        else next.delete(entry.id)
                        return next
                      })
                    }}
                    aria-label={entry.title}
                  />
                )}
                <div
                  className={css.rowMain}
                  role="button"
                  tabIndex={0}
                  aria-expanded={expandedId === entry.id}
                  onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                  onKeyDown={event => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault()
                      setExpandedId(expandedId === entry.id ? null : entry.id)
                    }
                  }}
                >
                  <span className={css.title} style={entry.color !== undefined && entry.color !== '' ? { borderLeft: `3px solid ${entry.color}`, paddingLeft: 6 } : undefined}>
                    <span className={css.kindIcon}>{entry.icon ?? kindIcon(entry.kind)}</span>
                    <button
                      type="button"
                      className={`${css.pinStar} ${(entry as VaultSummaryWire & { favorite?: boolean }).favorite ? css.pinOn : css.pinOff}`}
                      title={t('togglePinHint')}
                      disabled={busy || locked}
                      onClick={event => {
                        event.stopPropagation()
                        const next = !(entry as VaultSummaryWire & { favorite?: boolean }).favorite
                        void setFavorite(entry.id, next).then(() => void refresh())
                      }}
                      onKeyDown={event => event.stopPropagation()}
                    >★</button>
                    {highlightText(entry.title, query)}
                    {(entry as VaultSummaryWire & { sensitivity?: string }).sensitivity === 'high' && (
                      <span className={css.highBadge}>{t('highSensitivity')}</span>
                    )}
                    {dueMap[entry.id] !== undefined && (
                      <button
                        type="button"
                        className={`${css.dueBadge} ${css.badgeLink} ${dueMap[entry.id]!.due === 'expired' ? css.badgeDanger : css.badgeWarn}`}
                        title={t('badgeEditHint')}
                        onClick={event => { event.stopPropagation(); void startEdit(entry.id) }}
                      >
                        {dueMap[entry.id]!.due === 'expired' ? t('dueExpired') : dueMap[entry.id]!.due === 'soon' ? `${t('dueExpiring')} ${dueMap[entry.id]!.daysLeft}d` : t('dueNow')}
                      </button>
                    )}
                    {passwordAge(entry) !== '' && (
                      <button type="button" className={`${css.dueBadge} ${css.badgeLink}`} title={t('ageHint')} onClick={event => { event.stopPropagation(); void startEdit(entry.id) }}>{passwordAge(entry)}</button>
                    )}
                    {cardExpiryBadge(entry) !== '' && (
                      <button type="button" className={`${css.dueBadge} ${css.badgeLink}`} title={t('cardExpiryHint')} onClick={event => { event.stopPropagation(); void startEdit(entry.id) }}>{cardExpiryBadge(entry)}</button>
                    )}
                    {watchMap[entry.id] !== undefined && watchMap[entry.id]!.verdict !== 'good' && (
                      <button
                        type="button"
                        className={`${css.dueBadge} ${css.badgeLink} ${watchMap[entry.id]!.verdict === 'poor' ? css.badgeDanger : css.badgeWarn}`}
                        title={t('watchFlagsTitle') + watchMap[entry.id]!.flags.join(', ')}
                        onClick={event => { event.stopPropagation(); void startEdit(entry.id) }}
                      >
                        {t('watchScore').replace('{n}', String(watchMap[entry.id]!.score))}
                      </button>
                    )}
                  </span>
                  <span className={css.identity}>{highlightText(identityLine(entry), query)}</span>
                  {uriMap[entry.id] !== undefined && uriMap[entry.id] !== '' && (
                    <span className={css.totp} title={t('totpUriHint')}>
                      <code className={css.uriCode}>{uriMap[entry.id]}</code>
                    </span>
                  )}
                  {entry.hasOtp === true && code !== undefined && (
                    <span className={css.totp} title={t('totpInlineHint')}>
                      <svg className={css.totpRing} width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
                        <circle cx="8" cy="8" r="6.5" fill="none" stroke="var(--dsh-color-border, #ddd)" strokeWidth="2" />
                        <circle
                          cx="8" cy="8" r="6.5" fill="none"
                          stroke={remaining !== undefined && remaining <= 5 ? '#cf3d3d' : '#2e9e5b'}
                          strokeWidth="2" strokeLinecap="round"
                          strokeDasharray={`${(frac * 2 * Math.PI * 6.5).toFixed(1)} ${(2 * Math.PI * 6.5).toFixed(1)}`}
                          transform="rotate(-90 8 8)"
                        />
                      </svg>
                      {code}{remaining !== undefined ? ` (${remaining}s)` : ''}
                    </span>
                  )}
                </div>
                {expandedId === entry.id && (
                  <div className={css.detailBox}>
                    {entry.hasOtp === true && code !== undefined && (
                      <span className={css.detailTotp} title={t('totpInlineHint')}>
                        <svg className={css.totpRing} width="18" height="18" viewBox="0 0 16 16" aria-hidden="true">
                          <circle cx="8" cy="8" r="6.5" fill="none" stroke="var(--dsh-color-border, #ddd)" strokeWidth="2" />
                          <circle
                            cx="8" cy="8" r="6.5" fill="none"
                            stroke={remaining !== undefined && remaining <= 5 ? '#cf3d3d' : '#2e9e5b'}
                            strokeWidth="2" strokeLinecap="round"
                            strokeDasharray={`${(frac * 2 * Math.PI * 6.5).toFixed(1)} ${(2 * Math.PI * 6.5).toFixed(1)}`}
                            transform="rotate(-90 8 8)"
                          />
                        </svg>
                        <code className={css.detailCode}>{code}</code>
                        <span className={css.detailRemain}>{remaining !== undefined ? `${remaining}s` : ''}</span>
                        <button
                          type="button"
                          className={css.revealButton}
                          title={t('copyCode')}
                          onClick={() => void copyValue(entry.id, code!)}
                          disabled={busy || locked}
                        >⧉</button>
                      </span>
                    )}
                    {Object.entries(entry).filter(([k]) => !['id', 'title', 'favorite'].includes(k) && entry[k as keyof VaultSummaryWire] !== undefined).map(([k, v]) => (
                      <span key={k} className={css.detailItem}>
                        <strong>{k}</strong>: {formatDetail(k, v)}
                        <button
                          type="button"
                          className={css.revealButton}
                          title={t('copyFieldHint')}
                          onClick={() => void copyValue(entry.id, Array.isArray(v) ? v.join(', ') : String(v))}
                          disabled={locked}
                        >⧉</button>
                      </span>
                    ))}
                    <div className={css.attachBox}>
                      <strong>{t('attachmentsTitle')}:</strong>
                      {(attachmentsMap[entry.id] ?? []).map(a => (
                          <span key={a.name} className={css.detailItem}>
                            📎 {a.name} ({formatSize(a.size)})
                            <button
                              type="button"
                              className={css.revealButton}
                              title={t('downloadHint')}
                              disabled={busy || locked}
                              onClick={() => void downloadAttachmentFile(entry.id, a.name)}
                            >⬇</button>
                            <button
                              type="button"
                              className={css.revealButton}
                              title={t('detachHint')}
                              disabled={busy || readonly || locked}
                              onClick={() => {
                                setBusy(true)
                                void detach(entry.id, a.name).then(() => {
                                  void attachments(entry.id).then(r => {
                                    if (r.found) setAttachmentsMap(prev => ({ ...prev, [entry.id]: r.attachments }))
                                  })
                                  setBusy(false)
                                }, () => setBusy(false))
                              }}
                            >✕</button>
                          </span>
                        ))}
                        <label className={css.attachAdd} title={t('attachHint')}>
                          ＋ {t('attachFile')}
                          <input
                            type="file"
                            className={css.srOnly}
                            onChange={event => { attachFile(entry.id, event.target.files?.[0]); event.target.value = '' }}
                          />
                        </label>
                      </div>
                  </div>
                )}
                <div className={css.rowActions}>
                  {copiedId === entry.id && <span className={css.copied}>{t('copied')} · {t('clearsIn30s')}</span>}
                  <button
                    type="button"
                    className={css.actionPrimary}
                    onClick={() => void copyValue(entry.id, entry.username ?? entry.title)}
                    disabled={busy || readonly || locked}
                    title={entry.username !== undefined && entry.username !== '' ? t('copyUsernameHint') : t('copyTitleHint')}
                  >{entry.username !== undefined && entry.username !== '' ? t('copyUsername') : t('copy')}</button>
                  <button
                    type="button"
                    className={css.actionPrimary}
                    onClick={() => {
                      setBusy(true)
                      void get(entry.id).then(r => {
                        if (r.found && r.entry) {
                          // Copy the entry's primary secret: for api-key /
                          // secret / oauth / card kinds the secret lives in a
                          // different field than `password`, so fall back
                          // through the kind-appropriate chain.
                          const e = r.entry
                          const value = e.password ?? e.apiKey ?? e.secret ?? e.accessToken ?? e.refreshToken ?? e.privateKey ?? e.cardNumber ?? ''
                          if (value.length > 0) void copyValue(entry.id, value)
                          else setMessage(t('nothingToCopy'))
                        }
                        setBusy(false)
                      }, () => setBusy(false))
                    }}
                    disabled={busy || readonly || locked}
                  >{entry.kind === 'api-key' ? t('copyApiKey') : entry.kind === 'oauth' ? t('copyToken') : entry.kind === 'card' ? t('copyCardNumber') : entry.kind === 'secret' || entry.kind === 'custom' ? t('copyKey') : t('copyPassword')}</button>
                  {code !== undefined && (
                    <button type="button" className={css.actionPrimary} onClick={() => void copyValue(entry.id, code)} disabled={busy || locked}>{t('copyCode')}</button>
                  )}
                  <span className={css.moreWrap}>
                    <button
                      type="button"
                      className={css.moreButton}
                      aria-haspopup="menu"
                      aria-expanded={openMenuId === entry.id}
                      onClick={event => { event.stopPropagation(); setOpenMenuId(openMenuId === entry.id ? null : entry.id) }}
                    >⋯</button>
                    {openMenuId === entry.id && (
                      <span className={css.moreMenu} role="menu" onClick={() => setOpenMenuId(null)}>
                        <button type="button" role="menuitem" onClick={() => void showTotp(entry.id)} disabled={busy || locked}>{t('totp')}</button>
                        <button type="button" role="menuitem" onClick={() => void showTotpUri(entry.id)} disabled={busy || locked}>{t('totpUri')}</button>
                        {entry.url !== undefined && entry.url !== '' && (
                          <button type="button" role="menuitem" onClick={() => window.open(entry.url!, '_blank', 'noopener')}>{t('openUrl')}</button>
                        )}
                        <button type="button" role="menuitem" onClick={() => void touch(entry.id).then(() => void refresh())} disabled={busy || readonly || locked}>{t('touch')}</button>
                        <button type="button" role="menuitem" onClick={() => void showPasswordHistory(entry.id)} disabled={busy || locked}>{t('pwHistory')}</button>
                        <button type="button" role="menuitem" onClick={() => void startEdit(entry.id)} disabled={busy || readonly || locked}>{t('edit')}</button>
                        <button type="button" role="menuitem" onClick={() => void cloneEntry(entry.id)} disabled={busy || readonly || locked}>{t('clone')}</button>
                        <button type="button" role="menuitem" className={css.deleteButton} onClick={() => void removeEntry(entry.id)} disabled={busy || readonly || locked}>{t('delete')}</button>
                      </span>
                    )}
                  </span>
                </div>
              </li>
            )
          })}
        </ul>
        </>
      )}
      </div>)}

      {activeTab === 'security' && (<div className={css.tabPane}>
      {state.status === 'ready' && (
        <div className={css.healthBar}>
          {vaultStats !== null && typeof vaultStats.total === 'number' && (
            <span className={css.badge}>{t('entryCount')}: {String(vaultStats.total)}</span>
          )}
          {vaultStats !== null && typeof vaultStats.withTotp === 'number' && (
            <span className={css.badge}>TOTP: {String(vaultStats.withTotp)}</span>
          )}
          {vaultStats !== null && typeof vaultStats.highSensitivity === 'number' && (
            <span className={css.badge}>{t('highSensitivity')}: {String(vaultStats.highSensitivity)}</span>
          )}
          {report !== null && report.strength !== null && (
            <span className={`${css.badge} ${report.strength.weak > 0 ? css.badgeDanger : css.badgeOk}`}>
              {t('healthStrength')}: {report.strength.weak}W/{report.strength.fair}F/{report.strength.strong}S
            </span>
          )}
          {report !== null && (
            <span className={`${css.badge} ${report.verdict === 'good' ? css.badgeOk : report.verdict === 'fair' ? css.badgeWarn : css.badgeDanger}`}>
              <svg className={css.scoreRing} width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
                <circle cx="8" cy="8" r="6.5" fill="none" stroke="var(--dsh-color-border, #ddd)" strokeWidth="2" />
                <circle
                  cx="8" cy="8" r="6.5" fill="none"
                  stroke={report.verdict === 'good' ? '#2e9e5b' : report.verdict === 'fair' ? '#c98a1b' : '#cf3d3d'}
                  strokeWidth="2" strokeLinecap="round"
                  strokeDasharray={`${(report.score / 100 * 2 * Math.PI * 6.5).toFixed(1)} ${(2 * Math.PI * 6.5).toFixed(1)}`}
                  transform="rotate(-90 8 8)"
                />
              </svg>
              {t('healthScore')}: {report.score} ({t(VERDICT_KEYS[report.verdict] ?? 'verdictGood')})
            </span>
          )}
          {report !== null && report.no2fa.length > 0 && (
            <span className={`${css.badge} ${css.badgeWarn}`}>{t('no2fa')}: {report.no2fa.length}</span>
          )}
          {report !== null && report.httpSites.length > 0 && (
            <span className={`${css.badge} ${css.badgeWarn}`}>{t('httpSites')}: {report.httpSites.length}</span>
          )}
          {report !== null && report.rotation.length > 0 && (
            <span className={`${css.badge} ${css.badgeWarn}`}>{t('reportRotation')}: {report.rotation.length}</span>
          )}
          {vaultStats !== null && typeof vaultStats.expired === 'number' && vaultStats.expired > 0 && (
            <span className={`${css.badge} ${css.badgeDanger}`}>{t('dueExpired')}: {String(vaultStats.expired)}</span>
          )}
          {report !== null && report.weak.length > 0 && (
            <span className={`${css.badge} ${css.badgeDanger}`}>{t('reportWeak')}: {report.weak.length}</span>
          )}
          {report !== null && report.reused.length > 0 && (
            <span className={`${css.badge} ${css.badgeDanger}`}>{t('reportReused')}: {report.reused.length}</span>
          )}
          {dupGroups > 0 && (
            <span className={`${css.badge} ${css.badgeWarn}`}>{t('dupGroups')}: {dupGroups}</span>
          )}
          {report !== null && report.rotation.length === 0 && report.weak.length === 0 && report.reused.length === 0 && (
            <span className={`${css.badge} ${css.badgeOk}`}>{t('healthOk')}</span>
          )}
          {backupInfo !== null && backupInfo.daysSinceBackup >= 0 && (
            <span className={`${css.badge} ${backupInfo.daysSinceBackup > 14 ? css.badgeDanger : backupInfo.daysSinceBackup > 7 ? css.badgeWarn : ''}`}>
              {t('healthBackup')}: {backupInfo.daysSinceBackup}d ({backupInfo.backups})
            </span>
          )}
          <button type="button" className={css.backupButton} onClick={() => void exportReportCsv()} disabled={busy || report === null}>
            {t('exportReport')}
          </button>
          <button type="button" className={css.backupButton} onClick={() => void backupNow()} disabled={busy}>
            {t('backupNow')}
          </button>
          <button type="button" className={css.backupButton} onClick={() => void runBreachCheck()} disabled={busy}>
            {t('breachCheck')}
          </button>
          <button type="button" className={css.backupButton} onClick={() => void lockNow()} disabled={busy || locked}>
            {t('lock')}
          </button>
          <button type="button" className={css.backupButton} onClick={() => void runRecoveryCode()} disabled={busy || locked}>
            {t('recoveryCode')}
          </button>
          <button type="button" className={css.backupButton} onClick={() => void runVerifyRecovery()} disabled={busy || locked}>
            {t('recoveryVerify')}
          </button>
        </div>
      )}

      {breach !== null && (breach.pwned.length > 0 || breach.weak.length > 0) && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('breachTitle')}{breach.offline ? ` (${t('breachOffline')})` : ''}</p>
          {breach.pwned.slice(0, 6).map(item => (
            <p key={item.id} className={css.reportSub}>· {item.title} — {t('breachPwned')}{item.count > 0 ? ` ×${item.count}` : ''}</p>
          ))}
          {breach.weak.slice(0, 6).map(item => (
            <p key={item.id} className={css.reportSub}>· {item.title} — {t('breachWeak')}</p>
          ))}
        </div>
      )}
      {state.status === 'ready' && (
        <p className={css.footer}>
          {t('entryCount')}: {state.entries.length}
          {vaultStats !== null && typeof vaultStats.withTotp === 'number' && ` · TOTP: ${String(vaultStats.withTotp)}`}
          {vaultStats !== null && typeof vaultStats.highSensitivity === 'number' && ` · ${t('highSensitivity')}: ${String(vaultStats.highSensitivity)}`}
          {backupInfo !== null && backupInfo.daysSinceBackup >= 0 && ` · backup: ${backupInfo.daysSinceBackup}d ago`}
          {vaultStats !== null && typeof vaultStats.byTag === 'object' && vaultStats.byTag !== null
            && Object.keys(vaultStats.byTag as Record<string, unknown>).length > 0
            && ` · tags: ${Object.entries(vaultStats.byTag as Record<string, unknown>).map(([k, v]) => `${k}(${String(v)})`).join(' ')}`}
        </p>
      )}

      </div>)}

      {editor.status !== 'closed' && (
        <div className={css.editor} role="dialog" aria-label={editor.status === 'creating' ? t('add') : t('edit')}>
          <div className={css.editorBody}>
            <div className={css.genOpts}>
              <label className={css.genOptRow}>
                <span>{t('tplApply')}</span>
                <select
                  value=""
                  onChange={event => { const v = event.target.value; if (v) applyTemplate(v) }}
                >
                  <option value="">—</option>
                  {tplList.map(tpl => <option key={tpl.name} value={tpl.name}>{templateLabel(tpl.name)}</option>)}
                </select>
              </label>
              {editor.status === 'editing' && (
                <button type="button" className={css.retryButton} onClick={() => void saveAsTemplate()} disabled={busy}>{t('tplSave')}</button>
              )}
            </div>
            {FORM_FIELDS.filter(f => {
              const kind = form.kind ?? 'login'
              // Card-only fields show only for the card kind; everything else
              // is hidden when a card is selected (keeps the form focused).
              if (f.key === 'cardNumber' || f.key === 'cardExpiry' || f.key === 'cardCvv' || f.key === 'cardHolder') {
                return kind === 'card'
              }
              return kind !== 'card' || f.key === 'title' || f.key === 'kind' || f.key === 'notes' || f.key === 'icon' || f.key === 'color'
            }).map(field => (
              <label key={field.key} className={css.field}>
                <span>{t(field.label)}</span>
                {field.key === 'kind' ? (
                  <select
                    value={form.kind ?? 'login'}
                    onChange={event => changeKind(event.target.value)}
                  >
                    {Object.entries(KIND_KEYS).map(([value, key]) => (
                      <option key={value} value={value}>{t(key)}</option>
                    ))}
                  </select>
                ) : field.key === 'title' ? (
                  <input
                    value={form.title ?? ''}
                    onChange={event => setForm(previous => ({ ...previous, title: event.target.value }))}
                  />
                ) : field.key === 'password' || field.key === 'otpSecret' || field.key === 'apiKey'
                  || field.key === 'secret' || field.key === 'accessToken' || field.key === 'refreshToken'
                  || field.key === 'privateKey' ? (
                  <span className={css.secretField}>
                    <input
                      type={revealed[field.key] ? 'text' : 'password'}
                      value={(form[field.key] as string | undefined) ?? ''}
                      onChange={event => setForm(previous => ({ ...previous, [field.key]: event.target.value }))}
                    />
                    {field.key === 'password' && (
                      <>
                        <button
                          type="button"
                          className={css.revealButton}
                          title={t('genPwHint')}
                          onClick={() => { void generatePassword(genOpts).then(r => { setForm(previous => ({ ...previous, password: r.password })); void generatorHistory().then(setGenHistory).catch(() => {}) }) }}
                        >{t('genPw')}</button>
                        <button
                          type="button"
                          className={css.revealButton}
                          title={t('genOptsHint')}
                          onClick={() => setShowGenOpts(v => !v)}
                        >⚙</button>
                      </>
                    )}
                    <button
                      type="button"
                      className={css.revealButton}
                      onClick={() => setRevealed(previous => ({ ...previous, [field.key]: !previous[field.key] }))}
                    >{revealed[field.key] ? t('hide') : t('show')}</button>
                  </span>
                ) : field.key === 'expiresAt' ? (
                  <input
                    type="datetime-local"
                    value={form.expiresAt !== undefined ? new Date(form.expiresAt).toISOString().slice(0, 16) : ''}
                    onChange={event => {
                      const raw = event.target.value
                      const epoch = raw.length > 0 ? Date.parse(raw) : NaN
                      setForm(previous => ({ ...previous, expiresAt: Number.isNaN(epoch) ? undefined : epoch }))
                    }}
                  />
                ) : field.key === 'rotationDays' ? (
                  <input
                    type="number"
                    min={0}
                    max={3650}
                    placeholder={t('rotationClearHint')}
                    value={form.rotationDays ?? ''}
                    onChange={event => {
                      const raw = event.target.value
                      setForm(previous => ({ ...previous, rotationDays: raw.length > 0 ? Number(raw) : undefined }))
                    }}
                  />
                ) : field.key === 'sensitivity' ? (
                  <select
                    value={form.sensitivity ?? 'normal'}
                    onChange={event => setForm(previous => ({ ...previous, sensitivity: event.target.value === 'high' ? 'high' : 'normal' }))}
                  >
                    <option value="normal">{t('sensitivityNormal')}</option>
                    <option value="high">{t('sensitivityHigh')}</option>
                  </select>
                ) : field.key === 'favorite' ? (
                  <label className={css.checkField}>
                    <input
                      type="checkbox"
                      checked={form.favorite ?? false}
                      onChange={event => setForm(previous => ({ ...previous, favorite: event.target.checked }))}
                    />
                    {t('favoriteHint')}
                  </label>
                ) : field.key === 'cardNumber' ? (
                  <input
                    type="text"
                    inputMode="numeric"
                    placeholder="4111 1111 1111 1111"
                    value={(form.cardNumber ?? '').replace(/(.{4})/g, '$1 ').trim()}
                    onChange={event => {
                      const digits = event.target.value.replace(/\D/g, '').slice(0, 19)
                      setForm(previous => ({ ...previous, cardNumber: digits }))
                    }}
                  />
                ) : field.key === 'cardExpiry' ? (
                  <input
                    type="text"
                    inputMode="numeric"
                    placeholder="MM/YY"
                    maxLength={5}
                    value={form.cardExpiry ?? ''}
                    onChange={event => {
                      let raw = event.target.value.replace(/\D/g, '').slice(0, 4)
                      if (raw.length >= 3) raw = raw.slice(0, 2) + '/' + raw.slice(2)
                      setForm(previous => ({ ...previous, cardExpiry: raw }))
                    }}
                  />
                ) : field.key === 'cardCvv' ? (
                  <input
                    type="text"
                    inputMode="numeric"
                    placeholder="123"
                    maxLength={4}
                    value={form.cardCvv ?? ''}
                    onChange={event => setForm(previous => ({ ...previous, cardCvv: event.target.value.replace(/\D/g, '').slice(0, 4) }))}
                  />
                ) : field.key === 'cardHolder' ? (
                  <input
                    type="text"
                    value={form.cardHolder ?? ''}
                    onChange={event => setForm(previous => ({ ...previous, cardHolder: event.target.value }))}
                  />
                ) : field.key === 'icon' ? (
                  <span className={css.iconFieldWrap}>
                    <input
                      type="text"
                      value={(form.icon as string | undefined) ?? ''}
                      placeholder="🔑"
                      maxLength={4}
                      onChange={event => setForm(previous => ({ ...previous, icon: event.target.value }))}
                    />
                    <span className={css.emojiPicker} role="group" aria-label={t('iconPickerHint')}>
                      {EMOJI_ICONS.map(e => (
                        <button key={e} type="button" className={css.emojiBtn} title={e} onClick={() => setForm(previous => ({ ...previous, icon: e }))}>{e}</button>
                      ))}
                    </span>
                  </span>
                ) : field.key === 'color' ? (
                  <span className={css.colorFieldWrap}>
                    <input
                      type="text"
                      value={(form.color as string | undefined) ?? ''}
                      placeholder="#2e9e5b"
                      maxLength={7}
                      onChange={event => setForm(previous => ({ ...previous, color: event.target.value }))}
                    />
                    <span className={css.colorPalette} role="group" aria-label={t('colorPickerHint')}>
                      {COLOR_PRESETS.map(c => (
                        <button key={c} type="button" className={css.colorSwatch} style={{ background: c }} title={c} aria-label={c} onClick={() => setForm(previous => ({ ...previous, color: c }))} />
                      ))}
                    </span>
                  </span>
                ) : field.key === 'username' ? (
                  <input
                    type="text"
                    value={(form[field.key] as string | undefined) ?? ''}
                    onChange={event => setForm(previous => ({ ...previous, [field.key]: event.target.value }))}
                  />
                ) : (
                  <input
                    type="text"
                    value={(form[field.key] as string | undefined) ?? ''}
                    onChange={event => setForm(previous => ({ ...previous, [field.key]: event.target.value }))}
                  />
                )}
              </label>
            ))}
            {pwStrength !== null && (
              <div className={css.pwMeter}>
                <div className={`${css.pwBar} ${pwStrength.score >= 60 ? css.pwStrong : pwStrength.score >= 40 ? css.pwFair : css.pwWeak}`} style={{ width: `${pwStrength.score}%` }} />
                <span className={css.pwLabel}>{t('strengthLabel')}: {pwStrength.score}/100 ({t(VERDICT_KEYS_SHORT[pwStrength.verdict] ?? 'verdictGood')}) · {t('entropyLabel')}: {pwStrength.bits} bits</span>
              </div>
            )}
            {showGenOpts && (
              <div className={css.genOpts}>
                <label className={css.genOptRow}>
                  <span>{t('genPassphrase')}</span>
                  <input
                    type="checkbox"
                    checked={genOpts.passphrase}
                    onChange={event => setGenOpts(previous => ({ ...previous, passphrase: event.target.checked }))}
                  />
                </label>
                {genOpts.passphrase ? (
                  <>
                    <label className={css.genOptRow}>
                      <span>{t('genWords')}</span>
                      <input
                        type="number" min={2} max={12} value={genOpts.words}
                        onChange={event => setGenOpts(previous => ({ ...previous, words: Math.max(2, Math.min(12, Number(event.target.value) || 4)) }))}
                      />
                    </label>
                    <label className={css.genOptRow}>
                      <span>{t('genSeparator')}</span>
                      <input
                        type="text" maxLength={4} value={genOpts.separator}
                        onChange={event => setGenOpts(previous => ({ ...previous, separator: event.target.value }))}
                      />
                    </label>
                    <label className={css.genOptRow}>
                      <span>{t('genWordDigits')}</span>
                      <input
                        type="checkbox"
                        checked={genOpts.wordDigits}
                        onChange={event => setGenOpts(previous => ({ ...previous, wordDigits: event.target.checked }))}
                      />
                    </label>
                  </>
                ) : (
                  <>
                    <label className={css.genOptRow}>
                      <span>{t('genLength')}</span>
                      <input
                        type="number" min={6} max={64} value={genOpts.length}
                        onChange={event => setGenOpts(previous => ({ ...previous, length: Math.max(6, Math.min(64, Number(event.target.value) || 24)) }))}
                      />
                    </label>
                    {(['uppercase', 'lowercase', 'digits', 'symbols', 'excludeAmbiguous'] as const).map(key => (
                      <label key={key} className={css.genOptRow}>
                        <span>{t(GEN_OPT_KEYS[key] ?? 'genOptUppercase')}</span>
                        <input
                          type="checkbox"
                          checked={genOpts[key]}
                          onChange={event => setGenOpts(previous => ({ ...previous, [key]: event.target.checked }))}
                        />
                      </label>
                    ))}
                  </>
                )}
                {genHistory.length > 0 && (
                  <div className={css.genHist}>
                    <span>{t('genHistory')}:</span>
                    {genHistory.slice(0, 3).map((h, i) => (
                      <button
                        key={i}
                        type="button"
                        className={css.revealButton}
                        onClick={() => setForm(previous => ({ ...previous, password: h.password }))}
                        title={new Date(h.at).toLocaleString()}
                      >{h.password}</button>
                    ))}
                  </div>
                )}
              </div>
            )}
            <label className={css.field}>
              <span>{t('fieldTags')}</span>
              <input
                list="dsh-vault-tags"
                value={tagsDraft}
                onChange={event => setTagsDraft(event.target.value)}
                placeholder="dev, prod"
              />
              <datalist id="dsh-vault-tags">
                {[...new Set(state.status === 'ready' ? state.entries.flatMap(e => e.tags ?? []) : [])].sort().map(tag => (
                  <option key={tag} value={tag} />
                ))}
              </datalist>
            </label>
            <label className={css.field}>
              <span>{t('fieldCustom')}</span>
              <textarea
                value={fieldsDraft}
                onChange={event => setFieldsDraft(event.target.value)}
                rows={3}
                placeholder="region=us-east-1&#10;team=infra"
              />
            </label>
          </div>
          <div className={css.editorActions}>
            <button type="button" onClick={() => setEditor({ status: 'closed' })} disabled={busy}>{t('cancel')}</button>
            <button type="button" className={css.saveButton} onClick={() => void save()} disabled={busy}>{t('save')}</button>
          </div>
        </div>
      )}
    </section>
  )
}
