/**
 * Vault settings section: list, search, add, edit, delete, and copy encrypted
 * credentials. All mutations go through the host VaultGateway remote; secrets
 * are shown only inside the edit form or a copy action, never in the list.
 */

import { useEffect, useId, useMemo, useState, type ReactNode } from 'react'
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
  config: () => Promise<{ accessMode: 'readonly' | 'ask' | 'auto'; autoCapture: boolean }>
  setAccessMode: (mode: 'readonly' | 'ask' | 'auto') => Promise<{ accessMode: 'readonly' | 'ask' | 'auto'; autoCapture: boolean }>
  setAutoCapture: (enabled: boolean) => Promise<{ accessMode: 'readonly' | 'ask' | 'auto'; autoCapture: boolean }>
  list: () => Promise<VaultSummaryWire[]>
  search: (query: string, limit?: number) => Promise<VaultSummaryWire[]>
  get: (id: string) => Promise<{ found: boolean; entry?: VaultFullWire }>
  add: (patch: VaultPatch & { title: string }) => Promise<VaultSummaryWire>
  update: (id: string, patch: VaultPatch) => Promise<{ found: boolean; entry?: VaultSummaryWire }>
  remove: (id: string) => Promise<{ deleted: boolean }>
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
  listVaults: () => Promise<Array<{ name: string; active: boolean }>>
  touch: (id: string) => Promise<{ touched: boolean }>
  verifyAll: () => Promise<Array<{ id: string; title: string; issues: string[] }>>
  breachCheck: (online?: boolean) => Promise<{ checked: number; pwned: Array<{ id: string; title: string; count: number }>; weak: Array<{ id: string; title: string }>; offline: boolean }>
  generatePassword: () => Promise<{ password: string }>
  merge: (fromId: string, toId: string, keepSource?: boolean) => Promise<{ found: boolean }>
  restore: (id: string) => Promise<{ restored: boolean }>
  undeleteAll: () => Promise<{ restored: number }>
  totp: (id: string) => Promise<{ code: string; label?: string; secondsRemaining: number }>
}

/** Type-level alias so consumers can reference the wire shapes without values. */
export type VaultSectionTypes = {
  entries: VaultSummaryWire[]
  fullEntry: VaultFullWire
  summaryEntry: VaultSummaryWire
  config: { accessMode: 'readonly' | 'ask' | 'auto'; autoCapture: boolean }
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

const KIND_KEYS: Record<string, VaultLocaleKey> = {
  login: 'kindLogin',
  ssh: 'kindSsh',
  'api-key': 'kindApiKey',
  secret: 'kindSecret',
  oauth: 'kindOauth',
  custom: 'kindCustom',
}

type ViewState =
  | { readonly status: 'loading' }
  | { readonly status: 'error' }
  | { readonly status: 'ready'; readonly entries: VaultSummaryWire[] }

type EditorState =
  | { readonly status: 'closed' }
  | { readonly status: 'creating' }
  | { readonly status: 'editing'; readonly entry: VaultFullWire }

function emptyForm(): FormFields {
  return { title: '', kind: 'login', username: '', email: '', phone: '', password: '', host: '', port: '', icon: '', color: '' }
}

/** Render the Vault settings section. */
export function VaultSection(props: VaultSectionProps): ReactNode {
  const { t, config, setAccessMode, setAutoCapture, list, search, get, add, update, remove, trash, rotation, health, duplicates, duplicateGroups, merge, history, stats, backupStatus, backup, recent, restore, undeleteAll, totp, status, switchVault, listVaults, touch, verifyAll, breachCheck, generatePassword } = props
  const searchId = useId()
  const [query, setQuery] = useState('')
  const [state, setState] = useState<ViewState>({ status: 'loading' })
  const [editor, setEditor] = useState<EditorState>({ status: 'closed' })
  const [form, setForm] = useState<FormFields>(emptyForm())
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [totpMap, setTotpMap] = useState<Record<string, { code: string; until: number }>>({})
  const [nowTick, setNowTick] = useState(Date.now())
  const [tagsDraft, setTagsDraft] = useState('')
  const [fieldsDraft, setFieldsDraft] = useState('')
  const [revealed, setRevealed] = useState<Record<string, boolean>>({})
  const [kindFilter, setKindFilter] = useState('')
  const [tagFilter, setTagFilter] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [sortBy, setSortBy] = useState<'alpha' | 'recent'>('alpha')
  const [policy, setPolicy] = useState<{ accessMode: 'readonly' | 'ask' | 'auto'; autoCapture: boolean } | null>(null)
  const [showTrash, setShowTrash] = useState(false)
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
  const [vaults, setVaults] = useState<Array<{ name: string; active: boolean }>>([])
  const [audit, setAudit] = useState<Array<{ id: string; title: string; issues: string[] }>>([])
  const [breach, setBreach] = useState<{ checked: number; pwned: Array<{ id: string; title: string; count: number }>; weak: Array<{ id: string; title: string }>; offline: boolean } | null>(null)

  const readonly = policy?.accessMode === 'readonly'

  /** Switch the active vault and reload everything. */
  async function switchVaultTo(name: string): Promise<void> {
    setBusy(true)
    setMessage(null)
    try {
      await switchVault(name)
      await listVaults().then(setVaults)
      setQuery('')
      void refresh()
      status().then(value => setLocked(value.locked)).catch(() => {})
    } catch {
      setMessage(t('error'))
    } finally {
      setBusy(false)
    }
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
    } catch {
      setMessage(t('error'))
    } finally {
      setBusy(false)
    }
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
    } catch {
      setMessage(t('error'))
    } finally {
      setBusy(false)
    }
  }

  /** Run an encrypted backup now and refresh the backup-age badge. */
  async function backupNow(): Promise<void> {
    setBusy(true)
    setMessage(null)
    try {
      const result = await backup()
      setBackupInfo({ daysSinceBackup: 0, backups: result.kept })
      setMessage(`${t('backupDone')} (${result.kept} kept, ${result.pruned} pruned)`)
      void refresh()
    } catch {
      setMessage(t('error'))
    } finally {
      setBusy(false)
    }
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
    return () => { current = false }
  }, [config, status, listVaults])

  const refresh = useMemo(() => async () => {
    setState({ status: 'loading' })
    try {
      const entries = query.trim().length === 0
        ? await list()
        : await search(query.trim())
      setState({ status: 'ready', entries })
      status().then(value => setLocked(value.locked)).catch(() => {})
    } catch {
      setState({ status: 'error' })
    }
  }, [list, search, query])

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

  // Vault health & meta: load once on mount (stats, backup age, rotation,
  // weak/reused scan, recent activity) and refresh on window focus.
  useEffect(() => {
    let current = true
    const load = (): void => {
      void Promise.all([
        stats().catch(() => null),
        backupStatus().catch(() => null),
        rotation().catch(() => []),
        health().catch(() => null),
        recent().catch(() => []),
        duplicates().catch(() => null),
      ]).then(([st, bk, rot, hl, rc, dp]) => {
        if (dp !== null && typeof dp === 'object' && (dp as { groups?: number }).groups !== undefined) {
          setDupGroups((dp as { groups: number }).groups)
        }
        duplicateGroups().then(setDupList).catch(() => {})
        verifyAll().then(setAudit).catch(() => {})
        if (!current) return
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
    }
    load()
    const onFocus = (): void => { load() }
    window.addEventListener('focus', onFocus)
    return () => { current = false; window.removeEventListener('focus', onFocus) }
  }, [stats, backupStatus, rotation, health, recent, duplicates, duplicateGroups, verifyAll])

  /** Open the editor for a new entry. */
  function startCreate(): void {
    setForm(emptyForm())
    setTagsDraft('')
    setFieldsDraft('')
    setMessage(null)
    setEditor({ status: 'creating' })
  }

  /** Open the editor for an existing entry (fetches full secrets). */
  async function startEdit(id: string): Promise<void> {
    setBusy(true)
    setMessage(null)
    try {
      const result = await get(id)
      if (!result.found || result.entry === undefined) {
        setMessage(t('error'))
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
    } catch {
      setMessage(t('error'))
    } finally {
      setBusy(false)
    }
  }

  /** Save the current form (create or update). */
  async function save(): Promise<void> {
    if (!(form.title ?? '').trim()) {
      setMessage(t('error'))
      return
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
      } else if (editor.status === 'editing') {
        await update(editor.entry.id, patch)
      }
      setEditor({ status: 'closed' })
      await refresh()
    } catch {
      setMessage(t('error'))
    } finally {
      setBusy(false)
    }
  }

  /** Delete an entry after confirmation. */
  async function removeEntry(id: string): Promise<void> {
    if (!window.confirm(t('deleteConfirm'))) return
    setBusy(true)
    try {
      await remove(id)
      await refresh()
    } catch {
      setMessage(t('error'))
    } finally {
      setBusy(false)
    }
  }

  /** Copy a field value to the clipboard and flash the row. */
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
    window.setTimeout(() => setCopiedId(null), 1500)
  }

  /** Fetch and display a TOTP code for an entry with an otpSecret. */
  async function showTotp(id: string): Promise<void> {
    setBusy(true)
    try {
      const result = await totp(id)
      setTotpMap(previous => ({ ...previous, [id]: { code: result.code, until: Date.now() + result.secondsRemaining * 1000 } }))
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

  /** Human-friendly value formatting for the expanded detail box. */
  function formatDetail(key: string, value: unknown): string {
    if (key === 'expiresAt' || key === 'updatedAt' || key === 'createdAt') {
      const n = Number(value)
      return Number.isFinite(n) && n > 0 ? new Date(n).toISOString().slice(0, 16).replace('T', ' ') : String(value)
    }
    if (key === 'sensitivity' && value === 'high') return t('sensitivityHigh')
    if (key === 'kind') return t(KIND_KEYS[String(value)] ?? 'kindCustom')
    if (Array.isArray(value)) return value.join(', ')
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
      case 'custom': return '🧩'
      default: return '👤'
    }
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
        <p role="alert" className={css.lockedBanner}>{t('lockedBanner')}</p>
      )}

      <div className={css.toolbar}>
        {vaults.length > 0 && (
          <select
            className={css.kindFilter}
            value={vaults.find(v => v.active)?.name ?? ''}
            onChange={event => void switchVaultTo(event.target.value)}
            aria-label={t('vaultSelect')}
          >
            {vaults.map(v => (
              <option key={v.name} value={v.name}>{v.name}{v.active ? ' *' : ''}</option>
            ))}
          </select>
        )}
        <label className={css.searchBox}>
          <span className={css.srOnly}>{t('searchPlaceholder')}</span>
          <input
            id={searchId}
            type="search"
            placeholder={t('searchPlaceholder')}
            value={query}
            onChange={event => setQuery(event.target.value)}
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
          className={css.sortButton}
          onClick={() => setSortBy(sortBy === 'alpha' ? 'recent' : 'alpha')}
        >{sortBy === 'alpha' ? t('sortAlpha') : t('sortRecent')}</button>
        <button type="button" className={css.addButton} onClick={startCreate} disabled={busy || readonly}>
          + {t('add')}
        </button>
      </div>

      {policy !== null && (
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
                  () => { setMessage(t('error')); setBusy(false) },
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
                  () => { setMessage(t('error')); setBusy(false) },
                )
              }}
            />
          </label>
          <p className={policy.accessMode === 'readonly' ? css.modeReadonly : policy.accessMode === 'ask' ? css.modeAsk : css.modeAuto}>
            {policy.accessMode === 'readonly'
              ? t('modeReadonlyHint')
              : policy.accessMode === 'ask'
                ? t('modeAskHint')
                : t('modeAutoHint')}
            {policy.autoCapture ? ` · ${t('autoCaptureOn')}` : ` · ${t('autoCaptureOff')}`}
          </p>
        </div>
      )}

      {message !== null && <p role="alert" className={css.error}>{message}</p>}

      {state.status === 'loading' && <p className={css.status}>{t('loading')}</p>}
      {state.status === 'error' && (
        <p role="alert" className={css.error}>
          {t('error')}{' '}
          <button type="button" className={css.retryButton} onClick={() => void refresh()}>{t('retry')}</button>
        </p>
      )}
      {state.status === 'ready' && state.entries.length === 0 && (
        <div className={css.emptyBox}>
          <p className={css.empty}>{t('empty')}</p>
          <p className={css.emptyHint}>{readonly ? t('emptyHintReadonly') : t('emptyHint')}</p>
          {!readonly && (
            <button type="button" className={css.addButton} onClick={startCreate}>{t('quickAdd')}</button>
          )}
        </div>
      )}

      {recentEntries.length > 0 && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('recentlyAdded')}</p>
          {recentEntries.map((e, i) => (
            <p key={i} className={css.reportLine}>{String(e.title ?? '')}{relTime((e as Record<string, unknown>).updatedAt) !== '' && ` · ${relTime((e as Record<string, unknown>).updatedAt)}`}</p>
          ))}
        </div>
      )}

      {recentEvents.length > 0 && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('recentActivity')}</p>
          {recentEvents.map((ev, i) => (
            <p key={i} className={css.reportLine}>
              {String(ev.action ?? '')} · {String(ev.title ?? ev.id ?? '')}{relTime((ev as Record<string, unknown>).at) !== '' && ` · ${relTime((ev as Record<string, unknown>).at)}`}
            </p>
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
                disabled={busy || readonly}
              >{t('dupMerge')}</button>
            </div>
          ))}
        </div>
      )}

      {state.status === 'ready' && (state.entries.length > 0 || trashEntries.length > 0) && (
        <button
          type="button"
          className={css.trashButton}
          onClick={() => {
            if (!showTrash) void trash().then(setTrashEntries)
            setShowTrash(!showTrash)
          }}
        >{showTrash ? t('hideTrash') : t('showTrash')}{trashEntries.length > 0 ? ` (${trashEntries.length})` : ''}</button>
      )}

      {showTrash && (
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
                  onClick={() => { void restore(entry.id).then(() => { void trash().then(setTrashEntries); void refresh() }) }}
                  disabled={busy || readonly}
                >{t('restore')}</button>
              </div>
            </li>
          ))}
          {trashEntries.length === 0 && <p className={css.empty}>{t('trashEmpty')}</p>}
        </ul>
      )}
      {showTrash && trashEntries.length > 0 && (
        <>
          <button
            type="button"
            className={css.trashButton}
            onClick={() => {
              setBusy(true)
              void undeleteAll().then(() => {
                void trash().then(setTrashEntries)
                void refresh()
                setBusy(false)
              }, () => setBusy(false))
            }}
            disabled={busy || readonly}
          >{t('restoreAll')}</button>
          <button
            type="button"
            className={css.dangerButton}
            onClick={() => {
              if (!window.confirm(t('clearTrashConfirm'))) return
              setBusy(true)
              void Promise.all(trashEntries.map(e => remove(e.id))).then(() => {
                void trash().then(setTrashEntries)
                void refresh()
                setBusy(false)
              }, () => setBusy(false))
            }}
            disabled={busy || readonly}
          >{t('clearTrash')}</button>
        </>
      )}

      {state.status === 'ready' && state.entries.length > 0 && (
        <ul className={css.list}>
          {state.entries.filter(entry => (kindFilter === '' || entry.kind === kindFilter) && (tagFilter === '' || (entry.tags ?? []).includes(tagFilter))).sort((a, b) => sortBy === 'alpha' ? a.title.localeCompare(b.title) : (b.updatedAt ?? 0) - (a.updatedAt ?? 0)).map(entry => {
            const totpInfo = totpMap[entry.id]
            const remaining = totpInfo !== undefined && totpInfo.until > 0 ? Math.max(0, Math.ceil((totpInfo.until - nowTick) / 1000)) : undefined
            const frac = remaining !== undefined ? remaining / 30 : 0
            const code = totpInfo?.code
            return (
              <li key={entry.id} className={`${css.row}${dueMap[entry.id] !== undefined ? ` ${dueMap[entry.id]!.due === 'expired' ? css.rowExpired : css.rowDue}` : ''}`}>
                <div className={css.rowMain} onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}>
                  <span className={css.title} style={entry.color !== undefined && entry.color !== '' ? { borderLeft: `3px solid ${entry.color}`, paddingLeft: 6 } : undefined}>
                    <span className={css.kindIcon}>{entry.icon ?? kindIcon(entry.kind)}</span>
                    {(entry as VaultSummaryWire & { favorite?: boolean }).favorite && (
                      <span className={css.pinStar} title={t('pinned')}>★</span>
                    )}
                    {entry.title}
                    {(entry as VaultSummaryWire & { sensitivity?: string }).sensitivity === 'high' && (
                      <span className={css.highBadge}>{t('highSensitivity')}</span>
                    )}
                    {dueMap[entry.id] !== undefined && (
                      <span className={`${css.dueBadge} ${dueMap[entry.id]!.due === 'expired' ? css.badgeDanger : css.badgeWarn}`}>
                        {dueMap[entry.id]!.due === 'expired' ? t('dueExpired') : dueMap[entry.id]!.due === 'soon' ? `${t('dueExpiring')} ${dueMap[entry.id]!.daysLeft}d` : t('dueNow')}
                      </span>
                    )}
                  </span>
                  <span className={css.identity}>{identityLine(entry)}</span>
                  {code !== undefined && (
                    <span className={css.totp}>
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
                    {Object.entries(entry).filter(([k]) => !['id', 'title', 'favorite'].includes(k) && entry[k as keyof VaultSummaryWire] !== undefined).map(([k, v]) => (
                      <span key={k} className={css.detailItem}>
                        <strong>{k}</strong>: {formatDetail(k, v)}
                      </span>
                    ))}
                  </div>
                )}
                <div className={css.rowActions}>
                  {copiedId === entry.id && <span className={css.copied}>{t('copied')}</span>}
                  <button
                    type="button"
                    onClick={() => void copyValue(entry.id, entry.username ?? entry.title)}
                    disabled={busy}
                  >{t('copy')}</button>
                  <button
                    type="button"
                    onClick={() => {
                      setBusy(true)
                      void get(entry.id).then(r => {
                        if (r.found && r.entry?.password) void copyValue(entry.id, r.entry.password)
                        setBusy(false)
                      }, () => setBusy(false))
                    }}
                    disabled={busy || readonly}
                  >{t('copyPassword')}</button>
                  <button type="button" onClick={() => void showTotp(entry.id)} disabled={busy}>{t('totp')}</button>
                  {code !== undefined && (
                    <button type="button" onClick={() => void copyValue(entry.id, code)} disabled={busy}>{t('copyCode')}</button>
                  )}
                  <button type="button" onClick={() => void touch(entry.id).then(() => void refresh())} disabled={busy || readonly} title={t('touchHint')}>{t('touch')}</button>
                  <button type="button" onClick={() => void startEdit(entry.id)} disabled={busy || readonly}>{t('edit')}</button>
                  <button
                    type="button"
                    className={css.deleteButton}
                    onClick={() => void removeEntry(entry.id)}
                    disabled={busy || readonly}
                  >{t('delete')}</button>
                </div>
              </li>
            )
          })}
        </ul>
      )}

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
          <button type="button" className={css.backupButton} onClick={() => void backupNow()} disabled={busy}>
            {t('backupNow')}
          </button>
          <button type="button" className={css.backupButton} onClick={() => void runBreachCheck()} disabled={busy}>
            {t('breachCheck')}
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

      {editor.status !== 'closed' && (
        <div className={css.editor} role="dialog" aria-label={editor.status === 'creating' ? t('add') : t('edit')}>
          <div className={css.editorBody}>
            {FORM_FIELDS.map(field => (
              <label key={field.key} className={css.field}>
                <span>{t(field.label)}</span>
                {field.key === 'kind' ? (
                  <select
                    value={form.kind ?? 'login'}
                    onChange={event => setForm(previous => ({ ...previous, kind: event.target.value }))}
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
                      <button
                        type="button"
                        className={css.revealButton}
                        title={t('genPwHint')}
                        onClick={() => { void generatePassword().then(r => setForm(previous => ({ ...previous, password: r.password }))) }}
                      >{t('genPw')}</button>
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
                ) : (
                  <input
                    type="text"
                    value={(form[field.key] as string | undefined) ?? ''}
                    onChange={event => setForm(previous => ({ ...previous, [field.key]: event.target.value }))}
                  />
                )}
              </label>
            ))}
            <label className={css.field}>
              <span>{t('fieldTags')}</span>
              <input
                value={tagsDraft}
                onChange={event => setTagsDraft(event.target.value)}
                placeholder="dev, prod"
              />
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
