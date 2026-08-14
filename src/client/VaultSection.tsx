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
  otpSecret?: string
  url?: string
  notes?: string
  tags?: string[]
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
  health: () => Promise<{ weak: unknown[]; reused: unknown[] }>
  restore: (id: string) => Promise<{ restored: boolean }>
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
type FormFields = Pick<
  VaultFullWire, 'title' | 'kind' | 'username' | 'email' | 'phone' | 'password' | 'host' | 'port'
  | 'privateKey' | 'apiKey' | 'secret' | 'accessToken' | 'refreshToken' | 'otpSecret' | 'url' | 'notes'
>

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
]

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
  return { title: '', kind: 'login', username: '', email: '', phone: '', password: '', host: '', port: '' }
}

/** Render the Vault settings section. */
export function VaultSection(props: VaultSectionProps): ReactNode {
  const { t, config, setAccessMode, setAutoCapture, list, search, get, add, update, remove, trash, rotation, health, history, stats, restore, totp } = props
  const searchId = useId()
  const [query, setQuery] = useState('')
  const [state, setState] = useState<ViewState>({ status: 'loading' })
  const [editor, setEditor] = useState<EditorState>({ status: 'closed' })
  const [form, setForm] = useState<FormFields>(emptyForm())
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [codeMap, setCodeMap] = useState<Record<string, string>>({})
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
  const [report, setReport] = useState<{ rotation: unknown[]; weak: unknown[]; reused: unknown[] } | null>(null)
  const [recentEvents, setRecentEvents] = useState<Array<Record<string, unknown>>>([])
  const [vaultStats, setVaultStats] = useState<Record<string, unknown> | null>(null)

  const readonly = policy?.accessMode === 'readonly'

  useEffect(() => {
    let current = true
    void config().then(
      value => { if (current) setPolicy(value) },
      () => { /* policy is informational; ignore failures */ },
    )
    return () => { current = false }
  }, [config])

  const refresh = useMemo(() => async () => {
    setState({ status: 'loading' })
    try {
      const entries = query.trim().length === 0
        ? await list()
        : await search(query.trim())
      setState({ status: 'ready', entries })
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
    if (!form.title.trim()) {
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
        title: form.title.trim(),
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
      setCodeMap(previous => ({ ...previous, [id]: `${result.code} (${result.secondsRemaining}s)` }))
    } catch {
      setCodeMap(previous => ({ ...previous, [id]: t('error') }))
    } finally {
      setBusy(false)
    }
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

      <div className={css.toolbar}>
        <label className={css.searchBox}>
          <span className="sr-only">{t('searchPlaceholder')}</span>
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
      {state.status === 'error' && <p role="alert" className={css.error}>{t('error')}</p>}
      {state.status === 'ready' && state.entries.length === 0 && (
        <div className={css.emptyBox}>
          <p className={css.empty}>{t('empty')}</p>
          <p className={css.emptyHint}>{readonly ? t('emptyHintReadonly') : t('emptyHint')}</p>
          {!readonly && (
            <button type="button" className={css.addButton} onClick={startCreate}>{t('quickAdd')}</button>
          )}
        </div>
      )}

      {recentEvents.length > 0 && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('recentActivity')}</p>
          {recentEvents.map((ev, i) => (
            <p key={i} className={css.reportLine}>
              {String(ev.action ?? '')} · {String(ev.title ?? ev.id ?? '')}
            </p>
          ))}
        </div>
      )}

      {report !== null && (report.rotation.length > 0 || report.weak.length > 0 || report.reused.length > 0) && (
        <div className={css.reportBox}>
          <p className={css.reportTitle}>{t('reportTitle')}</p>
          {report.rotation.length > 0 && (
            <p className={css.reportLine}>{t('reportRotation')}: {report.rotation.length}</p>
          )}
          {report.weak.length > 0 && (
            <p className={css.reportLine}>{t('reportWeak')}: {report.weak.length}</p>
          )}
          {report.reused.length > 0 && (
            <p className={css.reportLine}>{t('reportReused')}: {report.reused.length}</p>
          )}
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
      )}

      {state.status === 'ready' && state.entries.length > 0 && (
        <ul className={css.list}>
          {state.entries.filter(entry => (kindFilter === '' || entry.kind === kindFilter) && (tagFilter === '' || (entry.tags ?? []).includes(tagFilter))).sort((a, b) => sortBy === 'alpha' ? a.title.localeCompare(b.title) : 0).map(entry => {
            const code = codeMap[entry.id]
            return (
              <li key={entry.id} className={css.row}>
                <div className={css.rowMain} onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}>
                  <span className={css.title}>
                    <span className={css.kindIcon}>{kindIcon(entry.kind)}</span>
                    {(entry as VaultSummaryWire & { favorite?: boolean }).favorite && (
                      <span className={css.pinStar} title={t('pinned')}>★</span>
                    )}
                    {entry.title}
                    {(entry as VaultSummaryWire & { sensitivity?: string }).sensitivity === 'high' && (
                      <span className={css.highBadge}>{t('highSensitivity')}</span>
                    )}
                  </span>
                  <span className={css.identity}>{identityLine(entry)}</span>
                  {code !== undefined && <span className={css.totp}>{code}</span>}
                </div>
                {expandedId === entry.id && (
                  <div className={css.detailBox}>
                    {Object.entries(entry).filter(([k]) => !['id', 'title'].includes(k) && entry[k as keyof VaultSummaryWire] !== undefined).map(([k, v]) => (
                      <span key={k} className={css.detailItem}>
                        <strong>{k}</strong>: {Array.isArray(v) ? v.join(', ') : String(v)}
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
        <p className={css.footer}>
          {t('entryCount')}: {state.entries.length}
          {vaultStats !== null && typeof vaultStats.withTotp === 'number' && ` · TOTP: ${String(vaultStats.withTotp)}`}
          {vaultStats !== null && typeof vaultStats.highSensitivity === 'number' && ` · ${t('highSensitivity')}: ${String(vaultStats.highSensitivity)}`}
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
                    <button
                      type="button"
                      className={css.revealButton}
                      onClick={() => setRevealed(previous => ({ ...previous, [field.key]: !previous[field.key] }))}
                    >{revealed[field.key] ? t('hide') : t('show')}</button>
                  </span>
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
