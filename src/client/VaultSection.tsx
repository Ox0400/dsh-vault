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
  config: () => Promise<{ accessMode: 'readonly' | 'readwrite'; autoCapture: boolean }>
  list: () => Promise<VaultSummaryWire[]>
  search: (query: string, limit?: number) => Promise<VaultSummaryWire[]>
  get: (id: string) => Promise<{ found: boolean; entry?: VaultFullWire }>
  add: (patch: VaultPatch & { title: string }) => Promise<VaultSummaryWire>
  update: (id: string, patch: VaultPatch) => Promise<{ found: boolean; entry?: VaultSummaryWire }>
  remove: (id: string) => Promise<{ deleted: boolean }>
  totp: (id: string) => Promise<{ code: string; label?: string; secondsRemaining: number }>
}

/** Type-level alias so consumers can reference the wire shapes without values. */
export type VaultSectionTypes = {
  entries: VaultSummaryWire[]
  fullEntry: VaultFullWire
  summaryEntry: VaultSummaryWire
  config: { accessMode: 'readonly' | 'readwrite'; autoCapture: boolean }
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
  const { t, config, list, search, get, add, update, remove, totp } = props
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
  const [policy, setPolicy] = useState<{ accessMode: 'readonly' | 'readwrite'; autoCapture: boolean } | null>(null)

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
    void Promise.resolve().then(refresh).then(
      () => { /* state already set inside refresh */ },
      () => { if (current) setState({ status: 'error' }) },
    )
    return () => { current = false }
    // refresh is memoized on query; list/search are stable inject faces.
  }, [refresh])

  /** Open the editor for a new entry. */
  function startCreate(): void {
    setForm(emptyForm())
    setTagsDraft('')
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
        </label>
        <button type="button" className={css.addButton} onClick={startCreate} disabled={busy || readonly}>
          + {t('add')}
        </button>
      </div>

      {policy !== null && (
        <p className={readonly ? css.modeReadonly : css.modeReadwrite}>
          {readonly ? t('modeReadonly') : t('modeReadwrite')}
          {policy.autoCapture ? ` · ${t('autoCaptureOn')}` : ` · ${t('autoCaptureOff')}`}
        </p>
      )}

      {message !== null && <p role="alert" className={css.error}>{message}</p>}

      {state.status === 'loading' && <p className={css.status}>{t('loading')}</p>}
      {state.status === 'error' && <p role="alert" className={css.error}>{t('error')}</p>}
      {state.status === 'ready' && state.entries.length === 0 && (
        <div className={css.emptyBox}>
          <p className={css.empty}>{t('empty')}</p>
          <p className={css.emptyHint}>{readonly ? t('emptyHintReadonly') : t('emptyHint')}</p>
        </div>
      )}

      {state.status === 'ready' && state.entries.length > 0 && (
        <ul className={css.list}>
          {state.entries.map(entry => {
            const code = codeMap[entry.id]
            return (
              <li key={entry.id} className={css.row}>
                <div className={css.rowMain}>
                  <span className={css.title}>{entry.title}</span>
                  <span className={css.identity}>{identityLine(entry)}</span>
                  {code !== undefined && <span className={css.totp}>{code}</span>}
                </div>
                <div className={css.rowActions}>
                  {copiedId === entry.id && <span className={css.copied}>{t('copied')}</span>}
                  <button
                    type="button"
                    onClick={() => void copyValue(entry.id, entry.username ?? entry.title)}
                    disabled={busy}
                  >{t('copy')}</button>
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
                ) : (
                  <input
                    type={field.key === 'password' || field.key === 'otpSecret' ? 'password' : 'text'}
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
