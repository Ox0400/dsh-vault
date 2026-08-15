/**
 * Password-manager import formats for dsh-vault: 1Password 1PUX (ZIP + JSON),
 * Enpass JSON export, Bitwarden JSON export, and generic password CSV
 * (Dashlane / NordPass / Keeper auto-detected by header synonyms).
 *
 * Format references (open-source):
 * - 1PUX: https://support.1password.com/1pux-format/ — a ZIP with
 *   export.data (accounts → vaults → items → details.fields).
 * - Enpass JSON export schema: enpass2keepassxc
 *   (https://github.com/nilsding/enpass2keepassxc) — folders[] + items[] with
 *   fields[{label,type,value,sensitive}].
 * - Bitwarden JSON: https://bitwarden.com/help/import-data/#bitwarden-import-format
 *   — items[] with login{username,password,uris} and totp.
 * - CSV column synonyms: pass-import
 *   (https://github.com/roddhjav/pass-import) nordpass/keeper/dashlane
 *   managers and the Dashlane CSV export documented by the community
 *   converter scripts.
 *
 * @module dsh-vault/imports
 */

import { readZip, zipEntry } from './zip.ts'
import { extractEntries as kdbxExtractEntries } from './kdbx.ts'

export interface ImportedCredential {
  title: string
  username: string
  password: string
  url: string
  notes: string
  otp?: string
  tags?: string[]
  favorite?: boolean
}

/** ── 1Password 1PUX ─────────────────────────────────────────────────────── */

interface OnePasswordField {
  id?: string
  title?: string
  value?: string
  designation?: string
  type?: string
}

interface OnePasswordItem {
  id?: string
  title?: string
  categoryUuid?: string
  url?: string
  urls?: Array<{ label?: string; url?: string }>
  tags?: string[]
  details?: {
    fields?: OnePasswordField[]
    notesPlain?: string
    sections?: Array<{ title?: string; fields?: OnePasswordField[] }>
  }
}

interface OnePasswordVault {
  attrs?: Record<string, unknown>
  items?: OnePasswordItem[]
}

interface OnePasswordAccount {
  attrs?: Record<string, unknown>
  vaults?: OnePasswordVault[]
}

/**
 * Read a 1Password 1PUX export (a ZIP buffer) into credentials. The archive
 * contains export.data (JSON) plus export.attributes and optional files/.
 */
export function readOnePasswordPux(data: Buffer): ImportedCredential[] {
  const entries = readZip(data)
  const exportData = zipEntry(entries, 'export.data')
  if (!exportData) throw new Error('1pux: export.data not found in archive')
  let parsed: { accounts?: OnePasswordAccount[] }
  try {
    parsed = JSON.parse(exportData.toString('utf8')) as { accounts?: OnePasswordAccount[] }
  } catch {
    throw new Error('1pux: export.data is not valid JSON')
  }
  const out: ImportedCredential[] = []
  for (const account of parsed.accounts ?? []) {
    for (const vault of account.vaults ?? []) {
      for (const item of vault.items ?? []) {
        const fields = item.details?.fields ?? []
        const sections = item.details?.sections ?? []
        const allFields: OnePasswordField[] = [...fields]
        for (const section of sections) allFields.push(...(section.fields ?? []))
        const byDesignation = new Map<string, string>()
        const named = new Map<string, string>()
        for (const f of allFields) {
          const value = f.value ?? ''
          if (f.designation !== undefined && f.designation !== '') byDesignation.set(f.designation.toLowerCase(), value)
          if (f.title !== undefined && f.title !== '') named.set(f.title.toLowerCase(), value)
        }
        const username = byDesignation.get('username') ?? byDesignation.get('login') ?? named.get('username') ?? named.get('login') ?? ''
        const password = byDesignation.get('password') ?? named.get('password') ?? ''
        const otp = byDesignation.get('otp') ?? named.get('otp') ?? named.get('one-time password') ?? named.get('totp') ?? ''
        const urls = item.urls ?? []
        const url = item.url ?? (urls.length > 0 ? urls[0]!.url ?? '' : '')
        const notes = item.details?.notesPlain ?? ''
        out.push({
          title: item.title ?? '',
          username,
          password,
          url,
          notes,
          ...(otp.length > 0 ? { otp } : {}),
          ...((item.tags ?? []).length > 0 ? { tags: item.tags } : {}),
        })
      }
    }
  }
  return out
}

/** ── Enpass JSON export ─────────────────────────────────────────────────── */

interface EnpassField {
  label?: string
  type?: string
  value?: string
  sensitive?: number
}

interface EnpassItem {
  uuid?: string
  title?: string
  category?: string
  favorite?: number
  folders?: string[]
  fields?: EnpassField[]
  note?: string
  subtitle?: string
  template_type?: string
  updated_at?: number
}

interface EnpassFolder {
  uuid?: string
  title?: string
}

interface EnpassExport {
  folders?: EnpassFolder[]
  items?: EnpassItem[]
}

/**
 * Read an Enpass JSON export (File > Export > .json) into credentials.
 * Items carry a `fields` array typed as username/password/url/totp/… plus
 * custom labels; `sensitive` marks protected values.
 */
export function readEnpassJson(input: string): ImportedCredential[] {
  let parsed: EnpassExport
  try {
    parsed = JSON.parse(input) as EnpassExport
  } catch {
    throw new Error('enpass: not valid JSON')
  }
  if (!Array.isArray(parsed.items) && !Array.isArray(parsed.folders)) {
    throw new Error('enpass: not an Enpass JSON export (missing items/folders)')
  }
  const folderNames = new Map<string, string>()
  for (const f of parsed.folders ?? []) {
    if (f.uuid !== undefined && f.title !== undefined) folderNames.set(f.uuid, f.title)
  }
  const out: ImportedCredential[] = []
  for (const item of parsed.items ?? []) {
    const fields = item.fields ?? []
    let username = ''
    let password = ''
    let url = ''
    let otp = ''
    const extraNotes: string[] = []
    for (const f of fields) {
      const value = f.value ?? ''
      const type = (f.type ?? '').toLowerCase()
      if (type === 'username' || type === 'email') username = username || value
      else if (type === 'password') password = value
      else if (type === 'url') url = value
      else if (type === 'totp' || type === 'otp') otp = value
      else if (value !== '' && (f.label ?? '') !== '') extraNotes.push(`${f.label}: ${value}`)
    }
    const tags = (item.folders ?? []).map(id => folderNames.get(id) ?? '').filter(Boolean)
    const notes = [item.note ?? '', ...extraNotes].filter(Boolean).join('\n')
    out.push({
      title: item.title ?? item.subtitle ?? '',
      username,
      password,
      url,
      notes,
      ...(otp.length > 0 ? { otp } : {}),
      ...(tags.length > 0 ? { tags } : {}),
      ...(item.favorite === 1 ? { favorite: true } : {}),
    })
  }
  return out
}

/** ── Bitwarden JSON export ──────────────────────────────────────────────── */

interface BitwardenLogin {
  username?: string
  password?: string
  uris?: Array<{ uri?: string }>
  totp?: string
}

interface BitwardenItem {
  id?: string
  name?: string
  notes?: string
  folderId?: string
  favorite?: boolean
  type?: number
  login?: BitwardenLogin
  secureNote?: { type?: number }
}

interface BitwardenFolder {
  id?: string
  name?: string
}

interface BitwardenExport {
  encrypted?: boolean
  folders?: BitwardenFolder[]
  items?: BitwardenItem[]
}

/**
 * Read a Bitwarden JSON export (unencrypted) into credentials. Only login
 * items (type 1) are imported; notes/URIs/TOTP are preserved.
 */
export function readBitwardenJson(input: string): ImportedCredential[] {
  let parsed: BitwardenExport
  try {
    parsed = JSON.parse(input) as BitwardenExport
  } catch {
    throw new Error('bitwarden: not valid JSON')
  }
  if (parsed.encrypted === true) {
    throw new Error('bitwarden: encrypted exports are not supported — export unencrypted JSON instead')
  }
  if (!Array.isArray(parsed.items)) {
    throw new Error('bitwarden: not a Bitwarden JSON export (missing items)')
  }
  const folderNames = new Map<string, string>()
  for (const f of parsed.folders ?? []) {
    if (f.id !== undefined && f.name !== undefined) folderNames.set(f.id, f.name)
  }
  const out: ImportedCredential[] = []
  for (const item of parsed.items ?? []) {
    if (item.type !== undefined && item.type !== 1) continue // only logins
    const login = item.login ?? {}
    const uris = login.uris ?? []
    const url = uris.length > 0 ? (uris[0]!.uri ?? '') : ''
    const folderId = item.folderId
    out.push({
      title: item.name ?? '',
      username: login.username ?? '',
      password: login.password ?? '',
      url,
      notes: item.notes ?? '',
      ...(login.totp !== undefined && login.totp.length > 0 ? { otp: login.totp } : {}),
      ...(folderId !== undefined && folderNames.get(folderId) !== undefined ? { tags: [folderNames.get(folderId)!] } : {}),
      ...(item.favorite === true ? { favorite: true } : {}),
    })
  }
  return out
}

/** ── 1Password 1PIF (legacy text export) ───────────────────────────────── */

/**
 * Read a 1Password 1PIF export (1Password 4–7 "1PIF" text format): a stream
 * of JSON records separated by `***Top of File***`-style markers. Login items
 * carry `secureContents.fields[]` with designations (username/password),
 * `title`, `location` (URL), `notesPlain`, `tags` and optional otpauth URIs.
 * Reference: pass-import OnePassword4PIF (onepassword.py).
 */
export function readOnePasswordPif(input: string): ImportedCredential[] {
  // Strip the `***…***` record markers; remaining lines are concatenated JSON.
  const cleaned = input
    .replace(/^\*\*\*.*\*\*\*\s+/gm, '')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l.length > 0)
    .join(',')
    .replace(/,\s*$/, '')
  let records: Array<Record<string, unknown>>
  try {
    records = JSON.parse(`[${cleaned}]`) as Array<Record<string, unknown>>
  } catch {
    throw new Error('1pif: not a valid 1PIF export (expected JSON records)')
  }
  const out: ImportedCredential[] = []
  for (const item of records) {
    const typeName = String(item.typeName ?? '')
    if (typeName === 'system.folder.Regular') continue // folder record
    if (item.trashed === true) continue
    if (!typeName.includes('Login') && !typeName.includes('WebForm') && !typeName.includes('Password')) continue
    const secure = (item.secureContents ?? {}) as Record<string, unknown>
    const fields = (secure.fields ?? []) as Array<{ name?: string; designation?: string; value?: string }>
    let username = ''
    let password = ''
    let otp = ''
    const named = new Map<string, string>()
    for (const f of fields) {
      const value = f.value ?? ''
      const designation = (f.designation ?? '').toLowerCase()
      const name = f.name ?? ''
      if (designation === 'username' || name.toLowerCase() === 'username') username = username || value
      else if (designation === 'password' || name.toLowerCase() === 'password') password = value
      else if (name.toLowerCase() === 'totp' || name.toLowerCase() === 'one-time password' || value.startsWith('otpauth://')) otp = value
      else if (name !== '') named.set(name.toLowerCase(), value)
    }
    // Sections may hold otpauth:// fields.
    if (otp === '') {
      for (const section of (secure.sections ?? []) as Array<{ fields?: Array<{ v?: string }> }>) {
        for (const f of section.fields ?? []) {
          if ((f.v ?? '').startsWith('otpauth://')) otp = f.v!
        }
      }
    }
    const tags = Array.isArray(item.tags) ? (item.tags as string[]) : []
    const title = String(item.title ?? named.get('title') ?? '')
    const url = String(item.location ?? '')
    const notes = String(secure.notesPlain ?? item.notesPlain ?? '')
    if (title === '' && username === '' && password === '') continue
    out.push({
      title,
      username,
      password,
      url,
      notes,
      ...(otp.length > 0 ? { otp } : {}),
      ...(tags.length > 0 ? { tags } : {}),
    })
  }
  return out
}

/** ── KeePass 2.x XML export (plaintext) ─────────────────────────────────── */

/**
 * Read a KeePass 2.x XML export (File > Export > XML) — the same document
 * structure as a decrypted KDBX. Protected values are base64'd against a
 * plaintext-protected stream only when the export protected them; since the
 * KeePass XML export writes values in the clear (Protected="True" values are
 * replaced by "********" unless "Export passwords" is checked), we surface
 * them as-is. Reference: KeePass XML schema (keepassxc-specs).
 */
export function readKeePassXml(input: string): ImportedCredential[] {
  // Reuse the KDBX XML parser for the entry shape.
  const { entries } = kdbxExtractEntries(input)
  return entries.map(fields => {
    const out: Record<string, string> = {}
    for (const [name, value] of fields) out[name] = value
    return {
      title: out.Title ?? '',
      username: out.UserName ?? '',
      password: out.Password ?? '',
      url: out.URL ?? '',
      notes: out.Notes ?? '',
    }
  })
}

/** ── Generic password CSV (Dashlane / NordPass / Keeper) ────────────────── */

/** Header synonyms → canonical field. Order matters: first match wins. */
const CSV_SYNONYMS: Array<[string, string[]]> = [
  ['title', ['title', 'name', 'item name', 'entry']],
  ['username', ['username', 'login', 'user', 'email', 'login name', 'user name']],
  ['password', ['password', 'pass', 'secret']],
  ['url', ['url', 'website', 'website address', 'web site', 'link', 'login uri', 'uri']],
  ['notes', ['notes', 'note', 'comments', 'comment', 'description', 'remark', 'extra']],
  ['otp', ['otp', 'totp', 'otp secret', '2fa secret', '2fa', 'secret', 'auth']],
  ['tags', ['tags', 'tag', 'labels', 'group', 'grouping', 'category', 'folder']],
  ['favorite', ['fav', 'favorite', 'favourite']],
]

/** Map a CSV header row to canonical fields; unknown columns are skipped. */
function mapCsvHeaders(headers: string[]): Map<number, string> {
  const map = new Map<number, string>()
  headers.forEach((raw, index) => {
    const header = raw.trim().toLowerCase().replace(/^\uFEFF/, '')
    for (const [canonical, synonyms] of CSV_SYNONYMS) {
      if (synonyms.some(s => header === s)) {
        map.set(index, canonical)
        return
      }
    }
  })
  return map
}

/**
 * Read a generic password CSV. The header row is matched against known column
 * names (Dashlane, NordPass, Keeper, Bitwarden and similar exports), so the
 * same importer handles all of them. Header-less files are treated as
 * title,username,password,url,notes in order when that yields sensible rows.
 */
export function readPasswordCsv(input: string): ImportedCredential[] {
  const rows = parseCsvRows(input)
  if (rows.length === 0) return []
  const mapped = mapCsvHeaders(rows[0]!)
  const hasHeader = mapped.size >= 2
  const dataRows = hasHeader ? rows.slice(1) : rows
  const out: ImportedCredential[] = []
  const pick = (row: string[], field: string): string => {
    for (const [index, canonical] of mapped) {
      if (canonical === field) return (row[index] ?? '').trim()
    }
    return ''
  }
  for (let i = 0; i < dataRows.length; i++) {
    const row = dataRows[i]!
    if (hasHeader) {
      const title = pick(row, 'title') || pick(row, 'username') || `entry ${i + 1}`
      const username = pick(row, 'username')
      const password = pick(row, 'password')
      const url = pick(row, 'url')
      const notes = pick(row, 'notes')
      const otp = pick(row, 'otp')
      const tagsRaw = pick(row, 'tags')
      const favRaw = pick(row, 'favorite')
      if (username === '' && password === '' && url === '' && notes === '') continue // blank row
      out.push({
        title,
        username,
        password,
        url,
        notes,
        ...(otp.length > 0 ? { otp } : {}),
        ...(tagsRaw.length > 0 ? { tags: tagsRaw.split(/[;,]/).map(t => t.trim()).filter(Boolean) } : {}),
        ...(favRaw.length > 0 ? { favorite: favRaw.toLowerCase() === '1' || favRaw.toLowerCase() === 'true' || favRaw.toLowerCase() === 't' || favRaw.toLowerCase() === 'yes' } : {}),
      })
    } else {
      // Legacy header-less rows (pass-import style): title,url,login,password,notes
      const [title, url, login, password, notes] = row
      out.push({
        title: (title ?? '').trim(),
        username: (login ?? '').trim(),
        password: (password ?? '').trim(),
        url: (url ?? '').trim(),
        notes: (notes ?? '').trim(),
      })
    }
  }
  return out
}

/** RFC-4180-ish CSV row parser (handles quotes, embedded commas/newlines). */
function parseCsvRows(input: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let field = ''
  let inQuotes = false
  let i = 0
  const pushField = (): void => { row.push(field); field = '' }
  const pushRow = (): void => { pushField(); rows.push(row); row = [] }
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
    } else if (ch === ',') {
      pushField()
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && input[i + 1] === '\n') i++
      pushRow()
      if (i + 1 >= input.length) break
    } else {
      field += ch
    }
    i++
  }
  if (field.length > 0 || row.length > 0) pushRow()
  // Drop trailing empty rows.
  while (rows.length > 0 && rows[rows.length - 1]!.every(c => c === '')) rows.pop()
  return rows
}
