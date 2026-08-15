/**
 * Password-manager import formats for dsh-vault: 1Password 1PUX (ZIP + JSON)
 * and generic password CSV (Dashlane / NordPass / Keeper auto-detected by
 * header synonyms).
 *
 * Format references (open-source):
 * - 1PUX: https://support.1password.com/1pux-format/ — a ZIP with
 *   export.data (accounts → vaults → items → details.fields).
 * - CSV column synonyms: pass-import
 *   (https://github.com/roddhjav/pass-import) nordpass/keeper/dashlane
 *   managers and the Dashlane CSV export documented by the community
 *   converter scripts.
 *
 * @module dsh-vault/imports
 */

import { readZip, zipEntry } from './zip.ts'

export interface ImportedCredential {
  title: string
  username: string
  password: string
  url: string
  notes: string
  otp?: string
  tags?: string[]
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

/** ── Generic password CSV (Dashlane / NordPass / Keeper) ────────────────── */

/** Header synonyms → canonical field. Order matters: first match wins. */
const CSV_SYNONYMS: Array<[string, string[]]> = [
  ['title', ['title', 'name', 'item name', 'entry']],
  ['username', ['username', 'login', 'user', 'email', 'login name', 'user name']],
  ['password', ['password', 'pass', 'secret']],
  ['url', ['url', 'website', 'website address', 'web site', 'link', 'login uri', 'uri']],
  ['notes', ['notes', 'note', 'comments', 'comment', 'description', 'remark']],
  ['otp', ['otp', 'totp', 'otp secret', '2fa secret', '2fa', 'secret', 'auth']],
  ['tags', ['tags', 'tag', 'labels', 'group', 'category', 'folder']],
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
      if (username === '' && password === '' && url === '' && notes === '') continue // blank row
      out.push({
        title,
        username,
        password,
        url,
        notes,
        ...(otp.length > 0 ? { otp } : {}),
        ...(tagsRaw.length > 0 ? { tags: tagsRaw.split(/[;,]/).map(t => t.trim()).filter(Boolean) } : {}),
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
