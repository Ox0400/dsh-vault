/**
 * Chrome password vault importer for dsh-vault.
 *
 * Reads Chrome's `Login Data` SQLite database and decrypts stored passwords
 * (v10/v11 AES-GCM format). The AES key is derived via PBKDF2 from the
 * "Chrome Safe Storage" password held in the macOS keychain, fetched with the
 * `security` CLI. The decrypted key lives only in memory for the duration of
 * an import.
 *
 * The database is copied (with any -wal/-journal siblings) to a temp dir and
 * read via the macOS system `sqlite3` CLI, which correctly handles WAL
 * recovery; a minimal pure-JS reader (`src/sqlite.ts`) is the fallback when
 * `sqlite3` is unavailable.
 *
 * @module dsh-vault/chrome
 */

import { execFileSync } from 'node:child_process'
import { createDecipheriv, pbkdf2Sync } from 'node:crypto'
import { copyFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { readTableRows } from './sqlite.ts'

export interface ChromeCredential {
  origin: string
  username: string
  password: string
}

/** Known Chrome Safe Storage service names. */
const SAFE_STORAGE_SERVICES = ['Chrome Safe Storage', 'Chromium Safe Storage', 'Brave Safe Storage']

/** Fetch the safe-storage password from the macOS keychain. */
function safeStoragePassword(service: string): string {
  // Reference implementations query with the account name (-a Chrome).
  try {
    return execFileSync('security', ['find-generic-password', '-a', 'Chrome', '-s', service, '-w'], { encoding: 'utf8' })
      .replace(/\s+$/, '')
  } catch {
    return execFileSync('security', ['find-generic-password', '-s', service, '-w'], { encoding: 'utf8' })
      .replace(/\s+$/, '')
  }
}

/** Derive the 16-byte AES key from the safe-storage base64 string bytes. */
function safeStorageKey(): Buffer {
  for (const service of SAFE_STORAGE_SERVICES) {
    try {
      const pw = safeStoragePassword(service)
      return pbkdf2Sync(pw, 'saltysalt', 1003, 16, 'sha1')
    } catch { /* try next service */ }
  }
  throw new Error('Chrome Safe Storage key unavailable — is Chrome installed and were the passwords saved on this macOS keychain?')
}

/**
 * Decrypt one Chrome v10 password blob (macOS).
 *
 * Per the open-source Chrome decryptors (e.g. osx-chrome-infostealer), macOS
 * Chrome v10 blobs are AES-128-CBC with a fixed IV of sixteen 0x20 bytes; the
 * AES key is PBKDF2-HMAC-SHA1(safe-storage-base64-string, "saltysalt", 1003,
 * 16). The ciphertext is the blob with the 3-byte "v10" prefix stripped.
 * @param blob - the raw `password_value` bytes.
 * @param key - the 16-byte AES key derived from the safe-storage password.
 */
export function decryptChromeV10(blob: Buffer, key: Buffer): string {
  if (blob.length < 4) return ''
  const prefix = blob.subarray(0, 3).toString('latin1')
  if (prefix !== 'v10' && prefix !== 'v11') return ''
  const iv = Buffer.alloc(16, 0x20)
  const ciphertext = blob.subarray(3)
  try {
    const decipher = createDecipheriv('aes-128-cbc', key, iv)
    return decipher.update(ciphertext, undefined, 'utf8') + decipher.final('utf8')
  } catch {
    return ''
  }
}

/**
 * Read Chrome logins from a `Login Data` file and decrypt their passwords.
 * @param dbPath - absolute path to the Login Data file.
 */
export function readChromeLogins(dbPath: string): ChromeCredential[] {
  const key = safeStorageKey()
  const creds: ChromeCredential[] = []
  try {
    const rows = queryLogins(dbPath)
    for (const row of rows) {
      const password = decryptChromeV10(row.passwordBlob, key)
      if (password.length === 0) continue
      creds.push({ origin: row.origin, username: row.username, password })
    }
  } finally {
    key.fill(0)
  }
  return creds
}

interface RawLogin {
  origin: string
  username: string
  passwordBlob: Buffer
}

/** Query the logins table via sqlite3 CLI (preferred) or the pure-JS reader. */
function queryLogins(dbPath: string): RawLogin[] {
  // Copy with WAL/journal siblings so a running Chrome still yields data.
  const dir = mkdtempSync(join(tmpdir(), 'dsh-vault-chrome-'))
  const copy = join(dir, basename(dbPath))
  try {
    copyFileSync(dbPath, copy)
    for (const suffix of ['-wal', '-journal', '-shm']) {
      const extra = dbPath + suffix
      if (existsSync(extra)) copyFileSync(extra, copy + suffix)
    }
    try {
      // -separator passes the real 0x1F byte; sqlite3 otherwise renders control
      // characters in caret notation which would corrupt the split.
      const sep = String.fromCharCode(31)
      const out = execFileSync(
        'sqlite3',
        ['-separator', sep, copy, "SELECT origin_url, username_value, quote(password_value) FROM logins"],
        { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
      )
      return out.split('\n')
        .filter(line => line.trim().length > 0)
        .map(line => {
          const parts = line.split(sep)
          const origin = parts[0] ?? ''
          const username = parts[1] ?? ''
          const pw = parts[2] ?? 'NULL'
          let blob = Buffer.alloc(0)
          if (pw !== 'NULL' && pw.startsWith("X'")) {
            blob = Buffer.from(pw.slice(2, -1), 'hex')
          }
          return { origin, username, passwordBlob: blob }
        })
        .filter(r => r.passwordBlob.length > 0)
    } catch {
      // sqlite3 CLI unavailable → pure-JS fallback (works when the DB was
      // cleanly closed, i.e. WAL was checkpointed).
      return readTableRows(copy, 'logins', ['origin_url', 'username_value', 'password_value']).map(row => ({
        origin: typeof row.origin_url === 'string' ? row.origin_url : '',
        username: typeof row.username_value === 'string' ? row.username_value : '',
        passwordBlob: row.password_value instanceof Buffer ? row.password_value : Buffer.alloc(0),
      })).filter(r => r.passwordBlob.length > 0)
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}
