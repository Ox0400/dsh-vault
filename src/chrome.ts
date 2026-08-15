/**
 * Chrome/Chromium/Brave/Edge password vault importer for dsh-vault.
 *
 * Reads the browser's `Login Data` SQLite database and decrypts stored
 * passwords. The AES key is OS-protected; the scheme differs per platform
 * (reference: Chromium os_crypt and yt-dlp cookies.py / osx-chrome-infostealer):
 *
 * - macOS:   v10/v11 = AES-128-CBC, key = PBKDF2-HMAC-SHA1(safe-storage
 *            base64 string, "saltysalt", 1003, 16), IV = 16×0x20. The safe
 *            storage password lives in the login keychain (`security` CLI).
 * - Linux:   v10 = AES-128-CBC with PBKDF2("peanuts", "saltysalt", 1, 16);
 *            v11 = same but the password comes from the keyring
 *            (`secret-tool lookup application chrome|chromium|brave`).
 *            IV = 16×0x20.
 * - Windows: v10 = AES-128-GCM, key = DPAPI-decrypted value stored in
 *            `Local State` → os_crypt.encrypted_key. DPAPI requires Windows;
 *            on non-Windows hosts this path reports an explicit error.
 *
 * The database is copied (with -wal/-journal siblings) to a temp dir and read
 * via the system `sqlite3` CLI, with a pure-JS reader fallback.
 *
 * @module dsh-vault/chrome
 */

import { execFileSync } from 'node:child_process'
import { createDecipheriv, pbkdf2Sync } from 'node:crypto'
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { readTableRows } from './sqlite.ts'

export interface ChromeCredential {
  origin: string
  username: string
  password: string
}

/** Known Chrome Safe Storage service names (macOS). */
const SAFE_STORAGE_SERVICES = ['Chrome Safe Storage', 'Chromium Safe Storage', 'Brave Safe Storage']

/** Platform name (lowercase). */
const PLATFORM = process.platform

/** IV used by the Chromium os_crypt AES-CBC scheme. */
const CBC_IV = Buffer.alloc(16, 0x20)

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

/** macOS: derive the 16-byte AES key from the safe-storage base64 bytes. */
function safeStorageKeyMac(): Buffer {
  for (const service of SAFE_STORAGE_SERVICES) {
    try {
      const pw = safeStoragePassword(service)
      return pbkdf2Sync(pw, 'saltysalt', 1003, 16, 'sha1')
    } catch { /* try next service */ }
  }
  throw new Error('Chrome Safe Storage key unavailable — is Chrome installed and were the passwords saved on this macOS keychain?')
}

/** Linux: PBKDF2("peanuts", "saltysalt", 1, 16) — the fixed Chromium key. */
function linuxPeanutsKey(): Buffer {
  return pbkdf2Sync(Buffer.from('peanuts'), 'saltysalt', 1, 16, 'sha1')
}

/**
 * Linux v11: fetch the keyring password for the browser (secret-tool, the
 * GNOME Keyring CLI Chromium uses) and derive PBKDF2(password, saltysalt,
 * 1, 16). Returns undefined when no keyring backend is available, so callers
 * fall back to the v10 "peanuts" key / empty password.
 */
function linuxKeyringKey(): Buffer | undefined {
  const apps = ['chrome', 'chromium', 'brave']
  for (const app of apps) {
    try {
      const pw = execFileSync('secret-tool', ['lookup', 'application', app], { encoding: 'utf8' }).replace(/\s+$/, '')
      if (pw.length > 0) return pbkdf2Sync(Buffer.from(pw), 'saltysalt', 1, 16, 'sha1')
    } catch { /* try next app */ }
  }
  return undefined
}

/** Windows: parse the DPAPI-wrapped key from `Local State`. */
function windowsLocalStateKey(localStatePath: string): Buffer {
  if (PLATFORM !== 'win32') {
    throw new Error('Windows Chrome decryption requires a Windows host (DPAPI is unavailable here)')
  }
  const raw = readFileSync(localStatePath, 'utf8')
  const parsed = JSON.parse(raw) as { os_crypt?: { encrypted_key?: string } }
  const b64 = parsed.os_crypt?.encrypted_key
  if (!b64) throw new Error('Windows Chrome: os_crypt.encrypted_key not found in Local State')
  const wrapped = Buffer.from(b64, 'base64')
  // "DPAPI" 5-byte prefix then the DPAPI-encrypted key.
  if (wrapped.subarray(0, 5).toString('latin1') !== 'DPAPI') {
    throw new Error('Windows Chrome: unexpected encrypted_key format (not DPAPI)')
  }
  return decryptDpapi(wrapped.subarray(5))
}

/** DPAPI unwrap via PowerShell (only meaningful on Windows). */
function decryptDpapi(blob: Buffer): Buffer {
  const b64 = blob.toString('base64')
  const script =
    `$b=[Convert]::FromBase64String('${b64}');` +
    `$u=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);` +
    `[Convert]::ToBase64String($u)`
  const out = execFileSync('powershell.exe', ['-NoProfile', '-Command', script], { encoding: 'utf8' }).trim()
  return Buffer.from(out, 'base64')
}

/**
 * Derive the AES key for the current platform.
 * @param localStatePath - Windows only: path to the browser's Local State.
 */
function browserKey(localStatePath?: string): Buffer {
  if (PLATFORM === 'darwin') return safeStorageKeyMac()
  if (PLATFORM === 'linux') return linuxKeyringKey() ?? linuxPeanutsKey()
  if (PLATFORM === 'win32') return windowsLocalStateKey(localStatePath ?? '')
  throw new Error(`Chrome import is not supported on ${PLATFORM}`)
}

/**
 * Decrypt one Chrome password blob.
 *
 * - macOS/Linux v10/v11: AES-128-CBC, IV = 16×0x20 (osx-chrome-infostealer,
 *   yt-dlp cookies.py). The ciphertext is the blob with the 3-byte "v10"/"v11"
 *   prefix stripped; both the derived key and the empty key are attempted
 *   (Chromium falls back to an empty password in some builds).
 * - Windows v10: AES-128-GCM with the 12-byte nonce = blob[3..15] and the
 *   tag = the final 16 bytes.
 * @param blob - the raw `password_value` bytes.
 * @param key - the platform AES key.
 */
export function decryptChromeBlob(blob: Buffer, key: Buffer): string {
  if (blob.length < 4) return ''
  const prefix = blob.subarray(0, 3).toString('latin1')
  const ciphertext = blob.subarray(3)
  if (PLATFORM === 'win32' && prefix === 'v10') {
    // AES-128-GCM: nonce 12 bytes, tag 16 bytes at the end.
    if (ciphertext.length < 12 + 16) return ''
    const nonce = ciphertext.subarray(0, 12)
    const tag = ciphertext.subarray(ciphertext.length - 16)
    const data = ciphertext.subarray(12, ciphertext.length - 16)
    try {
      const decipher = createDecipheriv('aes-128-gcm', key, nonce)
      decipher.setAuthTag(tag)
      return decipher.update(data, undefined, 'utf8') + decipher.final('utf8')
    } catch {
      return ''
    }
  }
  if (prefix !== 'v10' && prefix !== 'v11') return ''
  for (const candidate of [key, Buffer.alloc(16)]) {
    try {
      const decipher = createDecipheriv('aes-128-cbc', candidate, CBC_IV)
      const out = decipher.update(ciphertext, undefined, 'utf8') + decipher.final('utf8')
      if (out.length > 0 && out.charCodeAt(0) !== 0) return out
    } catch { /* try next candidate */ }
  }
  return ''
}

/**
 * Read Chrome logins from a `Login Data` file and decrypt their passwords.
 * @param dbPath - absolute path to the Login Data file.
 * @param localStatePath - Windows only: path to Local State (optional).
 */
export function readChromeLogins(dbPath: string, localStatePath?: string): ChromeCredential[] {
  const key = browserKey(localStatePath)
  const creds: ChromeCredential[] = []
  try {
    const rows = queryLogins(dbPath)
    for (const row of rows) {
      const password = decryptChromeBlob(row.passwordBlob, key)
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
  // Copy with WAL/journal siblings so a running browser still yields data.
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

/** Default path to the Chrome (or Chromium/Brave) `Login Data` file. */
export function defaultChromeLoginData(browser: 'chrome' | 'chromium' | 'brave' = 'chrome', profile = 'Default'): string {
  if (PLATFORM === 'darwin') {
    const dirs: Record<string, string> = {
      chrome: 'Google/Chrome',
      chromium: 'Chromium',
      brave: 'BraveSoftware/Brave-Browser',
    }
    return join(homedir(), 'Library/Application Support', dirs[browser]!, profile, 'Login Data')
  }
  if (PLATFORM === 'linux') {
    const dirs: Record<string, string> = {
      chrome: '.config/google-chrome',
      chromium: '.config/chromium',
      brave: '.config/BraveSoftware/Brave-Browser',
    }
    return join(homedir(), dirs[browser]!, profile, 'Login Data')
  }
  if (PLATFORM === 'win32') {
    const dirs: Record<string, string> = {
      chrome: 'Google/Chrome/User Data',
      chromium: 'Chromium/User Data',
      brave: 'BraveSoftware/Brave-Browser/User Data',
    }
    return join(process.env.LOCALAPPDATA ?? '', dirs[browser]!, profile, 'Login Data')
  }
  return join(homedir(), 'Chrome', profile, 'Login Data')
}

/** Windows only: default path to the browser's `Local State`. */
export function defaultChromeLocalState(browser: 'chrome' | 'chromium' | 'brave' = 'chrome'): string {
  if (PLATFORM !== 'win32') return ''
  const dirs: Record<string, string> = {
    chrome: 'Google/Chrome/User Data',
    chromium: 'Chromium/User Data',
    brave: 'BraveSoftware/Brave-Browser/User Data',
  }
  return join(process.env.LOCALAPPDATA ?? '', dirs[browser]!, 'Local State')
}
