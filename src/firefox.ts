/**
 * Firefox password vault importer for dsh-vault.
 *
 * Implements the NSS decryption scheme per the open-source `firepwd` /
 * `firepwd-ng` tool ([lclevy/firepwd](https://github.com/lclevy/firepwd)):
 *
 * - key4.db `metadata` row "password" holds the global salt (item1) and the
 *   ASN.1-PBE-encrypted password-check blob (item2).
 * - key4.db `nssPrivate` row whose CKA_ID is the NSS marker holds the
 *   ASN.1-PBE-encrypted master key (a11).
 * - logins.json holds per-site encryptedUsername / encryptedPassword blobs
 *   (base64 → ASN.1 PBE), decrypted with the master key.
 *
 * Both the legacy `pbeWithSha1AndTripleDES-CBC` and modern PBES2
 * (AES-256-CBC) variants are supported. An empty master password is used when
 * Firefox has no primary password set.
 *
 * @module dsh-vault/firefox
 */

import { createDecipheriv, createHash, createHmac, pbkdf2Sync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { readTableRows } from './sqlite.ts'
import { parseDer, findChild, readInteger, TAG_OCTET_STRING, TAG_SEQUENCE } from './der.ts'

/** NSS master-key CKA_ID marker (f8 00 … 01). */
const CKA_ID = Buffer.from([0xf8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])

export interface FirefoxCredential {
  origin: string
  username: string
  password: string
}

/** Decrypt a PBE blob (3DES legacy or PBES2/AES) with the given password. */
export function decryptPbe(der: Buffer, masterPassword: Buffer, globalSalt: Buffer): Buffer {
  const { node } = parseDer(der)
  const algo = node.children[0]
  const encrypted = node.children[1]
  if (!algo || encrypted?.tag !== TAG_OCTET_STRING) throw new Error('bad PBE structure')
  const oid = algo.children[0]
  const oidHex = oid?.value.toString('hex') ?? ''
  const ciphertext = encrypted.value

  if (oidHex === '2a864886f70d010c050103') {
    // pbeWithSha1AndTripleDES-CBC
    const params = algo.children[1]?.children ?? []
    const entrySalt = params[0]?.value ?? Buffer.alloc(0)
    return decryptMoz3Des(globalSalt, masterPassword, entrySalt, ciphertext)
  }
  if (oidHex === '2a864886f70d01050d') {
    // PBES2 (pkcs5 pbes2) → PBKDF2 + AES-CBC
    const pbes2 = algo.children[1]
    const kdf = pbes2?.children[0]
    const enc = pbes2?.children[1]
    const pbkdf2Params = kdf?.children[1]?.children ?? []
    const entrySalt = pbkdf2Params[0]?.value ?? Buffer.alloc(0)
    const iterations = pbkdf2Params[1] ? readInteger(pbkdf2Params[1]) : 1
    const keyLength = pbkdf2Params[2] ? readInteger(pbkdf2Params[2]) : 32
    const aesParams = enc?.children ?? []
    // NSS hard-codes a 2-byte IV prefix (0x04 0x0e).
    const ivSuffix = aesParams[1]?.value ?? Buffer.alloc(14)
    const iv = Buffer.concat([Buffer.from([0x04, 0x0e]), ivSuffix])
    const kIntermediate = createHash('sha1').update(Buffer.concat([globalSalt, masterPassword])).digest()
    const key = pbkdf2Sync(kIntermediate, entrySalt, iterations, keyLength, 'sha256')
    const decipher = createDecipheriv('aes-256-cbc', key, iv)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  }
  throw new Error(`unsupported PBE algorithm ${oidHex}`)
}

/** Legacy NSS 3DES key schedule (drh-consultancy scheme). */
function decryptMoz3Des(globalSalt: Buffer, masterPassword: Buffer, entrySalt: Buffer, data: Buffer): Buffer {
  const sha1 = (input: Buffer): Buffer => createHash('sha1').update(input).digest()
  const hmac = (key: Buffer, msg: Buffer): Buffer => createHmac('sha1', key).update(msg).digest()
  const hp = sha1(Buffer.concat([globalSalt, masterPassword]))
  const pes = Buffer.concat([entrySalt, Buffer.alloc(Math.max(0, 20 - entrySalt.length))])
  const chp = sha1(Buffer.concat([hp, entrySalt]))
  const k1 = hmac(chp, Buffer.concat([pes, entrySalt]))
  const tk = hmac(chp, pes)
  const k2 = hmac(chp, Buffer.concat([tk, entrySalt]))
  const k = Buffer.concat([k1, k2])
  const key = k.subarray(0, 24)
  const iv = k.subarray(k.length - 8)
  const decipher = createDecipheriv('des-ede3-cbc', key, iv)
  return Buffer.concat([decipher.update(data), decipher.final()])
}

/** Decrypt one login blob with the master key (3DES or AES-256-CBC). */
function decryptLogin(der: Buffer, masterKey: Buffer): Buffer {
  const { node } = parseDer(der)
  const algo = node.children[1]
  const oidHex = algo?.children[0]?.value.toString('hex') ?? ''
  const iv = algo?.children[1]?.value ?? Buffer.alloc(0)
  const ciphertext = node.children[2]?.value ?? Buffer.alloc(0)
  if (oidHex === '2a864886f70d0307') {
    const d = createDecipheriv('des-ede3-cbc', masterKey.subarray(0, 24), iv)
    return Buffer.concat([d.update(ciphertext), d.final()])
  }
  if (oidHex === '60864801650304012a') {
    const d = createDecipheriv('aes-256-cbc', masterKey.subarray(0, 32), iv)
    return Buffer.concat([d.update(ciphertext), d.final()])
  }
  throw new Error(`unsupported login algorithm ${oidHex}`)
}

/** Read Firefox credentials from a profile directory. */
export function readFirefoxLogins(profileDir: string, masterPassword = ''): FirefoxCredential[] {
  const keyDbPath = join(profileDir, 'key4.db')
  const loginsPath = join(profileDir, 'logins.json')
  const mp = Buffer.from(masterPassword, 'utf8')

  // 1) global salt + password-check from metadata.
  const meta = readTableRows(keyDbPath, 'metadata', ['id', 'item1', 'item2'])
  const pwRow = meta.find(r => r.id === 'password')
  if (!pwRow) throw new Error('Firefox key4.db has no password-check row (key4.db missing or empty?)')
  const globalSalt = pwRow.item1 instanceof Buffer ? pwRow.item1 : Buffer.from(String(pwRow.item1), 'binary')
  const checkDer = pwRow.item2 instanceof Buffer ? pwRow.item2 : Buffer.alloc(0)

  // 2) verify master password (throws on wrong password).
  try {
    const clear = decryptPbe(checkDer, mp, globalSalt)
    if (!clear.subarray(0, 14).equals(Buffer.from('password-check', 'utf8'))) {
      throw new Error('master password is incorrect')
    }
  } catch (error) {
    if ((error as Error).message.includes('master password')) throw error
    throw new Error('Firefox key4.db password-check decryption failed')
  }

  // 3) master key from nssPrivate.
  const priv = readTableRows(keyDbPath, 'nssPrivate', ['a11', 'a102'])
  const keyRow = priv.find(r => r.a102 instanceof Buffer && (r.a102 as Buffer).equals(CKA_ID))
  if (!keyRow) throw new Error('Firefox master key not found in nssPrivate')
  const keyDer = keyRow.a11 instanceof Buffer ? keyRow.a11 : Buffer.alloc(0)
  const masterKey = decryptPbe(keyDer, mp, globalSalt)

  // 4) logins.json entries.
  const doc = JSON.parse(readFileSync(loginsPath, 'utf8')) as {
    logins?: Array<{ hostname?: string; encryptedUsername?: string; encryptedPassword?: string }>
  }
  const out: FirefoxCredential[] = []
  for (const entry of doc.logins ?? []) {
    if (!entry.hostname || !entry.encryptedUsername || !entry.encryptedPassword) continue
    try {
      const username = decryptLogin(Buffer.from(entry.encryptedUsername, 'base64'), masterKey).toString('utf8')
      const password = decryptLogin(Buffer.from(entry.encryptedPassword, 'base64'), masterKey).toString('utf8')
      out.push({ origin: entry.hostname, username, password })
    } catch { /* unreadable entry — skip */ }
  }
  return out
}
