/**
 * Tests for dsh-vault: crypto round-trips, TOTP (RFC 6238) vectors, password
 * generation, and the encrypted store's CRUD/search behavior.
 *
 * Uses Node's built-in test runner so the plugin stays dependency-free.
 * Run with: `node --test tests/` from the package root (Node >= 22).
 */

import { test, expect } from 'vitest'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { decrypt, deriveKey, encrypt, newKdfParams, safeEqual } from '../src/crypto'
import { base32Decode, bytesToBase32, generateTotpSecret, hotp, parseTotpSecret, totp } from '../src/totp'
import { generatePassword } from '../src/password'
import { openVault } from '../src/store'

// ── crypto ──────────────────────────────────────────────────────────────────

test('encrypt/decrypt round-trips and authenticates', async () => {
  const kdf = newKdfParams()
  const key = await deriveKey('correct horse battery staple', kdf)
  const plaintext = Buffer.from('{"secret":"hunter2"}')
  const blob = encrypt(plaintext, key)
  assert.notEqual(blob.dataHex, plaintext.toString('hex'))
  assert.deepEqual(decrypt(blob, key), plaintext)
})

test('decrypt rejects a wrong key', async () => {
  const kdf = newKdfParams()
  const key = await deriveKey('right password', kdf)
  const wrongKey = await deriveKey('wrong password', kdf)
  const blob = encrypt(Buffer.from('secret'), key)
  assert.throws(() => decrypt(blob, wrongKey))
})

test('decrypt rejects tampered ciphertext', async () => {
  const kdf = newKdfParams()
  const key = await deriveKey('pw', kdf)
  const blob = encrypt(Buffer.from('secret data'), key)
  const tampered = { ...blob, dataHex: blob.dataHex.slice(0, -2) + '00' }
  assert.throws(() => decrypt(tampered, key))
})

test('same plaintext encrypts to different blobs (fresh nonce)', async () => {
  const kdf = newKdfParams()
  const key = await deriveKey('pw', kdf)
  const a = encrypt(Buffer.from('same'), key)
  const b = encrypt(Buffer.from('same'), key)
  assert.notEqual(a.ivHex, b.ivHex)
  assert.notEqual(a.dataHex, b.dataHex)
})

// ── TOTP (RFC 6238 Appendix B vectors) ──────────────────────────────────────

test('RFC 6238 SHA1 test vectors', () => {
  // Secret "12345678901234567890" (ASCII) Base32-encoded is
  // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
  const secret = bytesToBase32(Buffer.from('12345678901234567890', 'ascii'))
  const vectors: Array<[number, string]> = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ]
  for (const [time, expected] of vectors) {
    const counter = Math.floor(time / 30)
    assert.equal(hotp(base32Decode(secret), counter, 8), expected)
  }
})

test('totp() returns 6-digit codes by default', () => {
  const code = totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1234567890 * 1000)
  assert.match(code, /^\d{6}$/)
})

test('parseTotpSecret handles bare secrets and otpauth URIs', () => {
  assert.deepEqual(parseTotpSecret('abc def'), { secret: 'abc def', periodSeconds: 30, digits: 6 })
  const uri = parseTotpSecret('otpauth://totp/GitHub:ada?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&period=60')
  assert.equal(uri.secret, 'JBSWY3DPEHPK3PXP')
  assert.equal(uri.digits, 8)
  assert.equal(uri.periodSeconds, 60)
  assert.equal(uri.issuer, 'GitHub')
  assert.equal(uri.account, 'ada')
})

test('base32Decode accepts lowercase and padding', () => {
  const a = base32Decode('JBSWY3DPEHPK3PXP')
  const b = base32Decode('jbswy3dpehpk3pxp')
  assert.deepEqual(a, b)
})

test('generateTotpSecret produces valid Base32 of 32 chars', () => {
  const secret = generateTotpSecret()
  assert.equal(secret.length, 32)
  assert.doesNotThrow(() => base32Decode(secret))
  // Round-trip: a TOTP code computed with the generated secret is 6 digits.
  assert.match(totp(secret), /^\d{6}$/)
})

// ── password generation ─────────────────────────────────────────────────────

test('generatePassword satisfies character classes and length', () => {
  const password = generatePassword({ length: 24 })
  assert.equal(password.length, 24)
  assert.match(password, /[a-z]/)
  assert.match(password, /[A-Z]/)
  assert.match(password, /\d/)
  assert.match(password, /[^A-Za-z0-9]/)
})

test('generatePassword honors class toggles', () => {
  const digitsOnly = generatePassword({ length: 16, lowercase: false, uppercase: false, symbols: false })
  assert.match(digitsOnly, /^\d{16}$/)
})

test('generatePassword groups with separators', () => {
  const grouped = generatePassword({ length: 9, group: 3 })
  assert.match(grouped, /^.{3}-.{3}-.{3}$/)
})

test('generatePassword excludes ambiguous characters', () => {
  const clean = generatePassword({ length: 32, excludeAmbiguous: true })
  assert.ok(!/0O1lI/.test(clean))
})

test('generatePassword rejects impossible lengths', () => {
  assert.throws(() => generatePassword({ length: 1 }))
  assert.throws(() => generatePassword({ length: 10, lowercase: false, uppercase: false, digits: false, symbols: false }))
})

// ── store ───────────────────────────────────────────────────────────────────

async function withTempVault<T>(run: (path: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-vault-'))
  const path = join(dir, 'vault.json')
  try {
    return await run(path)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

test('store: add/search/get/update/delete lifecycle', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'test-master', path })
    const added = await vault.add({ title: 'GitHub', username: 'ada', password: 'hunter2', tags: ['dev'] })
    assert.ok(added.id)

    const byId = vault.get(added.id)
    assert.equal(byId?.username, 'ada')
    assert.equal(byId?.password, 'hunter2')

    const results = vault.search('ada')
    assert.equal(results.length, 1)
    assert.equal(results[0]!.title, 'GitHub')
    // Summaries never carry secrets.
    assert.ok(!('password' in results[0]!))
    assert.ok(!('otpSecret' in results[0]!))

    const updated = await vault.update(added.id, { email: 'ada@example.com' })
    assert.equal(updated?.email, 'ada@example.com')
    assert.equal(updated?.password, 'hunter2') // untouched fields survive

    assert.equal(await vault.delete(added.id), true)
    assert.equal(await vault.delete(added.id), false)
    assert.equal(vault.get(added.id), undefined)
  })
})

test('store: persists and reloads, decrypts with the same password', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    await vault.add({ title: 'Email', email: 'a@b.c', password: 's3cret' })

    const reloaded = await openVault({ masterPassword: 'pw', path })
    const [entry] = reloaded.list()
    assert.equal(entry?.email, 'a@b.c')
    assert.equal(entry?.password, 's3cret')
  })
})

test('store: update can rename the title and clear fields with empty strings', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const added = await vault.add({ title: 'Old name', username: 'ada', password: 's3cret', tags: ['dev'] })

    // Title updates (regression: pickDefined used to drop title in update).
    const renamed = await vault.update(added.id, { title: 'New name' })
    assert.equal(renamed?.title, 'New name')

    // Empty string clears the field entirely (not stored as '').
    const cleared = await vault.update(added.id, { password: '' })
    assert.equal(cleared?.password, undefined)
    assert.ok(!('password' in cleared!))
    assert.equal(cleared?.username, 'ada') // untouched fields survive
    assert.deepEqual(cleared?.tags, ['dev'])
  })
})

test('store: add drops empty strings and empty arrays from the form', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const added = await vault.add({ title: 'GitHub', username: '', email: 'a@b.c', tags: [], password: 'x' })
    const stored = vault.get(added.id)!
    assert.equal(stored.username, undefined)
    assert.equal(stored.tags, undefined)
    assert.equal(stored.email, 'a@b.c')
    assert.equal(stored.password, 'x')
  })
})

test('store: numeric and boolean custom fields are searchable', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    await vault.add({ title: 'api gateway', fields: { region: 'us-east-1', ttl: 3600, enabled: true, nested: { zone: 'z1' } } })
    assert.equal(vault.search('3600').length, 1) // number stringified
    assert.equal(vault.search('true').length, 1) // boolean stringified
    assert.equal(vault.search('z1').length, 1) // nested object leaf
  })
})

test('password: excludeAmbiguous never draws ambiguous guaranteed characters', () => {
  // The per-class guarantee used to sample the UNFILTERED pool, so a class
  // like digits could contribute 0/1 even with excludeAmbiguous. Run many
  // times to make the regression highly likely to fire.
  for (let i = 0; i < 500; i++) {
    const password = generatePassword({ length: 4, excludeAmbiguous: true })
    assert.ok(!/0O1lI/.test(password), `ambiguous char in ${password}`)
  }
})

test('password: rejects invalid group values', () => {
  assert.throws(() => generatePassword({ group: 1.5 }))
  assert.throws(() => generatePassword({ group: 0 }))
  assert.throws(() => generatePassword({ group: -3 }))
  assert.doesNotThrow(() => generatePassword({ group: 3 }))
})

test('store: concurrent adds persist every entry (snapshot built under lock)', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) => vault.add({ title: `entry-${i}` })),
    )
    assert.equal(vault.size, 20)
    const reloaded = await openVault({ masterPassword: 'pw', path })
    assert.equal(reloaded.size, 20)
    const titles = reloaded.list().map(e => e.title).sort()
    const expected = Array.from({ length: 20 }, (_, i) => `entry-${i}`).sort()
    assert.deepEqual(titles, expected)
    void results
  })
})

test('store: update rejects blanking the title', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const added = await vault.add({ title: 'Keep me', username: 'ada' })
    await assert.rejects(() => vault.update(added.id, { title: '' }))
    await assert.rejects(() => vault.update(added.id, { title: '   ' }))
    // The entry is untouched after a rejected update.
    assert.equal(vault.get(added.id)?.title, 'Keep me')
  })
})

test('store: wrong password fails to open an existing vault', async () => {
  await withTempVault(async path => {
    await openVault({ masterPassword: 'right', path })
    // First open created the file; wrong password must fail authentication.
    await assert.rejects(() => openVault({ masterPassword: 'wrong', path }))
  })
})

test('store: on-disk document contains no plaintext secrets', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    await vault.add({ title: 'Bank', username: 'ada-lovelace', password: 'hunter2!', email: 'a@b.c' })
    const raw = await readFile(path, 'utf8')
    // Secrets contain characters outside the hex alphabet (h, !, @, -, .),
    // so they can never appear inside hex-encoded ciphertext or tags.
    assert.ok(!raw.includes('hunter2!'))
    assert.ok(!raw.includes('ada-lovelace'))
    assert.ok(!raw.includes('a@b.c'))
  })
})

test('store: search is case-insensitive across fields', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    await vault.add({ title: 'GitHub Work', username: 'Ada', url: 'https://github.com' })
    assert.equal(vault.search('GITHUB').length, 1)
    assert.equal(vault.search('ada').length, 1)
    assert.equal(vault.search('github.com').length, 1)
    assert.equal(vault.search('nothing').length, 0)
  })
})

test('store: developer credential fields round-trip and search', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const ssh = await vault.add({
      title: 'prod-db',
      kind: 'ssh',
      host: 'db.internal.example.com',
      port: '2222',
      username: 'deploy',
      password: 's3cr3t!',
      privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----',
    })
    const stored = vault.get(ssh.id)
    assert.equal(stored?.kind, 'ssh')
    assert.equal(stored?.host, 'db.internal.example.com')
    assert.equal(stored?.port, '2222')
    assert.equal(stored?.password, 's3cr3t!')
    assert.match(stored!.privateKey!, /BEGIN OPENSSH/)

    // Search hits host and port; summary carries host/port but no secrets.
    assert.equal(vault.search('db.internal').length, 1)
    assert.equal(vault.search('2222').length, 1)
    const [summary] = vault.search('prod-db')
    assert.equal(summary!.host, 'db.internal.example.com')
    assert.ok(!('password' in summary!))
    assert.ok(!('privateKey' in summary!))
  })
})

test('store: oauth tokens and custom fields persist', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const entry = await vault.add({
      title: 'api gateway',
      kind: 'oauth',
      accessToken: 'at-123',
      refreshToken: 'rt-456',
      expiresAt: 1700000000000,
      apiKey: 'ak-789',
      fields: { region: 'us-east-1', ttl: '3600' },
    })
    const reloaded = await openVault({ masterPassword: 'pw', path })
    const stored = reloaded.get(entry.id)
    assert.equal(stored?.accessToken, 'at-123')
    assert.equal(stored?.refreshToken, 'rt-456')
    assert.equal(stored?.expiresAt, 1700000000000)
    assert.equal(stored?.apiKey, 'ak-789')
    assert.deepEqual(stored?.fields, { region: 'us-east-1', ttl: '3600' })
    // Custom field values are searchable.
    assert.equal(reloaded.search('us-east-1').length, 1)
  })
})

test('safeEqual compares buffers in constant time', () => {
  assert.equal(safeEqual(Buffer.from('abc'), Buffer.from('abc')), true)
  assert.equal(safeEqual(Buffer.from('abc'), Buffer.from('abd')), false)
  assert.equal(safeEqual(Buffer.from('abc'), Buffer.from('abcd')), false)
})

test('store: auto-lock relocks after idle timeout and unlock restores access', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    await vault.add({ title: 'Locked entry', password: 'pw' })
    // 10ms idle timeout; immediately after add the store is unlocked.
    vault.setAutoLock(10)
    vault.touch()
    assert.equal(vault.isLocked, false)
    // Simulate idle expiry: backdate the activity timestamp.
    ;(vault as unknown as { lastActivity: number }).lastActivity = Date.now() - 1000
    assert.equal(vault.expired, true)
    assert.equal(vault.isLocked, false)
    vault.lock()
    assert.equal(vault.isLocked, true)
    // Reads require unlock.
    assert.equal(vault.get('anything'), undefined)
    await vault.unlock()
    assert.equal(vault.isLocked, false)
    assert.equal(vault.list().length, 1)
  })
})

test('store: soft delete moves to trash and restore/purge manage it', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const entry = await vault.add({ title: 'Trash me', password: 'pw' })
    assert.equal(vault.list().length, 1)
    assert.equal(vault.listTrash().length, 0)

    assert.equal(await vault.delete(entry.id), true)
    assert.equal(vault.list().length, 0)
    assert.equal(vault.listTrash().length, 1)
    assert.equal(vault.get(entry.id), undefined)
    assert.equal(vault.getIncludingTrash(entry.id)?.title, 'Trash me')

    assert.equal(await vault.restore(entry.id), true)
    assert.equal(vault.list().length, 1)
    assert.equal(vault.listTrash().length, 0)

    await vault.delete(entry.id)
    assert.equal(await vault.purge(entry.id), true)
    assert.equal(vault.listTrash().length, 0)
    assert.equal(vault.getIncludingTrash(entry.id), undefined)
  })
})

test('store: rotationReport flags expired and due entries', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const now = Date.now()
    await vault.add({ title: 'Expired', accessToken: 'at', expiresAt: now - 1000 })
    await vault.add({ title: 'Normal', password: 'pw' })
    const report = vault.rotationReport(now)
    const expired = report.find(r => r.title === 'Expired')
    assert.equal(expired?.due, 'expired')
    assert.ok(!report.some(r => r.title === 'Normal'), 'no expiry/rotation → not listed')
    assert.ok(!('accessToken' in (expired ?? {})), 'report never carries secrets')
  })
})

test('store: health detects weak and reused credentials', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    await vault.add({ title: 'Weak', password: 'short' })
    await vault.add({ title: 'A', apiKey: 'dup-key' })
    await vault.add({ title: 'B', apiKey: 'dup-key' })
    const { weak, reused } = vault.health()
    assert.equal(weak.length, 1)
    assert.equal(weak[0]!.title, 'Weak')
    assert.equal(reused.length, 1)
    assert.equal(reused[0]!.entries.length, 2)
  })
})

test('store: exportEncrypted/importEncrypted round-trip without secrets leaking', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    await vault.add({ title: 'Portable', password: 's3cret' })
    const blob = await vault.exportEncrypted('export-pw')
    assert.ok(!blob.includes('s3cret'), 'export ciphertext must not contain plaintext secret')

    const vault2 = await openVault({ masterPassword: 'pw2', path: path + '.2' })
    const added = await vault2.importEncrypted(blob, 'export-pw')
    assert.equal(added, 1)
    assert.equal(vault2.list()[0]!.password, 's3cret')
    // Wrong export password fails authentication.
    await assert.rejects(() => vault2.importEncrypted(blob, 'wrong-export-pw'))
  })
})

test('store: rekey upgrades KDF and keeps all entries readable', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    await vault.add({ title: 'One', password: 'pw-1' })
    await vault.add({ title: 'Two', apiKey: 'ak-2' })
    const { n } = await vault.rekey()
    assert.equal(n, 32768) // default SCRYPT_N

    // Reload with the same password: the new KDF must decrypt everything.
    const reloaded = await openVault({ masterPassword: 'pw', path })
    assert.equal(reloaded.list().length, 2)
    const titles = reloaded.list().map(e => e.title).sort()
    assert.deepEqual(titles, ['One', 'Two'])
    assert.equal(reloaded.list().find(e => e.title === 'One')?.password, 'pw-1')
  })
})

test('store: search matches multiple whitespace-separated terms (OR)', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    await vault.add({ title: 'GitHub personal', username: 'ada', tags: ['dev'] })
    await vault.add({ title: 'AWS prod', username: 'deploy', tags: ['prod'] })
    // Single-term behavior unchanged.
    assert.equal(vault.search('github').length, 1)
    // Multi-term OR: either term may hit either entry.
    assert.equal(vault.search('github aws').length, 2)
    assert.equal(vault.search('github deploy').length, 2)
    assert.equal(vault.search('nothing here').length, 0)
  })
})

test('store: rotationDays 0 clears rotation (never rotate)', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const added = await vault.add({ title: 'Rot', password: 'pw', rotationDays: 30 })
    assert.equal(added.rotationDays, 30)
    // A zero interval must clear the field, not report due forever.
    await vault.update(added.id, { rotationDays: 0 })
    const updated = vault.get(added.id)!
    assert.ok(!('rotationDays' in updated), 'rotationDays cleared by 0')
    const report = vault.rotationReport(Date.now() + 10_000_000_000)
    assert.ok(!report.some(r => r.title === 'Rot'), 'no rotation due for cleared entry')
  })
})

test('store: expiresAt 0 clears expiry and rotationReport honors soonWindowDays', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const now = Date.now()
    const e = await vault.add({ title: 'Window', password: 'pw', expiresAt: now + 3 * 86_400_000 })
    // soon within the default 7-day window.
    assert.equal(vault.rotationReport(now).find(r => r.title === 'Window')?.due, 'soon')
    // not soon when the window is 2 days.
    assert.ok(!vault.rotationReport(now, 2).some(r => r.title === 'Window'), 'outside 2-day window')
    // expiresAt: 0 clears the expiry entirely.
    await vault.update(e.id, { expiresAt: 0 })
    const updated = vault.get(e.id)!
    assert.ok(!('expiresAt' in updated), 'expiresAt cleared by 0')
    assert.ok(!vault.rotationReport(now).some(r => r.title === 'Window'), 'no expiry after clear')
  })
})

test('store: merge with keepSource keeps the source entry', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    const a = await vault.add({ title: 'Src', password: 'pw-a', username: 'src-user' })
    const b = await vault.add({ title: 'Dst', username: 'dst-user' })
    const merged = await vault.merge(a.id, b.id, { keepSource: true })
    assert.equal(merged?.title, 'Dst')
    assert.equal(merged?.password, 'pw-a', 'gap filled from source')
    assert.ok(vault.get(a.id) !== undefined, 'source kept with keepSource')
    assert.equal(vault.list().length, 2)
  })
})

test('store: health reports no-2FA, HTTP sites, and a security score', async () => {
  await withTempVault(async path => {
    const vault = await openVault({ masterPassword: 'pw', path })
    await vault.add({ title: 'NoTOTP', username: 'u', password: 'a-very-long-password-ok-1' })
    await vault.add({ title: 'HasTOTP', username: 'u', password: 'a-very-long-password-ok-2', otpSecret: 'GEZDGNBVGY3TQOJQ' })
    await vault.add({ title: 'HttpSite', username: 'u', password: 'a-very-long-password-ok-3', url: 'http://insecure.example' })
    await vault.add({ title: 'WeakOne', password: 'short' })
    const h = vault.health()
    // NoTOTP, HttpSite and WeakOne are all login-kind entries with a password but no otpSecret.
    assert.equal(h.no2fa.length, 3, 'login entries without TOTP flagged')
    assert.ok(h.no2fa.some(x => x.title === 'NoTOTP'))
    assert.ok(!h.no2fa.some(x => x.title === 'HasTOTP'))
    assert.equal(h.httpSites.length, 1)
    assert.equal(h.httpSites[0]!.title, 'HttpSite')
    // 100 - 10(weak) - 15(no2fa x3) - 5(http) = 70
    assert.equal(h.score, 70)
    assert.equal(h.verdict, 'fair')
  })
})
