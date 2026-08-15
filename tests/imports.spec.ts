import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { readOnePasswordPux, readPasswordCsv, readEnpassJson, readBitwardenJson, readOnePasswordPif, readKeePassXml } from '../src/imports.ts'
import { readZip } from '../src/zip.ts'
import { deflateRawSync } from 'node:zlib'

const FIXTURE_1PUX = join(__dirname, 'fixtures', '1pux-sample.1pux')
const FIXTURE_DASHLANE = join(__dirname, 'fixtures', 'dashlane.csv')
const FIXTURE_NORDPASS = join(__dirname, 'fixtures', 'nordpass.csv')
const FIXTURE_KEEPER = join(__dirname, 'fixtures', 'keeper.csv')
const FIXTURE_ENPASS = join(__dirname, 'fixtures', 'enpass.json')
const FIXTURE_BITWARDEN = join(__dirname, 'fixtures', 'bitwarden.json')

describe('zip reader', () => {
  it('reads a deflate-compressed zip (the 1PUX fixture)', () => {
    const entries = readZip(readFileSync(FIXTURE_1PUX))
    const names = entries.map(e => e.name)
    expect(names).toContain('export.data')
    expect(names).toContain('export.attributes')
    const data = entries.find(e => e.name === 'export.data')!.data
    const parsed = JSON.parse(data.toString('utf8'))
    expect(parsed.accounts).toBeDefined()
  })

  it('reads stored entries and throws on non-zip data', () => {
    // Build a tiny stored-only zip in-memory.
    const name = Buffer.from('hello.txt')
    const content = Buffer.from('hello world')
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4) // version
    local.writeUInt16LE(0, 6) // flags
    local.writeUInt16LE(0, 8) // method stored
    local.writeUInt32LE(0, 10) // time
    local.writeUInt32LE(0, 14) // crc (unchecked)
    local.writeUInt32LE(content.length, 18)
    local.writeUInt32LE(content.length, 22)
    local.writeUInt16LE(name.length, 26)
    local.writeUInt16LE(0, 28)
    const localFull = Buffer.concat([local, name, content])

    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(0, 8)
    central.writeUInt16LE(0, 10)
    central.writeUInt32LE(0, 16)
    central.writeUInt32LE(content.length, 20) // compressed size
    central.writeUInt32LE(content.length, 24) // uncompressed size
    central.writeUInt16LE(name.length, 28)
    central.writeUInt16LE(0, 30)
    central.writeUInt16LE(0, 32)
    central.writeUInt32LE(0, 42)
    const centralFull = Buffer.concat([central, name])

    const eocd = Buffer.alloc(22)
    eocd.writeUInt32LE(0x06054b50, 0)
    eocd.writeUInt16LE(0, 4)
    eocd.writeUInt16LE(0, 6)
    eocd.writeUInt16LE(1, 8)
    eocd.writeUInt16LE(1, 10)
    eocd.writeUInt32LE(centralFull.length, 12)
    eocd.writeUInt32LE(localFull.length, 16)
    eocd.writeUInt16LE(0, 20)

    const zip = Buffer.concat([localFull, centralFull, eocd])
    const entries = readZip(zip)
    expect(entries).toHaveLength(1)
    expect(entries[0]!.name).toBe('hello.txt')
    expect(entries[0]!.data.toString('utf8')).toBe('hello world')

    expect(() => readZip(Buffer.from('not a zip at all!'))).toThrow(/too short|not a zip/)
    expect(() => readZip(Buffer.from('x'.repeat(64)))).toThrow(/not a zip/)
  })

  it('handles deflate method via a real zip build', () => {
    const name = Buffer.from('f.txt')
    const content = Buffer.from('compressed content '.repeat(20))
    const comp = deflateRawSync(content)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(8, 8) // deflate
    local.writeUInt32LE(comp.length, 18)
    local.writeUInt32LE(content.length, 22)
    local.writeUInt16LE(name.length, 26)
    const localFull = Buffer.concat([local, name, comp])
    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(8, 10) // method deflate
    central.writeUInt32LE(comp.length, 20)
    central.writeUInt32LE(content.length, 24)
    central.writeUInt16LE(name.length, 38)
    const centralFull = Buffer.concat([central, name])
    const eocd = Buffer.alloc(22)
    eocd.writeUInt32LE(0x06054b50, 0)
    eocd.writeUInt16LE(1, 8)
    eocd.writeUInt16LE(1, 10)
    eocd.writeUInt32LE(centralFull.length, 12)
    eocd.writeUInt32LE(localFull.length, 16)
    const zip = Buffer.concat([localFull, centralFull, eocd])
    const entries = readZip(zip)
    expect(entries[0]!.data.toString('utf8')).toBe(content.toString('utf8'))
  })
})

describe('1PUX import', () => {
  it('parses the sample export into credentials', () => {
    const creds = readOnePasswordPux(readFileSync(FIXTURE_1PUX))
    expect(creds.length).toBeGreaterThanOrEqual(2)
    const github = creds.find(c => c.title === 'GitHub')
    expect(github).toBeDefined()
    expect(github!.username).toBe('alice@example.com')
    expect(github!.password).toBe('s3cret-1p')
    expect(github!.url).toContain('github.com')
    expect(github!.tags).toContain('dev')
    const bank = creds.find(c => c.title === 'Bank of Test')
    expect(bank).toBeDefined()
    expect(bank!.username).toBe('bob')
    expect(bank!.password).toBe('bank-pass-1')
    expect(bank!.otp).toBeTruthy()
  })
})

describe('password-manager CSV import', () => {
  it('detects a Dashlane export by header', () => {
    const creds = readPasswordCsv(readFileSync(FIXTURE_DASHLANE, 'utf8'))
    expect(creds.length).toBeGreaterThanOrEqual(2)
    const tw = creds.find(c => c.title === 'twitter.com')
    expect(tw).toBeDefined()
    expect(tw!.username).toBe('ostqxi')
    expect(tw!.password).toBe('SoNEwvU,kJ%-cIKJ9[c#S;]jB')
    expect(tw!.url).toBe('https://twitter.com/')
  })

  it('detects a NordPass export by header', () => {
    const creds = readPasswordCsv(readFileSync(FIXTURE_NORDPASS, 'utf8'))
    expect(creds.length).toBe(2)
    const np = creds.find(c => c.title === 'Nord Site')
    expect(np).toBeDefined()
    expect(np!.username).toBe('nord-user')
    expect(np!.password).toBe('nord-pass-1')
    expect(np!.url).toBe('https://nord.example')
    expect(np!.notes).toContain('note here')
  })

  it('detects a Keeper export by header (folder/title/login/website address)', () => {
    const creds = readPasswordCsv(readFileSync(FIXTURE_KEEPER, 'utf8'))
    expect(creds.length).toBeGreaterThanOrEqual(2)
    const kb = creds.find(c => c.title === 'Keeper Bank')
    expect(kb).toBeDefined()
    expect(kb!.username).toBe('kb-user')
    expect(kb!.password).toBe('kb-pass-1')
    expect(kb!.url).toBe('https://keeper.example/bank')
    expect(kb!.tags).toContain('Banking')
  })

  it('handles header-less legacy rows as title,url,login,password,notes', () => {
    const csv = '"mastodon.social","https://mastodon.social/","ostqxi","D<INNeT?#?Bf4%`zA/4i!/\'$T",""'
    const creds = readPasswordCsv(csv)
    expect(creds).toHaveLength(1)
    expect(creds[0]!.title).toBe('mastodon.social')
    expect(creds[0]!.url).toBe('https://mastodon.social/')
    expect(creds[0]!.username).toBe('ostqxi')
    expect(creds[0]!.password).toBe('D<INNeT?#?Bf4%`zA/4i!/\'$T')
  })

  it('handles quoted fields with embedded commas and newlines', () => {
    const csv = 'title,username,password,url,notes\n"a, b","u","p","https://x.example","line1\nline2"'
    const creds = readPasswordCsv(csv)
    expect(creds).toHaveLength(1)
    expect(creds[0]!.title).toBe('a, b')
    expect(creds[0]!.notes).toBe('line1\nline2')
  })
})

describe('Enpass JSON import', () => {
  it('parses an Enpass export into credentials with tags, TOTP and favorite', () => {
    const creds = readEnpassJson(readFileSync(FIXTURE_ENPASS, 'utf8'))
    expect(creds.length).toBe(2)
    const gh = creds.find(c => c.title === 'GitHub')
    expect(gh).toBeDefined()
    expect(gh!.username).toBe('alice@example.com')
    expect(gh!.password).toBe('enpass-gh-pass')
    expect(gh!.url).toBe('https://github.com/')
    expect(gh!.tags).toContain('Work')
    expect(gh!.favorite).toBe(true)
    const bank = creds.find(c => c.title === 'Bank of Test')
    expect(bank).toBeDefined()
    expect(bank!.otp).toBe('JBSWY3DPEHPK3PXP')
    expect(bank!.tags).toContain('Personal')
    // Custom (non-typed) protected fields are appended to notes.
    expect(bank!.notes).toContain('Pin: 1234')
  })

  it('rejects non-Enpass JSON', () => {
    expect(() => readEnpassJson('{"foo": 1}')).toThrow(/not an Enpass/)
    expect(() => readEnpassJson('not json')).toThrow(/not valid JSON/)
  })
})

describe('Bitwarden JSON import', () => {
  it('parses an unencrypted export, skipping non-login items', () => {
    const creds = readBitwardenJson(readFileSync(FIXTURE_BITWARDEN, 'utf8'))
    expect(creds.length).toBe(1)
    const gh = creds[0]!
    expect(gh.title).toBe('BW GitHub')
    expect(gh.username).toBe('bw-user')
    expect(gh.password).toBe('bw-pass-1')
    expect(gh.url).toBe('https://github.com/login')
    expect(gh.notes).toBe('bw note')
    expect(gh.otp).toBe('JBSWY3DPEHPK3PXP')
    expect(gh.tags).toContain('Work')
    expect(gh.favorite).toBe(true)
  })

  it('rejects encrypted exports with a clear hint', () => {
    expect(() => readBitwardenJson('{"encrypted": true, "items": []}')).toThrow(/encrypted exports are not supported/)
  })
})

describe('LastPass CSV import', () => {
  it('detects a LastPass export by header (url/username/password/otp/extra/name/grouping/fav)', () => {
    const csv = readFileSync(join(__dirname, 'fixtures', 'lastpass.csv'), 'utf8')
    const creds = readPasswordCsv(csv)
    expect(creds.length).toBe(2)
    const gh = creds.find(c => c.title === 'GitHub LP')
    expect(gh).toBeDefined()
    expect(gh!.username).toBe('lp-alice')
    expect(gh!.password).toBe('lp-pass-1')
    expect(gh!.url).toBe('https://github.com')
    expect(gh!.otp).toBe('JBSWY3DPEHPK3PXP')
    expect(gh!.notes).toContain('primary account')
    expect(gh!.tags).toContain('Work')
    expect(gh!.favorite).toBe(true)
    const mail = creds.find(c => c.title === 'Mail LP')
    expect(mail!.favorite).toBe(false)
  })
})

describe('1Password 1PIF import', () => {
  it('parses a legacy 1PIF export (markers + JSON records)', () => {
    const pif = readFileSync(join(__dirname, 'fixtures', '1pif-sample.1pif'), 'utf8')
    const creds = readOnePasswordPif(pif)
    expect(creds.length).toBe(2)
    const gh = creds.find(c => c.title === 'GitHub Login')
    expect(gh).toBeDefined()
    expect(gh!.username).toBe('pif-alice')
    expect(gh!.password).toBe('pif-pass-1')
    expect(gh!.url).toBe('https://github.com')
    expect(gh!.otp).toBe('JBSWY3DPEHPK3PXP')
    expect(gh!.tags).toContain('dev')
    const bank = creds.find(c => c.title === 'Bank PIF')
    expect(bank!.otp).toContain('otpauth://')
    // folder records are skipped
    expect(creds.some(c => c.title === 'Work')).toBe(false)
  })

  it('rejects non-1PIF input', () => {
    expect(() => readOnePasswordPif('just some text')).toThrow(/not a valid 1PIF/)
  })
})

describe('KeePass 2.x XML export import', () => {
  it('parses a KeePass XML export (plaintext protected values)', () => {
    const xml = readFileSync(join(__dirname, 'fixtures', 'keepass-export.xml'), 'utf8')
    const creds = readKeePassXml(xml)
    expect(creds).toEqual([
      { title: 'XML Site', username: 'xml-user', password: 'xml-pass', url: 'https://xml.example', notes: 'xml note' },
      { title: 'Masked Site', username: 'masked-user', password: '********', url: 'https://masked.example', notes: '' },
    ])
  })
})

describe('Bitwarden CSV import', () => {
  it('detects a Bitwarden CSV export (login_uri/login_username/login_password/login_totp)', () => {
    const csv = readFileSync(join(__dirname, 'fixtures', 'bitwarden.csv'), 'utf8')
    const creds = readPasswordCsv(csv)
    expect(creds.length).toBe(2)
    const site = creds.find(c => c.title === 'BW Site')
    expect(site).toBeDefined()
    expect(site!.username).toBe('bw-user')
    expect(site!.password).toBe('bw-pass-1')
    expect(site!.url).toBe('https://bw.example')
    expect(site!.otp).toBe('JBSWY3DPEHPK3PXP')
    expect(site!.tags).toContain('Work')
    expect(site!.favorite).toBe(false)
    const mail = creds.find(c => c.title === 'BW Mail')
    expect(mail!.favorite).toBe(true)
  })
})

describe('1Password 8 CSV import', () => {
  it('detects a 1Password 8 CSV export (OTPAuth + Category/Tags merge)', () => {
    const csv = readFileSync(join(__dirname, 'fixtures', '1password8.csv'), 'utf8')
    const creds = readPasswordCsv(csv)
    expect(creds.length).toBe(2)
    const site = creds.find(c => c.title === 'OP8 Site')
    expect(site).toBeDefined()
    expect(site!.username).toBe('op8-user')
    expect(site!.password).toBe('op8-pass')
    expect(site!.otp).toBe('JBSWY3DPEHPK3PXP')
    expect(site!.tags).toContain('work')
    expect(site!.tags).toContain('dev')
    expect(site!.favorite).toBe(false)
    const bank = creds.find(c => c.title === 'OP8 Bank')
    expect(bank!.tags).toContain('banking')
    expect(bank!.favorite).toBe(true)
  })
})
