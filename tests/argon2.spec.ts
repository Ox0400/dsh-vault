import { describe, expect, it } from 'vitest'
import { blake2b } from '../src/blake2b.ts'
import { argon2 } from '../src/argon2.ts'
import { readKdbx } from '../src/kdbx.ts'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const FIXTURE_ARGON2 = join(__dirname, 'fixtures', 'kdbx4-argon2.kdbx')

describe('blake2b (RFC 7693)', () => {
  it('matches RFC 7693 test vectors', () => {
    expect(blake2b(Buffer.from('abc'), 64).toString('hex')).toBe(
      'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923',
    )
    expect(blake2b(Buffer.alloc(0), 64).toString('hex')).toBe(
      '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
    )
    expect(blake2b(Buffer.alloc(0), 32).toString('hex')).toBe(
      '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8',
    )
  })

  it('matches keyed vectors (RFC 7693 §3.4 style, cross-checked with hashlib)', () => {
    const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i))
    expect(blake2b(Buffer.from('abc'), 32, key).toString('hex')).toBe(
      'd63a32d3e44738d7907f964316c241adaba0abfeabc32349677578a15a203f7f',
    )
    expect(blake2b(Buffer.alloc(0), 32, key).toString('hex')).toBe(
      '4e51e7a913fc80137da52880fecca175bf81e117d5c68126dc2774033517ea0d',
    )
  })
})

describe('argon2 (RFC 9106)', () => {
  const password = Buffer.alloc(32, 0x01)
  const salt = Buffer.alloc(16, 0x02)
  const secret = Buffer.alloc(8, 0x03)
  const ad = Buffer.alloc(12, 0x04)
  const base = { password, salt, parallelism: 4, iterations: 3, memoryKiB: 32, hashLength: 32, version: 0x13 }

  it('matches the RFC 9106 §5.1 Argon2d vector', () => {
    const out = argon2({ ...base, secret, associatedData: ad, type: 0 })
    expect(out.toString('hex')).toBe('512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb')
  })

  it('matches the RFC 9106 §5.3 Argon2id vector', () => {
    const out = argon2({ ...base, secret, associatedData: ad, type: 2 })
    expect(out.toString('hex')).toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659')
  })

  it('matches argon2-cffi for a small Argon2d case (no secret/ad)', () => {
    const out = argon2({ password: Buffer.from('password'), salt: Buffer.from('somesalt'), parallelism: 1, iterations: 1, memoryKiB: 8, hashLength: 32, type: 0, version: 0x13 })
    expect(out.toString('hex')).toBe('c519e603ac603ec1aeb5b71ec44a6179e3f3975b14c0c97e3914c79e6363e178')
  })

  it('rejects too-small memory', () => {
    expect(() => argon2({ password, salt, parallelism: 4, memoryKiB: 8, type: 0 })).toThrow(/too small/)
  })
})

describe('KDBX4 Argon2 import', () => {
  it('decrypts a kdbxweb Argon2 KDF database', () => {
    const entries = readKdbx(readFileSync(FIXTURE_ARGON2), 'ArgonPass123')
    expect(entries).toEqual([
      { title: 'argon-site', username: 'argon-user', password: 'argon-pass-1', url: 'https://argon.example', notes: '' },
    ])
  })

  it('rejects a wrong password for an Argon2 database', () => {
    expect(() => readKdbx(readFileSync(FIXTURE_ARGON2), 'Wrong')).toThrow(/HMAC mismatch/)
  })
})
