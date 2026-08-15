import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { readKdbx } from '../src/kdbx.ts'
import { chacha20Xor } from '../src/chacha20.ts'
import { salsa20Xor } from '../src/salsa20.ts'

// Fixtures were generated with kdbxweb 2.x (independent open-source KDBX4
// implementation) and committed under tests/fixtures/. The Salsa20/ChaCha20
// protected streams are exercised against real files.
const FIXTURE_AES = join(__dirname, 'fixtures', 'kdbx4-aes-salsa20.kdbx')
const FIXTURE_CHACHA = join(__dirname, 'fixtures', 'kdbx4-aes-chacha20.kdbx')

describe('kdbx4 import', () => {
  it('decrypts a kdbxweb AES-KDF + Salsa20 database', () => {
    const entries = readKdbx(readFileSync(FIXTURE_AES), 'TestPass123')
    expect(entries).toEqual([
      { title: 'prod-db', username: 'root', password: 'db-pass-42', url: '', notes: '' },
      { title: 'GitHub', username: 'alice', password: 's3cret!pw', url: 'https://github.com', notes: '' },
    ])
  })

  it('decrypts a kdbxweb AES-KDF + ChaCha20 database', () => {
    const entries = readKdbx(readFileSync(FIXTURE_CHACHA), 'TestPass123')
    expect(entries).toEqual([
      { title: 'prod-db', username: 'root', password: 'db-pass-42', url: '', notes: '' },
      { title: 'GitHub', username: 'alice', password: 's3cret!pw', url: 'https://github.com', notes: '' },
    ])
  })

  it('rejects non-KDBX data', () => {
    expect(() => readKdbx(Buffer.from('not a kdbx file at all'), 'x')).toThrow(/not a KeePass database/)
  })

  it('rejects KDBX 3.x files', () => {
    // sig1 + KDBX3 sig2 (b54bfb65) + version 0x00030001
    const hdr = Buffer.alloc(12)
    hdr.writeUInt32LE(0x9aa2d903, 0)
    hdr.writeUInt32LE(0xb54bfb65, 4)
    hdr.writeUInt32LE(0x00030001, 8)
    expect(() => readKdbx(hdr, 'x')).toThrow(/not a KeePass database|only KDBX 4/)
  })

  it('rejects wrong password with a header HMAC mismatch', () => {
    expect(() => readKdbx(readFileSync(FIXTURE_AES), 'WrongPass')).toThrow(/HMAC mismatch/)
  })
})

describe('salsa20', () => {
  it('matches the known KeePass keystream', () => {
    // The Salsa20 protected-stream key inside the fixture (extracted from its
    // inner header and committed alongside). Key = SHA256(streamKey), fixed
    // nonce E8 30 09 4B 97 20 5D 2A. XORing the first protected value
    // (qtUkvJF82w== → "prod-db") with keystream block 0 must match.
    const streamKey = Buffer.from(readFileSync(join(__dirname, 'fixtures', 'streamkey-salsa20.txt'), 'utf8').trim(), 'hex')
    const key = createHash('sha256').update(streamKey).digest()
    const nonce = Buffer.from('e830094b97205d2a', 'hex')
    const enc = Buffer.from('qtUkvJF82w==', 'base64')
    const plain = salsa20Xor(enc, key, nonce, 0)
    expect(plain.toString('utf8')).toBe('prod-db')
  })

  it('throws on bad key/nonce length', () => {
    const key = Buffer.alloc(32)
    expect(() => salsa20Xor(Buffer.alloc(8), key.subarray(0, 16), Buffer.alloc(8))).toThrow(/key must be 32/)
    expect(() => salsa20Xor(Buffer.alloc(8), key, Buffer.alloc(4))).toThrow(/nonce must be 8/)
  })
})

describe('chacha20', () => {
  it('matches RFC 8439 2.4.2 test vector (ChaCha20 cipher)', () => {
    const key = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex')
    const nonce = Buffer.from('000000000000004a00000000', 'hex')
    const input = Buffer.from('Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.')
    const enc = chacha20Xor(input, key, nonce, 1)
    expect(enc.toString('hex')).toBe(
      '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d',
    )
  })
})
