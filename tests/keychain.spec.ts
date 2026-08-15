import { test, assert } from 'vitest'
import { parseDump, isUserCredential } from '../src/keychain.ts'

const SAMPLE = `keychain: "/x"
class: "genp"
attributes:
    "acct"<blob>="alice"
    "svce"<blob>="example.com"
keychain: "/x"
class: "genp"
attributes:
    "acct"<blob>="com.apple.something"
    "svce"<blob>="iCloud"
keychain: "/x"
class: "genp"
attributes:
    "acct"<blob>="bob"
    "svce"<blob>="other.example"
`

test('keychain: parseDump extracts service/account pairs', () => {
  const pairs = parseDump(SAMPLE)
  assert.equal(pairs.length, 3)
  assert.deepEqual(pairs[0], { service: 'example.com', account: 'alice' })
})

test('keychain: isUserCredential filters system entries', () => {
  assert.equal(isUserCredential('example.com', 'alice'), true)
  assert.equal(isUserCredential('iCloud', 'com.apple.something'), false)
  assert.equal(isUserCredential('com.apple.foo', 'bar'), false)
  assert.equal(isUserCredential('', 'alice'), false)
  assert.equal(isUserCredential('x', ''), false)
})
