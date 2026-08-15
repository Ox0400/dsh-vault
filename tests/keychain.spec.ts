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
keychain: "/x"
class: "inet"
attributes:
    "acct"<blob>="zhangzhipeng1"
    "srvr"<blob>="reg.ainirobot.com"
    "ptcl"<uint32>="htps"
keychain: "/x"
class: "inet"
attributes:
    "acct"<blob>="aws"
    "srvr"<blob>="signin.aws.amazon.com"
    "ptcl"<uint32>="htps"
    "port"<uint32>=0x00001F90
`

test('keychain: parseDump extracts genp service/account pairs', () => {
  const pairs = parseDump(SAMPLE).filter(e => e.class === 'genp')
  assert.equal(pairs.length, 3)
  assert.deepEqual(pairs[0], { class: 'genp', service: 'example.com', account: 'alice' })
})

test('keychain: parseDump extracts inet entries with protocol and port', () => {
  const inet = parseDump(SAMPLE).filter(e => e.class === 'inet')
  assert.equal(inet.length, 2)
  assert.deepEqual(inet[0], {
    class: 'inet', service: 'reg.ainirobot.com', account: 'zhangzhipeng1', protocol: 'htps',
  })
  assert.deepEqual(inet[1], {
    class: 'inet', service: 'signin.aws.amazon.com', account: 'aws', protocol: 'htps', port: '8080',
  })
})

test('keychain: parseDump skips unknown classes', () => {
  const out = parseDump('keychain: "/x"\nclass: "cert"\nattributes:\n    "acct"<blob>="a"\n')
  assert.equal(out.length, 0)
})

test('keychain: isUserCredential filters system entries', () => {
  assert.equal(isUserCredential('example.com', 'alice'), true)
  assert.equal(isUserCredential('reg.ainirobot.com', 'zhangzhipeng1'), true)
  assert.equal(isUserCredential('iCloud', 'com.apple.something'), false)
  assert.equal(isUserCredential('com.apple.foo', 'bar'), false)
  assert.equal(isUserCredential('login', 'alice'), false)
  assert.equal(isUserCredential('', 'alice'), false)
  assert.equal(isUserCredential('x', ''), false)
})
