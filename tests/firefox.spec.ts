import { test, assert } from 'vitest'
import { createCipheriv, createHash, createHmac, pbkdf2Sync } from 'node:crypto'
import { parseDer } from '../src/der.ts'
import { decryptPbe } from '../src/firefox.ts'

// Reimplement the NSS 3DES schedule (inverse of decryptMoz3Des) to build a blob.
function moz3DesEncrypt(globalSalt: Buffer, masterPassword: Buffer, entrySalt: Buffer, plaintext: Buffer): Buffer {
  const sha1 = (input: Buffer): Buffer => createHash('sha1').update(input).digest()
  const hmac = (key: Buffer, msg: Buffer): Buffer => createHmac('sha1', key).update(msg).digest()
  const hp = sha1(Buffer.concat([globalSalt, masterPassword]))
  const pes = Buffer.concat([entrySalt, Buffer.alloc(20 - entrySalt.length)])
  const chp = sha1(Buffer.concat([hp, entrySalt]))
  const k1 = hmac(chp, Buffer.concat([pes, entrySalt]))
  const tk = hmac(chp, pes)
  const k2 = hmac(chp, Buffer.concat([tk, entrySalt]))
  const k = Buffer.concat([k1, k2])
  const cipher = createCipheriv('des-ede3-cbc', k.subarray(0, 24), k.subarray(k.length - 8))
  return Buffer.concat([cipher.update(plaintext), cipher.final()])
}

test('der: parseDer walks nested sequences', () => {
  // SEQUENCE { OCTET "ab", SEQUENCE { INTEGER 5 } }
  const inner = Buffer.concat([Buffer.from([0x02, 0x01, 0x05])])
  const seq = Buffer.concat([Buffer.from([0x30, 0x03]), inner])
  const oct = Buffer.concat([Buffer.from([0x04, 0x02]), Buffer.from('ab')])
  const outer = Buffer.concat([Buffer.from([0x30, 0x09]), oct, seq])
  const { node } = parseDer(outer)
  assert.equal(node.tag, 0x30)
  assert.equal(node.children.length, 2)
  assert.equal(node.children[0]!.value.toString(), 'ab')
  assert.equal(node.children[1]!.children[0]!.value[0], 5)
})


test('firefox: 3DES PBE round-trips a password-check blob', () => {
  const gs = Buffer.from('globalsalt123456')
  const mp = Buffer.from('')
  const entrySalt = Buffer.from('entry-salt!')
  const plain = Buffer.from('password-check\x02\x02secret')
  const ct = moz3DesEncrypt(gs, mp, entrySalt, plain)
  // Build DER: SEQUENCE { SEQUENCE { OID(pbeWithSha1AndTripleDES-CBC), SEQUENCE { OCTET salt, INTEGER 1, INTEGER 24 } }, OCTET ct }
  const oid = Buffer.from([0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x05, 0x01, 0x03])
  const saltOct = Buffer.concat([Buffer.from([0x04, entrySalt.length]), entrySalt])
  const iterInt = Buffer.from([0x02, 0x01, 0x01])
  const lenInt = Buffer.from([0x02, 0x01, 0x18])
  const paramsInner = Buffer.concat([saltOct, iterInt, lenInt])
  const params = Buffer.concat([Buffer.from([0x30, paramsInner.length]), paramsInner])
  const algo = Buffer.concat([Buffer.from([0x30, oid.length + params.length]), oid, params])
  const ctOct = Buffer.concat([Buffer.from([0x04, ct.length]), ct])
  const top = Buffer.concat([Buffer.from([0x30, algo.length + ctOct.length]), algo, ctOct])
  const clear = decryptPbe(top, mp, gs)
  assert.ok(clear.subarray(0, 14).equals(Buffer.from('password-check', 'utf8')))
})
