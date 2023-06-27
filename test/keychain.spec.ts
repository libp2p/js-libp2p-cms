/* eslint max-nested-callbacks: ["error", 8] */
/* eslint-env mocha */

import { DefaultKeyChain } from '@libp2p/keychain'
import { expect } from 'aegir/chai'
import { MemoryDatastore } from 'datastore-core/memory'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import { toString as uint8ArrayToString } from 'uint8arrays/to-string'
import { CMS } from '../src/index.js'
import type { KeyChain } from '@libp2p/interface-keychain'
import type { Datastore } from 'interface-datastore'

describe('keychain', () => {
  const passPhrase = 'this is not a secure phrase'
  const rsaKeyName = 'tajné jméno'
  let datastore1: Datastore
  let datastore2: Datastore
  let ks: KeyChain
  let cms: CMS
  let cms2: CMS

  before(async () => {
    datastore1 = new MemoryDatastore()
    datastore2 = new MemoryDatastore()

    ks = new DefaultKeyChain({
      datastore: datastore2
    }, { pass: passPhrase })
    cms = new CMS(ks)

    cms2 = new CMS(new DefaultKeyChain({
      datastore: datastore1
    }, { pass: passPhrase }))
  })

  describe('CMS protected data', () => {
    const plainData = uint8ArrayFromString('This is a message from Alice to Bob')

    before(async () => {
      await ks.createKey(rsaKeyName, 'RSA', 2048)
    })

    it('requires a key', async () => {
      await expect(cms.encrypt('no-key', plainData)).to.eventually.be.rejected.with.property('code', 'ERR_KEY_NOT_FOUND')
    })

    it('requires plain data as a Uint8Array', async () => {
      // @ts-expect-error invalid parameters
      await expect(cms.encrypt(rsaKeyName, 'plain data')).to.eventually.be.rejected.with.property('code', 'ERR_INVALID_PARAMETERS')
    })

    it('encrypts', async () => {
      const encrpted = await cms.encrypt(rsaKeyName, plainData)
      expect(encrpted).to.exist()
      expect(encrpted).to.be.instanceOf(Uint8Array)
    })

    it('is a PKCS #7 message', async () => {
      // @ts-expect-error invalid parameters
      await expect(cms.decrypt('not CMS')).to.eventually.be.rejected.with.property('code', 'ERR_INVALID_PARAMETERS')
    })

    it('is a PKCS #7 binary message', async () => {
      await expect(cms.decrypt(plainData)).to.eventually.be.rejected.with.property('code', 'ERR_INVALID_CMS')
    })

    it('cannot be read without the key', async () => {
      const encrpted = await cms.encrypt(rsaKeyName, plainData)
      await expect(cms2.decrypt(encrpted)).to.eventually.be.rejected.with.property('code', 'ERR_MISSING_KEYS')
    })

    it('can be read with the key', async () => {
      const encrpted = await cms.encrypt(rsaKeyName, plainData)
      const plain = await cms.decrypt(encrpted)
      expect(plain).to.exist()
      expect(uint8ArrayToString(plain)).to.equal(uint8ArrayToString(plainData))
    })
  })
})
