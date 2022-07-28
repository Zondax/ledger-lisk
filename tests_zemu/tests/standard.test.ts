/** ******************************************************************************
 *  (c) 2018 - 2022 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu, { DEFAULT_START_OPTIONS } from '@zondax/zemu'
// @ts-ignore
import { LiskApp } from '@zondax/ledger-lisk'
import { APP_SEED, models, tx_message, tx_token_transfer } from './common'

// @ts-ignore
import ed25519 from 'ed25519-supercop'

// @ts-ignore
import crypto from 'crypto'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

const hdpath = `m/44'/134'/0/0/0`

jest.setTimeout(60000)

beforeAll(async () => {
  await Zemu.checkAndPullImage()
})

describe('Standard', function () {
  test.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, [1, 0, 0, 4, -5])
    } finally {
      await sim.close()
    }
  })

  test.each(models)('get app version', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())
      const resp = await app.getVersion()

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
      expect(resp).toHaveProperty('test_mode')
      expect(resp).toHaveProperty('major')
      expect(resp).toHaveProperty('minor')
      expect(resp).toHaveProperty('patch')

    } finally {
      await sim.close()
    }
  })

  test.each(models)('get address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const response = await app.getAddressAndPubKey(hdpath)

      console.log(response)

      expect(response.return_code).toEqual(0x9000)
      expect(response.error_message).toEqual('No errors')

      const expected_pk = 'cbc23486224ab599b62c7e8387ddd9c29c9b024bb46034b3a39b193bc3de78cb'
      const expected_address = 'lskw3yr8azweujx4ecvb3hd2ddd3d47ygcyrxrrpw'

      expect(response.pubKey).toEqual(expected_pk)
      expect(response.address).toEqual(expected_address)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('show address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const request = app.showAddressAndPubKey(hdpath)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address`)

      const response = await request
      console.log(response)

      expect(response.return_code).toEqual(0x9000)
      expect(response.error_message).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

  test.each(models)('show address - reject', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const request = app.showAddressAndPubKey(hdpath)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.navigateAndCompareUntilText('.', `${m.prefix.toLowerCase()}-show_address_reject`, 'REJECT')

      const response = await request
      console.log(response)

      expect(response.return_code).toEqual(0x6986)
      expect(response.error_message).toEqual('Transaction rejected')
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign token transfer', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_token_transfer, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_token_transfer`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)

    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign message', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const message = Buffer.from(tx_message)
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.signMessage(hdpath, message)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_message`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(message).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)

    } finally {
      await sim.close()
    }
  })

  // #{TODO} --> Add Zemu tests for different transactions. Include expert mode if needed
  // test.each(models)('sign tx0 normal', async function (m) {
  //   const sim = new Zemu(m.path)
  //   try {
  //     await sim.start({ ...defaultOptions, model: m.name })
  //     const app = new LiskApp(sim.getTransport())

  //     const txBlob = Buffer.from(txBlobExample)
  //     const responseAddr = await app.getAddressAndPubKey(accountId)
  //     const pubKey = responseAddr.publicKey

  //     // do not wait here.. we need to navigate
  //     const signatureRequest = app.sign(accountId, txBlob)

  //     // Wait until we are not in the main menu
  //     await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
  //     await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_asset_freeze`,50000)

  //     const signatureResponse = await signatureRequest
  //     console.log(signatureResponse)

  //     expect(signatureResponse.return_code).toEqual(0x9000)
  //     expect(signatureResponse.error_message).toEqual('No errors')

  //     // Now verify the signature
  //     const prehash = Buffer.concat([Buffer.from('TX'), txBlob]);
  //     const valid = ed25519.verify(signatureResponse.signature, prehash, pubKey)
  //     expect(valid).toEqual(true)
  //   } finally {
  //     await sim.close()
  //   }
  // })

  // test.each(models)('sign tx1 normal', async function (m) {
  //   const sim = new Zemu(m.path)
  //   try {
  //     await sim.start({ ...defaultOptions, model: m.name })
  //     const app = new LiskApp(sim.getTransport())

  //     const txBlob = Buffer.from(txBlobExample)
  //     const responseAddr = await app.getAddressAndPubKey(accountId)
  //     const pubKey = responseAddr.publicKey

  //     // do not wait here.. we need to navigate
  //     const signatureRequest = app.sign(accountId, txBlob)

  //     // Wait until we are not in the main menu
  //     await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
  //     await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_asset_freeze`,50000)

  //     const signatureResponse = await signatureRequest
  //     console.log(signatureResponse)

  //     expect(signatureResponse.return_code).toEqual(0x9000)
  //     expect(signatureResponse.error_message).toEqual('No errors')

  //     // Now verify the signature
  //     const prehash = Buffer.concat([Buffer.from('TX'), txBlob]);
  //     const valid = ed25519.verify(signatureResponse.signature, prehash, pubKey)
  //     expect(valid).toEqual(true)
  //   } finally {
  //     await sim.close()
  //   }
  // })
})
