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
import {
  APP_SEED,
  models,
  tx_token_transfer,
  tx_crosschain_transfer,
  tx_auth_multisig,
  tx_dpos_regDelegate,
  tx_dpos_report_mis,
  tx_dpos_unlock,
  tx_dpos_vote,
  tx_legacy_reclaim,
  tx_message,
  tx_message_non_printable,
} from './common'

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

jest.setTimeout(300000)

describe('Custom', function () {
  test.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
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

  test.each(models)('sign message - non printable', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const message = Buffer.from(tx_message_non_printable)
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.signMessage(hdpath, message)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_message_non_printable`)

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
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign token transfer expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_token_transfer, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_token_transfer_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign crosschain transfer', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_crosschain_transfer, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_crosschain_transfer`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign crosschain transfer expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_crosschain_transfer, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_crosschain_transfer_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign register multisignature', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_auth_multisig, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_auth_multisig`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign register multisignature expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_auth_multisig, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_auth_multisig_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign dpos register delegate', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_dpos_regDelegate, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_dpos_reg_delegate`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign dpos register delegate expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_dpos_regDelegate, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_dpos_reg_delegate_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign dpos vote', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_dpos_vote, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_dpos_vote`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign dpos vote expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_dpos_vote, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_dpos_vote_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign dpos unlock', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_dpos_unlock, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_dpos_unlock`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign dpos unlock expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_dpos_unlock, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_dpos_unlock_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign dpos report misbehavior', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_dpos_report_mis, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_dpos_report_mis`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign dpos unlock expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_dpos_report_mis, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_dpos_report_mis_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign legacy reclaim', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_legacy_reclaim, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_legacy_reclaim`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign legacy reclaim expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_legacy_reclaim, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_legacy_reclaim_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const valid = ed25519.verify(signatureResponse.signature, txBlob, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })
})
