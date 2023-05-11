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
import { LiskApp } from '@zondax/ledger-lisk'
import { cryptography } from '@liskhq/lisk-client'
import {
  APP_SEED,
  models,
  tx_token_transfer,
  tx_crosschain_transfer,
  tx_auth_multisig,
  tx_pos_report_mis,
  tx_pos_unlock,
  tx_pos_stake,
  tx_legacy_reclaim,
  tx_message,
  tx_message_non_printable,
  tx_pos_regValidator,
  tx_legacy_registerkeys,
  tx_interop_main_cc,
  tx_interop_side_cc,
  tx_interop_side_reg,
  tx_interop_main_reg,
  tx_interop_msg_recovery,
  tx_interop_msg_recovery_init,
  tx_interop_state_recovery,
  tx_interop_state_recovery_init,
} from './common'

// @ts-expect-error
import ed25519 from 'ed25519-supercop'

import crypto from 'crypto'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

const hdpath = `m/44'/134'/0'`

jest.setTimeout(300000)

describe('Custom', function () {
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign message', async function (m) {
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
      // Verificaiton function from lisk lib, takes message and does all
      // the hashing and varint enconding needed
      const valid = cryptography.ed.verifyMessageWithPublicKey({
        message: tx_message,
        publicKey: Buffer.from(pubKey, 'hex'),
        signature: signatureResponse.signature,
      })
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign message - non printable', async function (m) {
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
      // Verificaiton function from lisk lib, takes message and does all
      // the hashing and varint enconding needed
      const valid = cryptography.ed.verifyMessageWithPublicKey({
        message: tx_message_non_printable,
        publicKey: Buffer.from(pubKey, 'hex'),
        signature: signatureResponse.signature,
      })
      expect(valid).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign token transfer', async function (m) {
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
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign token transfer expert', async function (m) {
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
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign crosschain transfer', async function (m) {
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
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign crosschain transfer expert', async function (m) {
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
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign register multisignature', async function (m) {
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
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign register multisignature expert', async function (m) {
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
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign pos register validator', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_pos_regValidator, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_pos_reg_validator`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign pos register validator expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_pos_regValidator, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_pos_reg_validator_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign pos stake', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_pos_stake, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_pos_stake`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign pos stake expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_pos_stake, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_pos_stake_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign pos unlock', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_pos_unlock, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_pos_unlock`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign pos unlock expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_pos_unlock, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_pos_unlock_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign pos report misbehavior', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_pos_report_mis, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_pos_report_mis`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign report mish expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_pos_report_mis, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_pos_report_mis_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign legacy reclaim', async function (m) {
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
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      console.log(msgHash)
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign legacy reclaim expert', async function (m) {
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
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign legacy register keys', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_legacy_registerkeys, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_legacy_register_keys`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign legacy register keys expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_legacy_registerkeys, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_legacy_register_keys_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop mainchain CC update', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_interop_main_cc, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_main_cc_update`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop mainchain CC update expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_interop_main_cc, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_main_cc_update_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop sidechain CC update', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_interop_side_cc, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_side_cc_update`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop sidechain CC update expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_interop_side_cc, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_side_cc_update_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop main register', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_interop_main_reg, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_main_reg`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop mainchain register expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_interop_main_reg, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_main_reg_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop sidechain register', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_interop_side_reg, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_side_reg`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop sidechain register expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_interop_side_reg, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_side_reg_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop msg recovery', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_interop_msg_recovery, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_msg_recovery`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop msg recovery expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_interop_msg_recovery, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_msg_recovey_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop msg recovery init', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_interop_msg_recovery_init, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_msg_init_recovery`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop msg recovery init expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_interop_msg_recovery_init, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_msg_recovey_init_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop state recovery', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_interop_state_recovery, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_state_recovery`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop state recovery expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_interop_state_recovery, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_state_recovey_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop state recovery init', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(tx_interop_state_recovery_init, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_state_init_recovery`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign interop state recovery init expert', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.clickRight()
      await sim.clickBoth()
      await sim.clickLeft()

      const txBlob = Buffer.from(tx_interop_state_recovery_init, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_interop_state_recovey_init_expert`)

      const signatureResponse = await signatureRequest
      console.log(signatureResponse)

      expect(signatureResponse.return_code).toEqual(0x9000)
      expect(signatureResponse.error_message).toEqual('No errors')

      // Now verify the signature
      const hash = crypto.createHash('sha256')
      const msgHash = hash.update(txBlob).digest()
      console.log(msgHash)

      const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
      expect(valid).toEqual(true)
      console.log(valid)
    } finally {
      await sim.close()
    }
  })
})
