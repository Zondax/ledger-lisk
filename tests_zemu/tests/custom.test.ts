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
  tx_message_wrong,
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

const TXNS = [
  {
    name: 'sign_token_transfer',
    blob: tx_token_transfer,
  },
  {
    name: 'sign_crosschain_transfer',
    blob: tx_crosschain_transfer,
  },
  {
    name: 'sign_auth_multisig',
    blob: tx_auth_multisig,
  },
  {
    name: 'sign_pos_report_mis',
    blob: tx_pos_report_mis,
  },
  {
    name: 'sign_pos_unlock',
    blob: tx_pos_unlock,
  },
  {
    name: 'sign_pos_stake',
    blob: tx_pos_stake,
  },
  {
    name: 'sign_legacy_reclaim',
    blob: tx_legacy_reclaim,
  },
  {
    name: 'sign_pos_regValidator',
    blob: tx_pos_regValidator,
  },
  {
    name: 'sign_legacy_registerkeys',
    blob: tx_legacy_registerkeys,
  },
  {
    name: 'sign_interop_main_cc',
    blob: tx_interop_main_cc,
  },
  {
    name: 'sign_interop_side_cc',
    blob: tx_interop_side_cc,
  },
  {
    name: 'sign_interop_side_reg',
    blob: tx_interop_side_reg,
  },
  {
    name: 'sign_interop_main_reg',
    blob: tx_interop_main_reg,
  },
  {
    name: 'sign_interop_msg_recovery',
    blob: tx_interop_msg_recovery,
  },
  {
    name: 'sign_interop_msg_recovery_init',
    blob: tx_interop_msg_recovery_init,
  },
  {
    name: 'sign_interop_state_recovery',
    blob: tx_interop_state_recovery,
  },
  {
    name: 'sign_interop_state_recovery_init',
    blob: tx_interop_state_recovery_init,
  },
]

describe.each(TXNS)('Custom', function (data) {
  test.concurrent.each(models)(`Test: ${data.name}`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      const txBlob = Buffer.from(data.blob, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-${data.name}`)

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

  test.concurrent.each(models)(`Test: ${data.name} expert`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new LiskApp(sim.getTransport())

      // Change to expert mode so we can skip fields
      await sim.toggleExpertMode()

      const txBlob = Buffer.from(data.blob, 'hex')
      const responseAddr = await app.getAddressAndPubKey(hdpath)
      const pubKey = responseAddr.pubKey

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(hdpath, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-${data.name}_expert`)

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

    const hash = crypto.createHash('sha256')
    const msgHash = hash.update(message).digest()
    const valid = ed25519.verify(signatureResponse.signature, msgHash, pubKey)
    expect(valid).toEqual(true)
    console.log(valid)
  } finally {
    await sim.close()
  }
})

test.concurrent.each(models)('sign message invalid', async function (m) {
  const sim = new Zemu(m.path)
  try {
    await sim.start({ ...defaultOptions, model: m.name })
    const app = new LiskApp(sim.getTransport())

    const message = Buffer.from(tx_message_wrong)

    // do not wait here.. we need to navigate
    const signatureResponse = await app.signMessage(hdpath, message)

    console.log(signatureResponse)

    expect(signatureResponse.return_code).toEqual(0x6984)
    expect(signatureResponse.error_message).toEqual('Data is invalid : Unexpected tag init')
  } finally {
    await sim.close()
  }
})

test.concurrent.each(models)('claim message', async function (m) {
  const sim = new Zemu(m.path)
  try {
    await sim.start({ ...defaultOptions, model: m.name })
    const app = new LiskApp(sim.getTransport())

    const message = Buffer.from(tx_message)
    const responseAddr = await app.getAddressAndPubKey(hdpath)
    const pubKey = responseAddr.pubKey

    // do not wait here.. we need to navigate
    const signatureRequest = app.claimMessage(hdpath, message)

    // Wait until we are not in the main menu
    await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
    await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-claim_message`)

    const signatureResponse = await signatureRequest
    console.log(signatureResponse)

    expect(signatureResponse.return_code).toEqual(0x9000)
    expect(signatureResponse.error_message).toEqual('No errors')

    const sha3 = require('js-sha3')
    const msgHash = sha3.keccak256(message)
    const appendedBytes = Buffer.concat([Buffer.from(msgHash, 'hex'), Buffer.alloc(9)])

    const valid = ed25519.verify(signatureResponse.signature, appendedBytes, pubKey)
    expect(valid).toEqual(true)
    console.log(valid)
  } finally {
    await sim.close()
  }
})
