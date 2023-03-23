/** ******************************************************************************
 *  (c) 2018 - 2022 Zondax AG
 *  (c) 2016-2017 Ledger
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
import type Transport from "@ledgerhq/hw-transport";
import {
  type ResponseMultipleAddresses,
  type ResponseAddress,
  type ResponseAppInfo,
  type ResponseDeviceInfo,
  type ResponseSign,
  type ResponseVersion,
} from "./types";
import {
  CHUNK_SIZE,
  ERROR_CODE,
  errorCodeToString,
  getVersion,
  LedgerError,
  PAYLOAD_TYPE,
  P1_VALUES,
  processErrorResponse,
  serializePath,
} from "./common";
import { CLA, INS, PKLEN } from "./config";

export { LedgerError };
export * from "./types";

function processGetAddrResponse(response: Buffer) {
  const errorCodeData = response.subarray(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const pubKey = response.subarray(0, PKLEN).toString("hex");
  const address = response.subarray(PKLEN, response.length - 2).toString("ascii");

  return {
    pubKey,
    address,
    return_code: returnCode,
    error_message: errorCodeToString(returnCode),
  };
}

export class LiskApp {
  private readonly transport: Transport;

  constructor(transport: Transport) {
    if (!transport) {
      throw new Error("Transport has not been defined");
    }
    this.transport = transport;
  }

  static prepareChunks(serializedPathBuffer: Buffer, message: Buffer) {
    const chunks = [];
    // First chunk (only path)
    chunks.push(serializedPathBuffer);

    const messageBuffer = Buffer.from(message);
    const buffer = Buffer.concat([messageBuffer]);
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE;
      if (i > buffer.length) {
        end = buffer.length;
      }
      chunks.push(buffer.subarray(i, end));
    }
    return chunks;
  }

  async signGetChunks(path: string, message: Buffer) {
    return LiskApp.prepareChunks(serializePath(path), message);
  }

  async getVersion(): Promise<ResponseVersion> {
    return await getVersion(this.transport).catch((err) => processErrorResponse(err));
  }

  async getAppInfo(): Promise<ResponseAppInfo> {
    return await this.transport.send(0xb0, 0x01, 0, 0).then((response) => {
      const errorCodeData = response.subarray(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      const result: { errorMessage?: string; returnCode?: LedgerError } = {};

      let appName = "err";
      let appVersion = "err";
      let flagLen = 0;
      let flagsValue = 0;

      if (response[0] !== 1) {
        // Ledger responds with format ID 1. There is no spec for any format != 1
        result.errorMessage = "response format ID not recognized";
        result.returnCode = LedgerError.DeviceIsBusy;
      } else {
        const appNameLen = response[1];
        appName = response.subarray(2, 2 + appNameLen).toString("ascii");
        let idx = 2 + appNameLen;
        const appVersionLen = response[idx];
        idx += 1;
        appVersion = response.subarray(idx, idx + appVersionLen).toString("ascii");
        idx += appVersionLen;
        const appFlagsLen = response[idx];
        idx += 1;
        flagLen = appFlagsLen;
        flagsValue = response[idx];
      }

      return {
        appName,
        appVersion,
        flagLen,
        flagsValue,
        flagRecovery: (flagsValue & 1) !== 0,
        // eslint-disable-next-line no-bitwise
        flagSignedMcuCode: (flagsValue & 2) !== 0,
        // eslint-disable-next-line no-bitwise
        flagOnboarded: (flagsValue & 4) !== 0,
        // eslint-disable-next-line no-bitwise
        flagPINValidated: (flagsValue & 128) !== 0,

        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
      };
    }, processErrorResponse);
  }

  async deviceInfo(): Promise<ResponseDeviceInfo> {
    return await this.transport.send(0xe0, 0x01, 0, 0, Buffer.from([]), [0x6e00]).then((response) => {
      const errorCodeData = response.subarray(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

      if (returnCode === 0x6e00) {
        return {
          return_code: returnCode,
          error_message: "This command is only available in the Dashboard",
        };
      }

      const targetId = response.subarray(0, 4).toString("hex");

      let pos = 4;
      const secureElementVersionLen = response[pos];
      pos += 1;
      const seVersion = response.subarray(pos, pos + secureElementVersionLen).toString();
      pos += secureElementVersionLen;

      const flagsLen = response[pos];
      pos += 1;
      const flag = response.subarray(pos, pos + flagsLen).toString("hex");
      pos += flagsLen;

      const mcuVersionLen = response[pos];
      pos += 1;
      // Patch issue in mcu version
      let tmp = response.subarray(pos, pos + mcuVersionLen);
      if (tmp[mcuVersionLen - 1] === 0) {
        tmp = response.subarray(pos, pos + mcuVersionLen - 1);
      }
      const mcuVersion = tmp.toString();

      return {
        targetId,
        seVersion,
        flag,
        mcuVersion,

        return_code: returnCode,
        error_message: errorCodeToString(returnCode),
      };
    }, processErrorResponse);
  }

  async getAddressAndPubKey(path: string): Promise<ResponseAddress> {
    const serializedPath = serializePath(path);
    return await this.transport
      .send(CLA, INS.GET_ADDR_PUBKEY, P1_VALUES.ONLY_RETRIEVE, 0, serializedPath, [LedgerError.NoErrors])
      .then(processGetAddrResponse, processErrorResponse);
  }

  async getMultipleAddresses(indexes: number[]): Promise<ResponseMultipleAddresses> {
    if (indexes.length === 0) throw new Error("Indexes array must not be empty");
    const addresses: ResponseMultipleAddresses = {
      return_code: LedgerError.NoErrors,
      error_message: errorCodeToString(LedgerError.NoErrors),
      addr: {},
    };
    for (const index of indexes) {
      const addr = await this.getAddressAndPubKey(`m/44'/134'/${index}'`);
      if (addr.return_code !== LedgerError.NoErrors)
        return { return_code: addr.return_code, error_message: addr.error_message, addr: [] };
      addresses.addr[index] = { pubKey: addr.pubKey, address: addr.address };
    }
    return addresses;
  }

  async showAddressAndPubKey(path: string): Promise<ResponseAddress> {
    const serializedPath = serializePath(path);
    return await this.transport
      .send(CLA, INS.GET_ADDR_PUBKEY, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, serializedPath, [LedgerError.NoErrors])
      .then(processGetAddrResponse, processErrorResponse);
  }

  async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer, ins: number): Promise<ResponseSign> {
    let payloadType = PAYLOAD_TYPE.ADD;
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT;
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST;
    }

    // Check supported sign instructions
    if (ins !== INS.SIGN_TXN) {
      // Error here
    }

    return await this.transport
      .send(CLA, ins, payloadType, 0, chunk, [
        LedgerError.NoErrors,
        LedgerError.DataIsInvalid,
        LedgerError.BadKeyHandle,
        LedgerError.SignVerifyError,
      ])
      .then((response: Buffer) => {
        const errorCodeData = response.subarray(-2);
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
        let errorMessage = errorCodeToString(returnCode);

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid ||
          returnCode === LedgerError.SignVerifyError
        ) {
          errorMessage = `${errorMessage} : ${response.subarray(0, response.length - 2).toString("ascii")}`;
        }

        if (returnCode === LedgerError.NoErrors && response.length > 2) {
          const signature = response.subarray(0, response.length - 2);
          return {
            signature,
            return_code: returnCode,
            error_message: errorMessage,
          };
        }

        return {
          return_code: returnCode,
          error_message: errorMessage,
        };
      }, processErrorResponse);
  }

  async sign(path: string, message: Buffer) {
    return await this.signGetChunks(path, message).then(async (chunks) => {
      return await this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN_TXN).then(async (result) => {
        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop,no-param-reassign
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN_TXN);
          if (result.return_code !== ERROR_CODE.NoError) {
            break;
          }
        }

        return {
          return_code: result.return_code,
          error_message: result.error_message,
          signature: result.signature,
        };
      }, processErrorResponse);
    });
  }

  async signMessage(path: string, message: Buffer) {
    return await this.signGetChunks(path, message).then(async (chunks) => {
      return await this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN_MSG).then(async (result) => {
        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop,no-param-reassign
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN_MSG);
          if (result.return_code !== ERROR_CODE.NoError) {
            break;
          }
        }

        return {
          return_code: result.return_code,
          error_message: result.error_message,
          signature: result.signature,
        };
      }, processErrorResponse);
    });
  }
}

/**
 * Class to specify An account used to query the ledger.
 */
enum SupportedCoin {
  /**
   * @see https://lisk.io
   */
  LISK = 134,
}

export class LedgerAccount {
  private _account: number = 0;
  private _coinIndex: SupportedCoin = SupportedCoin.LISK; // LISK

  /**
   * Specify the account number
   * @param {number} newAccount
   * @returns {this}
   */
  public account(newAccount: number): this {
    this.assertValidPath(newAccount);
    this._account = newAccount;
    return this;
  }

  /**
   * Specify the coin index. At the moment will force alwais Lisk.
   * @see https://github.com/satoshilabs/slips/blob/master/slip-0044.md
   * @param {number} newIndex
   * @returns {this}
   */
  public coinIndex(newIndex: SupportedCoin): this {
    this.assertValidPath(newIndex);
    // this._coinIndex = newIndex;
    this._coinIndex = SupportedCoin.LISK;
    return this;
  }

  /**
   * Derive the path using hardened entries.
   * @returns {string} defines the path in buffer form.
   */
  public derivePath(): string {
    const pathArray: string = `m/44'/${this._coinIndex}'/${this._account}'`;
    return pathArray;
  }

  /**
   * Asserts that the given param is a valid path (integer > 0)
   */
  private assertValidPath(n: number) {
    if (!Number.isInteger(n)) {
      throw new Error("Param must be an integer");
    }
    if (n < 0) {
      throw new Error("Param must be greater than zero");
    }
  }
}
