/*******************************************************************************
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
********************************************************************************/
#include "parser_utils.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "crypto_helper.h"
#include "coin.h"
#include "lisk_base32.h"

static const char MSB = 0x80;

// Checks that there are at least SIZE bytes available in the buffer
#define CTX_CHECK_AVAIL(CTX, SIZE) \
    if ( (CTX) == NULL || ((CTX)->offset + (SIZE)) > (CTX)->bufferLen) { return parser_unexpected_buffer_end; }

#define CTX_CHECK_AND_ADVANCE(CTX, SIZE) \
    CTX_CHECK_AVAIL((CTX), (SIZE))   \
    (CTX)->offset += (SIZE);

parser_error_t _encodeAddressHash(uint8_t *buffer, uint16_t bufferLen, const uint8_t *pubkeyHash) {

    // Add HRP
    const uint8_t hrpLen = strlen(COIN_HRP);
    MEMCPY(buffer, COIN_HRP, hrpLen);

    // Get address + checksum
    uint8_t tmpAddress[CHECKSUMMED_ADDRESS_LEN] = {0};
    crypto_split_string(pubkeyHash, 20, tmpAddress, sizeof(tmpAddress));
    crypto_checksum(tmpAddress, tmpAddress + ADDRESS_LEN, sizeof(tmpAddress)-ADDRESS_LEN);

    // LiskBase32 encoding
    lisk_base32_encode(tmpAddress, ADDRESS_LEN + CHECKSUM_LEN, buffer + hrpLen, bufferLen - hrpLen);

    return parser_ok;
}

parser_error_t _verifyBytes(parser_context_t *c, uint16_t buffLen) {
    CTX_CHECK_AVAIL(c, buffLen)
    CTX_CHECK_AND_ADVANCE(c, buffLen)
    return parser_ok;
}

parser_error_t _readBytes(parser_context_t *ctx, uint8_t *buff, uint16_t buffLen) {
    CTX_CHECK_AVAIL(ctx, buffLen)
    MEMCPY(buff, (ctx->buffer + ctx->offset), buffLen);
    CTX_CHECK_AND_ADVANCE(ctx, buffLen)
    return parser_ok;
}

parser_error_t _readUnsignedVarint(parser_context_t *ctx, uint64_t* output) {

    int bits = 0;
    uint64_t tmpByte = 0;
    *output = 0;

    CHECK_ERROR(_readBytes(ctx, (uint8_t*)&tmpByte, 1))

    while (tmpByte & MSB) {
        *output += ((tmpByte & 0x7F) << bits);
        bits += 7;

        CHECK_ERROR(_readBytes(ctx, (uint8_t*)&tmpByte, 1))
    }
    *output += ((tmpByte & 0x7F) << bits);

    return parser_ok;
}

parser_error_t _readSignedVarint(parser_context_t *ctx, int64_t* result) {

    int bits = 0;
    uint64_t tmpByte = 0;
    uint64_t output = 0;

    CHECK_ERROR(_readBytes(ctx, (uint8_t*)&tmpByte, 1))

    while (tmpByte & MSB) {
        output += ((tmpByte & 0x7F) << bits);
        bits += 7;

        CHECK_ERROR(_readBytes(ctx, (uint8_t*)&tmpByte, 1))
    }
    output += ((tmpByte & 0x7F) << bits);

    *result = (int64_t) output;

    if(*result % 2 == 0) {
        *result = *result / 2;
    } else {
        *result = -(*result + 1) / 2;
    }

    return parser_ok;
}

parser_error_t _toStringBalance(uint64_t *amount, uint8_t decimalPlaces, char postfix[], char prefix[],
                                char *outValue, uint16_t outValueLen, uint8_t pageIdx, uint8_t *pageCount)
{
    char bufferUI[200] = {0};
    if (uint64_to_str(bufferUI, sizeof(bufferUI), *amount) != NULL) {
        return parser_unexpected_value;
    }

    if (intstr_to_fpstr_inplace(bufferUI, sizeof(bufferUI), decimalPlaces) == 0) {
        return parser_unexpected_value;
    }

    if (z_str3join(bufferUI, sizeof(bufferUI), prefix, postfix) != zxerr_ok) {
        return parser_unexpected_buffer_end;
    }

    number_inplace_trimming(bufferUI, 1);

    pageString(outValue, outValueLen, bufferUI, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t _toStringStakeAmount(uint64_t *amount, char prefix[],
                                char *outValue, uint16_t outValueLen, uint8_t pageIdx, uint8_t *pageCount)
{
    char bufferUI[200] = {0};
    if (uint64_to_str(bufferUI, sizeof(bufferUI), *amount/(BASE_STAKE_AMOUNT_DECIMALS)) != NULL) {
        return parser_unexpected_value;
    }

    if (z_str3join(bufferUI, sizeof(bufferUI), prefix, "") != zxerr_ok) {
        return parser_unexpected_buffer_end;
    }

    pageString(outValue, outValueLen, bufferUI, pageIdx, pageCount);
    return parser_ok;
}


