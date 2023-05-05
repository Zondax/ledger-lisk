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
#pragma once

#include "parser_common.h"
#include "parser_txdef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GET_KEY_AND_VARUINT(CTX, VAL)           \
    CHECK_ERROR(_readUnsignedVarint(CTX, &VAL)) \
    CHECK_ERROR(_readUnsignedVarint(CTX, &VAL)) \

parser_error_t _verifyBytes(parser_context_t *c, uint16_t buffLen);

parser_error_t _readBytes(parser_context_t *ctx, uint8_t *buff,
                          uint16_t buffLen);

parser_error_t _readUnsignedVarint(parser_context_t *ctx, uint64_t *output);

parser_error_t _readSignedVarint(parser_context_t *ctx, int64_t* result);

parser_error_t _toStringBalance(uint64_t *amount, uint8_t decimalPlaces,
                                const char postfix[], const char prefix[], char *outValue,
                                uint16_t outValueLen, uint8_t pageIdx,
                                uint8_t *pageCount);

parser_error_t _toStringStakeAmount(uint64_t *amount, const char prefix[],
                                char *outValue, uint16_t outValueLen, uint8_t pageIdx, 
                                uint8_t *pageCount);

parser_error_t _encodeAddressHash(uint8_t *buffer, uint16_t bufferLen,
                                  const uint8_t *pubkeyHash);

#ifdef __cplusplus
}

#endif
