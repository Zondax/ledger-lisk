/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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

#include <stdint.h>
#include "zxerror.h"
#include "parser_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PUBKEY_HASH_LEN         32u
#define CHECKSUMMED_ADDRESS_LEN 38u
#define PUBKEY_HASH_160BITS     20u

#define ADDRESS_LEN             32u
#define CHECKSUM_LEN             6u
#define HASH_5BITS               5u

parser_error_t crypto_hash(const uint8_t * input, uint8_t inputLen, uint8_t* output, uint8_t outputLen);
zxerr_t crypto_hashPubkey(const uint8_t * pubKey, uint8_t* buffer, uint8_t bufferLen);
zxerr_t crypto_split_string(const uint8_t *input, const uint8_t inputLen, uint8_t *output, uint8_t outputLen);
zxerr_t crypto_checksum(const uint8_t * address_5bits, uint8_t* output, uint8_t outputLen);
zxerr_t crypto_encodePubkey(uint8_t *buffer, uint16_t bufferLen, const uint8_t *pubkey, uint8_t *addrLen);
#ifdef __cplusplus
}
#endif
