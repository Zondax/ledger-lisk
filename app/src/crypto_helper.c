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

#include "crypto_helper.h"
#include "coin.h"
#include "lisk_base32.h"
#include "zxmacros.h"


#define SHA256_LENGTH 32

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    #include "cx.h"
#else
    #include "picohash.h"
    #if !defined(CX_SHA256_SIZE)
        #define CX_SHA256_SIZE 32
    #endif
#endif

static uint32_t crypto_polymod(uint32_t checksum) {
  uint8_t top = checksum >> 25;
  return ((checksum & 0x1FFFFFF) << 5) ^
         (-((top >> 0) & 1) & 0x3b6a57b2) ^
         (-((top >> 1) & 1) & 0x26508e6d) ^
         (-((top >> 2) & 1) & 0x1ea119fa) ^
         (-((top >> 3) & 1) & 0x3d4233dd) ^
         (-((top >> 4) & 1) & 0x2a1462b3);
}

zxerr_t crypto_hashPubkey(const uint8_t * pubKey, uint8_t* buffer, uint8_t bufferLen) {
    unsigned char hash[32] = {0};

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    cx_sha256_t ctx;

    if(bufferLen < PUBKEY_HASH_LEN) {
        return zxerr_buffer_too_small;
    }
    memset(&ctx, 0, sizeof(ctx));
    cx_sha256_init(&ctx);
    cx_hash(&ctx.header, CX_LAST, pubKey, PK_LEN_25519, hash, sizeof(hash));
#else
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, pubKey, PK_LEN_25519);
    picohash_final(&ctx, hash);
#endif

    MEMCPY(buffer, hash, PUBKEY_HASH_LEN);
    return zxerr_ok;
}

parser_error_t crypto_hash(const uint8_t * input, uint8_t inputLen, uint8_t* output, uint8_t outputLen) {
    unsigned char hash[CX_SHA256_SIZE] = {0};

    if(outputLen < CX_SHA256_SIZE) {
        return parser_unexpected_buffer_end;
    }

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    cx_sha256_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    cx_sha256_init(&ctx);
    cx_hash(&ctx.header, CX_LAST, input, inputLen, hash, sizeof(hash));
#else
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, input, inputLen);
    picohash_final(&ctx, hash);
#endif
    MEMCPY(output, hash, sizeof(hash));
    return parser_ok;
}

zxerr_t crypto_msg_hash(const uint8_t * input, uint8_t inputLen, uint8_t* output, uint8_t outputLen) {
    unsigned char hash[CX_SHA256_SIZE] = {0};

    if (outputLen < CX_SHA256_SIZE) {
        return zxerr_buffer_too_small;
    }

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    cx_sha256_t tmp_ctx = {0};
    cx_sha256_init(&tmp_ctx);

    uint8_t varint[9] = {0};
    uint16_t prefixLength = strlen(SIGNED_MESSAGE_PREFIX);
    uint8_t varintLength = lisk_encode_varint(prefixLength, varint);

    // Hash enconded prefix length and prefix
    cx_hash(&tmp_ctx.header, 0, varint, varintLength, NULL, 0);
    cx_hash(&tmp_ctx.header, 0, (unsigned char*)SIGNED_MESSAGE_PREFIX, prefixLength, NULL, 0);

    // End first Hash with message length and message content
    MEMZERO(varint, sizeof(varint));
    varintLength = lisk_encode_varint(inputLen, varint);
    cx_hash(&tmp_ctx.header, 0, varint, varintLength, NULL, 0);
    cx_hash(&tmp_ctx.header, 0, input , inputLen, NULL, 0);
    cx_hash(&tmp_ctx.header, CX_LAST, NULL, 0, hash, CX_SHA256_SIZE);

    // Rehash previous hash
    cx_sha256_t ctx = {0};
    cx_sha256_init(&ctx);
    MEMZERO(output, outputLen);
    cx_hash(&ctx.header, CX_LAST, hash, CX_SHA256_SIZE, output, outputLen);
#endif 
    return zxerr_ok;
}

// Taken from base32 code --> create 5bits numbers from input
zxerr_t crypto_split_string(const uint8_t *input, const uint8_t inputLen, uint8_t *output, uint8_t outputLen) {
    uint32_t count = 0;
    if (inputLen > 0) {
        uint32_t buffer = input[0];
        uint32_t next = 1;
        uint32_t bitsLeft = 8;
        while (count < outputLen && (bitsLeft > 0 || next < inputLen)) {
            if (bitsLeft < 5) {
                if (next < inputLen) {
                    buffer <<= 8;
                    buffer |= input[next++] & 0xFF;
                    bitsLeft += 8;
                } else {
                    uint32_t pad = 5u - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }
            uint32_t index = 0x1Fu & (buffer >> (bitsLeft - 5u));
            bitsLeft -= 5;
            output[count++] = index;
        }
    }
    return zxerr_ok;
}

zxerr_t crypto_checksum(const uint8_t * address_5bits, uint8_t* output, uint8_t outputLen)
{
    if (outputLen < CHECKSUM_LEN) {
        return zxerr_buffer_too_small;
    }

    uint32_t checksum = 1;
    for (uint8_t i = 0; i < ADDRESS_LEN; ++i) {
        if (address_5bits[i] >> 5) {
            return zxerr_out_of_bounds;
        }
        checksum = crypto_polymod(checksum) ^ address_5bits[i];
    }

    for (uint8_t i = 0; i < CHECKSUM_LEN; ++i) {
        checksum = crypto_polymod(checksum);
    }

    checksum ^= 1;
    for (uint8_t i = 0; i < CHECKSUM_LEN; ++i) {
        output[i] = (checksum >> (5 * (5 - i)) & 0x1F);
    }

    return zxerr_ok;
}

zxerr_t crypto_encodePubkey(uint8_t *buffer, uint16_t bufferLen, const uint8_t *pubkey, uint8_t *addrLen) {
    // Generate address (https://github.com/LiskHQ/lips/blob/main/proposals/lip-0018.md)
    // Add HRP
    const uint8_t hrpLen = strlen(COIN_HRP);
    MEMCPY(buffer, COIN_HRP, hrpLen);
    // Get Hash(pubKey)
    uint8_t pubkeyHash[PUBKEY_HASH_LEN] = {0};
    CHECK_ZXERR(crypto_hashPubkey(pubkey, pubkeyHash, sizeof(pubkeyHash)))
    // Get address + checksum
    uint8_t tmpAddress[CHECKSUMMED_ADDRESS_LEN] = {0};
    CHECK_ZXERR(crypto_split_string(pubkeyHash, PUBKEY_HASH_160BITS, tmpAddress, sizeof(tmpAddress)))
    CHECK_ZXERR(crypto_checksum(tmpAddress, tmpAddress + ADDRESS_LEN, sizeof(tmpAddress)-ADDRESS_LEN))
    // LiskBase32 encoding
    uint8_t addressLen = lisk_base32_encode(tmpAddress, ADDRESS_LEN + CHECKSUM_LEN, buffer + hrpLen, bufferLen - hrpLen);

    *addrLen = addressLen + hrpLen;
    return zxerr_ok;
}
