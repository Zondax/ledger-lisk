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

#include "txn_auth_module.h"
#include "parser_utils.h"
#include "zxmacros.h"
#include "coin.h"
#include "zxformat.h"


static parser_error_t parse_reclaim(parser_context_t *ctx, tx_command_legacy_token_reclaim_t *transfer) {

    uint64_t tmp64 = 0;

    // Read amount
    GET_KEY_AND_VARUINT(ctx, tmp64);
    transfer->amount = tmp64;

    return parser_ok;
}

static parser_error_t parse_register_keys(parser_context_t *ctx, tx_command_legacy_register_keys_t *transfer) {

    uint64_t tmp64 = 0;

    // Read blskey
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != BLS_PUBLIC_KEY_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->blskey = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, BLS_PUBLIC_KEY_LENGTH))

    // Read proofOfPossession
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != BLS_POP_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->proofOfPossession = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, BLS_POP_LENGTH))

    // Read generatorKey
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != ED25519_PUBLIC_KEY_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->generatorKey = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, ED25519_PUBLIC_KEY_LENGTH))

    return parser_ok;
}

parser_error_t parse_legacy_module(parser_context_t *ctx, parser_tx_t *tx_obj) {

    switch (tx_obj->command_id) {
        case TX_COMMAND_ID_RECLAIM:
            CHECK_ERROR(parse_reclaim(ctx, &tx_obj->tx_command._legacy_token_reclaim))
            break;
        case TX_COMMAND_ID_REGISTER_KEYS:
            CHECK_ERROR(parse_register_keys(ctx, &tx_obj->tx_command._legacy_register_keys))
            break;
        default:
            return parser_unexpected_method;
    }

    return parser_ok;
}

parser_error_t print_module_legacy_reclaim(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {

    *pageCount = 1;
    switch (displayIdx)  {
        case RECLAIM_AMOUNT_TYPE:
            snprintf(outKey, outKeyLen, "Amount");
            return _toStringBalance(&ctx->tx_obj->tx_command._legacy_token_reclaim.amount,
                                    COIN_AMOUNT_DECIMAL_PLACES, "", COIN_TICKER,
                                    outVal, outValLen, pageIdx, pageCount);
        default:
            break;
    }

    return parser_display_idx_out_of_range;
}

parser_error_t print_module_legacy_register_keys(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {

    *pageCount = 1;
    char buf[BLS_POP_LENGTH * 2 + 1] = {0};
    switch (displayIdx) {
        case LEGACY_REGISTER_KEYS_GENKEY_TYPE: {
            array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->tx_command._legacy_register_keys.generatorKey,
                            ED25519_PUBLIC_KEY_LENGTH);
            snprintf(outKey, outKeyLen, "GenKey");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        }

        case LEGACY_REGISTER_KEYS_BLSKEY_TYPE: {
            array_to_hexstr(buf, sizeof(buf),ctx->tx_obj->tx_command._legacy_register_keys.blskey,
                            BLS_PUBLIC_KEY_LENGTH);
            snprintf(outKey, outKeyLen, "BlsKey");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        }

        case LEGACY_REGISTER_KEYS_POP_TYPE: {
            array_to_hexstr(buf, sizeof(buf),ctx->tx_obj->tx_command._legacy_register_keys.proofOfPossession,
                            BLS_POP_LENGTH);
            snprintf(outKey, outKeyLen, "PoP");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        }
        default :
            break;
    }

    return parser_display_idx_out_of_range;
}
