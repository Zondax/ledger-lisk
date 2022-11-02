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


static parser_error_t parse_reclaim(parser_context_t *ctx, tx_command_legacy_token_reclaim_t *transfer) {

    uint64_t tmp64 = 0;

    GET_KEY_AND_VARUINT(ctx, tmp64);

    // Read amount
    GET_KEY_AND_VARUINT(ctx, tmp64);
    transfer->amount = tmp64;

    return parser_ok;
}

parser_error_t parse_legacy_module(parser_context_t *ctx, parser_tx_t *tx_obj) {

    if (tx_obj->command_id != TX_COMMAND_ID_RECLAIM) {
        return parser_unexpected_method;
    }

    CHECK_ERROR(parse_reclaim(ctx, &tx_obj->tx_command._legacy_token_reclaim))

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
