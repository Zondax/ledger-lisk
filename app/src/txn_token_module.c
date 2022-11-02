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

#include "txn_token_module.h"
#include "parser_utils.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "coin.h"

static parser_error_t parse_transfer(parser_context_t *ctx, tx_command_token_transfer_t *transfer) {

    uint64_t tmp64 = 0;

    // skip
    GET_KEY_AND_VARUINT(ctx, tmp64);

    // Read TOKENID
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != TOKEN_ID_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->tokenid = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, TOKEN_ID_LENGTH))

    // Read amount
    GET_KEY_AND_VARUINT(ctx, tmp64);
    transfer->amount = tmp64;

    // Read recipent address
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != ADDRESS_HASH_LENGTH) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(_readBytes(ctx, (uint8_t*) &transfer->recipientAddress, ADDRESS_HASH_LENGTH))

    // Read data length and data
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 == 0 || tmp64 > DATA_MAX_LENGTH) {
        return parser_value_out_of_range;
    }
    transfer->dataLength=tmp64;
    transfer->data = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, tmp64))

    if(ctx->bufferLen == ctx->offset) {
         transfer->accountInitializationFee = USER_ACCOUNT_INITIALIZATION_FEE;
    } else {
        //Read accountInitializationFee
        GET_KEY_AND_VARUINT(ctx, tmp64);
        transfer->accountInitializationFee = tmp64;
    }

    return parser_ok;
}

static parser_error_t parse_crosschain_transfer(parser_context_t *ctx, tx_command_token_crosschain_transfer_t *transfer) {
    uint64_t tmp64 = 0;

    GET_KEY_AND_VARUINT(ctx, tmp64);

    // Read TOKENID
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != TOKEN_ID_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->tokenid = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, TOKEN_ID_LENGTH))

    // Read amount
    GET_KEY_AND_VARUINT(ctx, tmp64);
    transfer->amount = tmp64;

    // Read receivingChainID
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != CHAIN_ID_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->receivingChainID = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, CHAIN_ID_LENGTH))

    // Read recipent address
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != ADDRESS_HASH_LENGTH) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(_readBytes(ctx, (uint8_t*) &transfer->recipientAddress, ADDRESS_HASH_LENGTH))

    // Read data length and data
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 == 0 || tmp64 > DATA_MAX_LENGTH) {
        return parser_value_out_of_range;
    }
    transfer->dataLength = tmp64;
    transfer->data = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, tmp64))

    // Read message fee
    GET_KEY_AND_VARUINT(ctx, tmp64);
    transfer->messageFee = tmp64;

    if(ctx->bufferLen == ctx->offset) {
         transfer->escrowInitializationFee = ESCROW_ACCOUNT_INITIALIZATION_FEE;
    } else {
        // Read escrowInitializationFee
        GET_KEY_AND_VARUINT(ctx, tmp64);
        transfer->escrowInitializationFee = tmp64;
    }

       return parser_ok;
}

parser_error_t parse_token_module(parser_context_t *ctx, parser_tx_t *tx_obj) {

    switch (tx_obj->command_id) {
        case TX_COMMAND_ID_TRANSFER:
            CHECK_ERROR(parse_transfer(ctx, &tx_obj->tx_command._token_transfer))
            break;
        case TX_COMMAND_ID_CROSSCHAIN_TRANSFER:
            CHECK_ERROR(parse_crosschain_transfer(ctx, &tx_obj->tx_command._token_crosschain_transfer))
            break;
        default:
            return parser_unexpected_method;
    }

    return parser_ok;
}

parser_error_t print_module_token_transfer(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {

    *pageCount = 1;
    char buf[DATA_MAX_LENGTH] = {0};

    switch (displayIdx) {
        case TOKEN_TRANSFER_TOKEN_ID_TYPE: {
            array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->tx_command._token_transfer.tokenid,TOKEN_ID_LENGTH);
            snprintf(outKey, outKeyLen, "TokenID");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        }

        case TOKEN_TRANSFER_AMOUNT_TYPE: {
            snprintf(outKey, outKeyLen, "Amount");
            return _toStringBalance(&ctx->tx_obj->tx_command._token_transfer.amount, COIN_AMOUNT_DECIMAL_PLACES, "", COIN_TICKER,
                        outVal, outValLen, pageIdx, pageCount);

        }

        case TOKEN_TRANSFER_RX_ADDRESS_TYPE: {
            _encodeAddressHash((uint8_t *) buf, sizeof(buf),(const uint8_t *) ctx->tx_obj->tx_command._token_transfer.recipientAddress);
            snprintf(outKey, outKeyLen, "RxAddress");
            pageString(outVal, outValLen, (const char*) &buf, pageIdx, pageCount);
            return parser_ok;
        }

        case TOKEN_TRANSFER_ACCNT_INIT_FEE_TYPE: {
            snprintf(outKey, outKeyLen, "AcntInitFee");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->tx_command._token_transfer.accountInitializationFee) != NULL) {
                return parser_unexpected_error;
            }
            return parser_ok;
        }

        case TOKEN_TRANSFER_DATA_TYPE: {
            MEMCPY(buf, ctx->tx_obj->tx_command._token_transfer.data, ctx->tx_obj->tx_command._token_transfer.dataLength);
            snprintf(outKey, outKeyLen, "Data");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        }

        default:
            break;
    }

    return parser_display_idx_out_of_range;
}

parser_error_t print_module_token_cross(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {

    *pageCount = 1;
    char buf[DATA_MAX_LENGTH] = {0};

    switch (displayIdx)
    {
        case TOKEN_CROSSCHAIN_TOKEN_ID_TYPE: {
            array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->tx_command._token_crosschain_transfer.tokenid,TOKEN_ID_LENGTH);
            snprintf(outKey, outKeyLen, "TokenID");
            pageString(outVal, outValLen, (const char*) &buf, pageIdx, pageCount);

            return parser_ok;
        }

        case TOKEN_CROSSCHAIN_AMOUNT_TYPE: {
            snprintf(outKey, outKeyLen, "Amount");
            return _toStringBalance(&ctx->tx_obj->tx_command._token_transfer.amount, COIN_AMOUNT_DECIMAL_PLACES, "", COIN_TICKER,
                        outVal, outValLen, pageIdx, pageCount);
        }

        case TOKEN_CROSSCHAIN_RX_ADDRESS_TYPE: {
            _encodeAddressHash((uint8_t *) buf, sizeof(buf), (const uint8_t *) ctx->tx_obj->tx_command._token_crosschain_transfer.recipientAddress);
            snprintf(outKey, outKeyLen, "RxAddress");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        }

        case TOKEN_CROSSCHAIN_RX_CHAIN_ID_TYPE: {
            memset(buf, 0, sizeof(buf));
            array_to_hexstr((char*) &buf, sizeof(buf), ctx->tx_obj->tx_command._token_crosschain_transfer.receivingChainID, CHAIN_ID_LENGTH);
            snprintf(outKey, outKeyLen, "RxChainID");
            pageString(outVal, outValLen, (const char*) &buf, pageIdx, pageCount);
            return parser_ok;
        }

        case TOKEN_CROSSCHAIN_ESCROW_FEE_TYPE: {
            snprintf(outKey, outKeyLen, "EscrowInitFee");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->tx_command._token_crosschain_transfer.escrowInitializationFee) != NULL) {
                return parser_unexpected_error;
            }
            return parser_ok;
        }

        case TOKEN_CROSSCHAIN_MSG_FEE_TYPE: {
            snprintf(outKey, outKeyLen, "MsgFee");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->tx_command._token_crosschain_transfer.messageFee) != NULL) {
                return parser_unexpected_error;
            }
            return parser_ok;
        }

        case TOKEN_CROSSCHAIN_DATA_TYPE: {
            MEMCPY(buf, ctx->tx_obj->tx_command._token_crosschain_transfer.data, ctx->tx_obj->tx_command._token_crosschain_transfer.dataLength);
            snprintf(outKey, outKeyLen, "Data");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        }
    }

    return parser_display_idx_out_of_range;
}
