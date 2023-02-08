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
#include "parser_impl.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "coin.h"

static parser_error_t parse_reg_validator(parser_context_t *ctx, tx_command_pos_reg_validator_t *transfer) {

    uint64_t tmp64 = 0;

    GET_KEY_AND_VARUINT(ctx, tmp64);

    // Read name size and name
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 == 0 || tmp64 > DATA_MAX_LENGTH) {
        return parser_value_out_of_range;
    }
    transfer->nameLength = tmp64;
    transfer->name = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, tmp64))

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

static parser_error_t parse_stake(parser_context_t *ctx, tx_command_pos_stake_t *transfer) {

    uint64_t tmp64 = 0;
    int64_t stmp64 = 0;
    int64_t mod_stmp64 = 0;

    GET_KEY_AND_VARUINT(ctx, tmp64);

    transfer->start = ctx->buffer + ctx->offset;
    while(ctx->offset < ctx->bufferLen) {
        // Get stake size
        GET_KEY_AND_VARUINT(ctx, tmp64);
        transfer->stakeSize[transfer->n_stake] = tmp64;

        // Get address size
        GET_KEY_AND_VARUINT(ctx, tmp64);
        if (tmp64 != ADDRESS_HASH_LENGTH) {
            return parser_unexpected_value;
        }
        _verifyBytes(ctx,ADDRESS_HASH_LENGTH);
        display_item(POS_STAKE_ADDRESS_TYPE,1);

        // Get amount
        CHECK_ERROR(_readUnsignedVarint(ctx, &tmp64))
        CHECK_ERROR(_readSignedVarint(ctx, &stmp64))
        mod_stmp64 = (stmp64 < 0 ? -stmp64 : stmp64);

        if(mod_stmp64 == 0 || (mod_stmp64 % BASE_STAKE_AMOUNT != 0)) {
             return parser_unexpected_value;
         }
        transfer->amounts[transfer->n_stake] = stmp64;
        transfer->n_stake++;
        display_item(POS_STAKE_AMOUNT_TYPE,1);

        if(transfer->n_stake > 2*MAX_NUMBER_SENT_STAKES) {
            return parser_unexpected_value;
        }
    }

    return parser_ok;
}

static parser_error_t parse_unlock(parser_context_t *ctx, tx_command_pos_unlock_t *transfer) {

    uint64_t tmp64 = 0;

    //Skip extra bytes
    GET_KEY_AND_VARUINT(ctx, tmp64);

    return parser_ok;
}

static parser_error_t parse_misbehavior(parser_context_t *ctx, tx_command_pos_misbehavior_t *transfer) {

    while(ctx->offset < ctx->bufferLen) {
         _verifyBytes(ctx,1);
    }
    return parser_ok;
}

static parser_error_t parse_claim_rewards(parser_context_t *ctx, tx_command_pos_claim_rewards_t *transfer) {

    while(ctx->offset < ctx->bufferLen) {
         _verifyBytes(ctx,1);
    }
    return parser_ok;
}

static parser_error_t parse_change_comission(parser_context_t *ctx, tx_command_pos_change_commissions_t *transfer) {
    
    uint64_t tmp64 = 0;

    // commands is serialized as bytes, varint first for the size
    GET_KEY_AND_VARUINT(ctx, tmp64);

    // Read newCommission
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 > UINT32_MAX ) {
        return parser_unexpected_value;
    }
    transfer->newCommission = (uint32_t) tmp64;

    return parser_ok;
}

parser_error_t parse_pos_module(parser_context_t *ctx, parser_tx_t *tx_obj) {

    switch (tx_obj->command_id) {
        case TX_COMMAND_ID_REGISTER_VALIDATOR:
            CHECK_ERROR(parse_reg_validator(ctx, &tx_obj->tx_command._pos_reg_validator))
            break;
        case TX_COMMAND_ID_STAKE:
            CHECK_ERROR(parse_stake(ctx, &tx_obj->tx_command._pos_stake))
            break;
        case TX_COMMAND_ID_UNLOCK:
            CHECK_ERROR(parse_unlock(ctx, &tx_obj->tx_command._pos_unlock))
            break;
        case TX_COMMAND_ID_REPORT_MISBEHAVIOUR:
            CHECK_ERROR(parse_misbehavior(ctx, &tx_obj->tx_command._pos_misbehavior))
            break;
        case TX_COMMAND_ID_CLAIM_REWARDS:
            CHECK_ERROR(parse_claim_rewards(ctx, &tx_obj->tx_command._pos_claim_rewards))
            break;
        case TX_COMMAND_ID_CHANGE_COMMISSION:
            CHECK_ERROR(parse_change_comission(ctx, &tx_obj->tx_command._pos_change_commissions))
            break;
        default:
            return parser_unexpected_method;
    }

    return parser_ok;
}

parser_error_t print_module_pos_stake(const parser_context_t *ctx,
                                  uint8_t displayIdx, uint8_t displayType,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {

    *pageCount = 1;
    switch (displayType) {
        case POS_STAKE_ADDRESS_TYPE: {
            const uint8_t tmpIdx = displayIdx/2;
            char addr_str[42] = {0};
            uint32_t stake_offset = 0;

            for(uint8_t i = 0; i < tmpIdx; i++) {
                stake_offset += POS_STAKE_SIZE_OFFSET + ctx->tx_obj->tx_command._pos_stake.stakeSize[i];
            }

            _encodeAddressHash((uint8_t*) &addr_str, sizeof(addr_str),ctx->tx_obj->tx_command._pos_stake.start + POS_STAKE_ADDRESS_OFFSET + stake_offset) ;
    
            snprintf(outKey, outKeyLen, "Stakes %d", tmpIdx);
            pageString(outVal, outValLen, (const char*) &addr_str, pageIdx, pageCount);
            return parser_ok;
        }
        case POS_STAKE_AMOUNT_TYPE: {
            if(displayIdx == 0) return parser_unexpected_value;

            const uint8_t tmpIdx = (displayIdx - 1)/2;
            int64_t tmp64 = (ctx->tx_obj->tx_command._pos_stake.amounts[tmpIdx] < 0) ? -ctx->tx_obj->tx_command._pos_stake.amounts[tmpIdx] : ctx->tx_obj->tx_command._pos_stake.amounts[tmpIdx] ;
            
            snprintf(outKey, outKeyLen, "Stakes %d", tmpIdx);
            return _toStringStakeAmount((uint64_t *)&tmp64, (ctx->tx_obj->tx_command._pos_stake.amounts[tmpIdx] < 0) ? UNSTAKE_COIN_TICKER : COIN_TICKER,
                        outVal, outValLen, pageIdx, pageCount);
        }
        default:
            break;
    }
    return parser_display_idx_out_of_range;
}

parser_error_t print_module_pos_reg_validator(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {

    *pageCount = 1;
    char buf[BLS_POP_LENGTH * 2 + 1] = {0};
    switch (displayIdx) {
        case POS_REG_VALIDATOR_NAME_TYPE: {
            MEMCPY(buf, ctx->tx_obj->tx_command._pos_reg_validator.name, ctx->tx_obj->tx_command._pos_reg_validator.nameLength);
            snprintf(outKey, outKeyLen, "Name");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        }

        case POS_REG_VALIDATOR_GENKEY_TYPE: {
            array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->tx_command._pos_reg_validator.generatorKey,
                            ED25519_PUBLIC_KEY_LENGTH);
            snprintf(outKey, outKeyLen, "GenKey");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        }

        case POS_REG_VALIDATOR_BLSKEY_TYPE: {
            array_to_hexstr(buf, sizeof(buf),ctx->tx_obj->tx_command._pos_reg_validator.blskey,
                            BLS_PUBLIC_KEY_LENGTH);
            snprintf(outKey, outKeyLen, "BlsKey");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        }

        case POS_REG_VALIDATOR_POP_TYPE: {
            array_to_hexstr(buf, sizeof(buf),ctx->tx_obj->tx_command._pos_reg_validator.proofOfPossession,
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

parser_error_t print_module_pos_change_commission(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;

    if(displayIdx == 0) {
        snprintf(outKey, outKeyLen, "NewCommission");
        if (uint64_to_str(outVal, outValLen, ctx->tx_obj->tx_command._pos_change_commissions.newCommission) != NULL) {
            return parser_unexpected_error;
        }
        return parser_ok;
    }
    return parser_display_idx_out_of_range;
}