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
#include "parser_impl.h"
#include "app_mode.h"

static parser_error_t parse_chainCCUpdate(parser_context_t *ctx, tx_command_interop_chain_cc_update_t *transfer) {
    
    uint64_t tmp64 = 0;

    // commands is serialized as bytes, varint first for the size
    GET_KEY_AND_VARUINT(ctx, tmp64);

    //Read sending chain ID
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != SENDINGCHAIN_ID_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->sendingChainID = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, SENDINGCHAIN_ID_LENGTH))

    while(ctx->offset < ctx->bufferLen) {
         _verifyBytes(ctx,1);
    }

    return parser_ok;
}

static parser_error_t parse_mainchain_register(parser_context_t *ctx, tx_command_interop_mainchain_register_t *transfer) {
    
    uint64_t tmp64 = 0;

    // commands is serialized as bytes, varint first for the size
    GET_KEY_AND_VARUINT(ctx, tmp64);

    //Read sending chain ID
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != OWNCHAIN_ID_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->ownChainId = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, OWNCHAIN_ID_LENGTH))

    // Read name size and name
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 == 0 || tmp64 > DATA_MAX_LENGTH) {
        return parser_value_out_of_range;
    }
    transfer->ownNameLen = tmp64;
    transfer->ownName = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, tmp64))

    while(ctx->offset < ctx->bufferLen) {
         _verifyBytes(ctx,1);
    }

    return parser_ok;
}

static parser_error_t parse_recover_msg(parser_context_t *ctx, tx_command_interop_recover_msg_t *transfer) {
    
    uint64_t tmp64 = 0;

    // commands is serialized as bytes, varint first for the size
    GET_KEY_AND_VARUINT(ctx, tmp64);

    //Read sending chain ID
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != INTEROP_CHAINID_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->chainID = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, INTEROP_CHAINID_LENGTH))

    while(ctx->offset < ctx->bufferLen) {
         _verifyBytes(ctx,1);
    }

    return parser_ok;
}

static parser_error_t parse_recover_msg_init(parser_context_t *ctx, tx_command_interop_recover_msg_init_t *transfer) {
    
    uint64_t tmp64 = 0;

    // commands is serialized as bytes, varint first for the size
    GET_KEY_AND_VARUINT(ctx, tmp64);

    //Read sending chain ID
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != INTEROP_CHAINID_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->chainID = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, INTEROP_CHAINID_LENGTH))

    while(ctx->offset < ctx->bufferLen) {
         _verifyBytes(ctx,1);
    }

    return parser_ok;
}

static parser_error_t parse_sidechain_register(parser_context_t *ctx, tx_command_interop_sidechain_register_t *transfer) {
    
    
    uint64_t tmp64 = 0;

    // commands is serialized as bytes, varint first for the size
    GET_KEY_AND_VARUINT(ctx, tmp64);

    //Read sending chain ID
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != OWNCHAIN_ID_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->chainID = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, OWNCHAIN_ID_LENGTH))

    // Read name size and name
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 == 0 || tmp64 > DATA_MAX_LENGTH) {
        return parser_value_out_of_range;
    }
    transfer->nameLen = tmp64;
    transfer->name = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, tmp64))

    while(ctx->offset < ctx->bufferLen) {
         _verifyBytes(ctx,1);
    }

    return parser_ok;
}

static parser_error_t parse_recover_state_init(parser_context_t *ctx, tx_command_interop_recover_state_init_t *transfer) {
    
    uint64_t tmp64 = 0;

    // commands is serialized as bytes, varint first for the size
    GET_KEY_AND_VARUINT(ctx, tmp64);

    //Read sending chain ID
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != INTEROP_CHAINID_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->chainID = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, INTEROP_CHAINID_LENGTH))

    while(ctx->offset < ctx->bufferLen) {
         _verifyBytes(ctx,1);
    }

    return parser_ok;
}

static parser_error_t parse_recover_state(parser_context_t *ctx, tx_command_interop_recover_state_t *transfer) {
    
    uint64_t tmp64 = 0;

    // commands is serialized as bytes, varint first for the size
    GET_KEY_AND_VARUINT(ctx, tmp64);

    //Read sending chain ID
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 != INTEROP_CHAINID_LENGTH) {
        return parser_unexpected_value;
    }
    transfer->chainID = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, INTEROP_CHAINID_LENGTH))

    // Read name size and name
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 == 0 || tmp64 > DATA_MAX_LENGTH) {
        return parser_value_out_of_range;
    }
    transfer->moduleLen = tmp64;
    transfer->module = ctx->buffer + ctx->offset;
    CHECK_ERROR(_verifyBytes(ctx, tmp64))

    while(ctx->offset < ctx->bufferLen) {
         _verifyBytes(ctx,1);
    }

    return parser_ok;
}

parser_error_t parse_interop_module(parser_context_t *ctx, parser_tx_t *tx_obj) {

    switch (tx_obj->command_id) {
        case TX_COMMAND_ID_MAINCHAIN_CC_UPDATE:
        case TX_COMMAND_ID_SIDECHAIN_CC_UPDATE:
            CHECK_ERROR(parse_chainCCUpdate(ctx, &tx_obj->tx_command._interop_chain_cc_update))
            break;
        case TX_COMMAND_ID_MAINCHAIN_REG:
             CHECK_ERROR(parse_mainchain_register(ctx, &tx_obj->tx_command._interop_mainchain_register))
             break;
        case TX_COMMAND_ID_MSG_RECOVERY:
            CHECK_ERROR(parse_recover_msg(ctx, &tx_obj->tx_command._interpo_recover_msg))
            break;
        case TX_COMMAND_ID_MSG_RECOVERY_INIT:
            CHECK_ERROR(parse_recover_msg_init(ctx, &tx_obj->tx_command._interpo_recover_msg_init))
            break;
        case TX_COMMAND_ID_SIDECHAIN_REG:
            CHECK_ERROR(parse_sidechain_register(ctx, &tx_obj->tx_command._interop_sidechain_register))
            break;
        case TX_COMMAND_ID_STATE_RECOVERY:
            CHECK_ERROR(parse_recover_state(ctx, &tx_obj->tx_command._interop_recover_state))
            break;
        case TX_COMMAND_ID_STATE_RECOVERY_INIT:
            CHECK_ERROR(parse_recover_state_init(ctx, &tx_obj->tx_command._interop_recover_state_init))
            break;
        default:
            return parser_unexpected_method;
    }

    return parser_ok;
}

parser_error_t print_module_interop_CCupdate(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    char buf[DATA_MAX_LENGTH] = {0};
    if(displayIdx == 0) {
        snprintf(outKey, outKeyLen, "SendingChainID");
           array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->tx_command._interop_chain_cc_update.sendingChainID,SENDINGCHAIN_ID_LENGTH);
           pageString(outVal, outValLen, (const char*) &buf, pageIdx, pageCount);

        return parser_ok;
    }
    return parser_display_idx_out_of_range;
}

parser_error_t print_module_mainchain_register(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    char buf[DATA_MAX_LENGTH] = {0};

    switch (displayIdx) {
        case INTEROP_MAIN_REG_OWNCHAIN_ID_TYPE:
            snprintf(outKey, outKeyLen, "OwnChainID");
            array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->tx_command._interop_mainchain_register.ownChainId,OWNCHAIN_ID_LENGTH);
            pageString(outVal, outValLen, (const char*) &buf, pageIdx, pageCount);
            return parser_ok;

        case INTEROP_MAIN_REG_OWNNAME_TYPE:
            MEMCPY(buf, ctx->tx_obj->tx_command._interop_mainchain_register.ownName, ctx->tx_obj->tx_command._interop_mainchain_register.ownNameLen);
            snprintf(outKey, outKeyLen, "OwnName");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        default:
            break;
    }

    return parser_display_idx_out_of_range;
}

parser_error_t print_module_sidechain_register(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    char buf[DATA_MAX_LENGTH] = {0};

    switch (displayIdx) {
        case INTEROP_SIDE_REG_CHAIN_ID_TYPE:
            snprintf(outKey, outKeyLen, "ChainID");
            array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->tx_command._interop_sidechain_register.chainID,INTEROP_CHAINID_LENGTH);
            pageString(outVal, outValLen, (const char*) &buf, pageIdx, pageCount);
            return parser_ok;

        case INTEROP_SIDE_REG_NAME_TYPE:
            MEMCPY(buf, ctx->tx_obj->tx_command._interop_sidechain_register.name, ctx->tx_obj->tx_command._interop_sidechain_register.nameLen);
            snprintf(outKey, outKeyLen, "Name");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        default:
            break;
    }

    return parser_display_idx_out_of_range;
}

static const uint8_t *_getChainId(const parser_context_t *ctx) {
    
    switch (ctx->tx_obj->command_id) {
        case TX_COMMAND_ID_MSG_RECOVERY:
            return ctx->tx_obj->tx_command._interpo_recover_msg.chainID;
        case TX_COMMAND_ID_MSG_RECOVERY_INIT:
            return ctx->tx_obj->tx_command._interop_recover_state_init.chainID;
        case TX_COMMAND_ID_STATE_RECOVERY_INIT:
            return ctx->tx_obj->tx_command._interop_recover_state_init.chainID;
    default:
        break;
    }
    return NULL;
}

parser_error_t print_module_interop_chainID(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    char buf[DATA_MAX_LENGTH] = {0};
    const uint8_t *chainId;

    if(displayIdx == 0) {
        snprintf(outKey, outKeyLen, "ChainID");
        chainId= _getChainId(ctx);
        if (chainId == NULL) {
            return parser_unexpected_method;
        }
        array_to_hexstr(buf, sizeof(buf), chainId ,INTEROP_CHAINID_LENGTH);
        pageString(outVal, outValLen, (const char*) &buf, pageIdx, pageCount);

        return parser_ok;
    }
    return parser_display_idx_out_of_range;
}

parser_error_t print_module_state_recover(const parser_context_t *ctx,
                                  uint8_t displayIdx,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {
    *pageCount = 1;
    char buf[DATA_MAX_LENGTH] = {0};

    switch (displayIdx) {
        case INTEROP_MAIN_REG_OWNCHAIN_ID_TYPE:
            snprintf(outKey, outKeyLen, "ChainID");
            array_to_hexstr(buf, sizeof(buf), ctx->tx_obj->tx_command._interop_recover_state.chainID,OWNCHAIN_ID_LENGTH);
            pageString(outVal, outValLen, (const char*) &buf, pageIdx, pageCount);
            return parser_ok;

        case INTEROP_MAIN_REG_OWNNAME_TYPE:
            MEMCPY(buf, ctx->tx_obj->tx_command._interop_recover_state.module, ctx->tx_obj->tx_command._interop_recover_state.moduleLen);
            snprintf(outKey, outKeyLen, "Module");
            pageString(outVal, outValLen, buf, pageIdx, pageCount);
            return parser_ok;
        default:
            break;
    }

    return parser_display_idx_out_of_range;
}