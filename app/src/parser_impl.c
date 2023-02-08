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

#include "parser_impl.h"
#include "parser_utils.h"
#include "txn_token_module.h"
#include "txn_auth_module.h"
#include "txn_legacy_module.h"
#include "txn_pos_module.h"
#include "txn_interop_module.h"
#include "app_mode.h"

static uint8_t tx_num_items;

#define MAX_PARAM_SIZE 12
#define MAX_ITEM_ARRAY 128
static uint8_t itemArray[MAX_ITEM_ARRAY] = {0};
static uint8_t itemIndex = 0;


static const string_subst_t module_substitutions[] = {
        {"token",   0},
        {"auth",    1},
        {"pos",     2},
        {"legacy",  3},
        {"interoperability", 4}
};
static const string_subst_t command_substitutions[] = {
        {"transfer",                        0},
        {"transferCrossChain",              1},
        {"registerMultisignature",          0},
        {"registerValidator",               0},
        {"stake",                           1},
        {"unlock",                          2},
        {"reportMisbehavior",               3},
        {"claimRewards",                    4},
        {"changeCommission",                5},
        {"reclaimLSK",                      0},
        {"registerKeys",                    1},

        {"submitMainchainCrossChainUpdate", 0},
        {"submitSidechainCrossChainUpdate", 1},
        {"registerMainchain",               2},
        {"recoverMessage",                  3},
        {"initializeMessageRecovery",       4},
        {"registerSidechain",               5},
        {"recoverState",                    6},
        {"initializeStateRecovery",         7},

};

static parser_error_t find_id(parser_tx_t *tx_obj,uint8_t* module, uint8_t module_length, uint8_t* command, uint8_t command_length) {

    uint32_t i = 0;

    if(command_length == 0 || module_length ==0) {
        return parser_unexpected_value;
    }

    for (i = 0; i < array_length(module_substitutions); i++) {
        const char *substStr = module_substitutions[i].name;
        if (strlen(substStr) == module_length && !MEMCMP(substStr, module, module_length)) {
            tx_obj->module_id = module_substitutions[i].id;
            break;
        }
    }
    
    if(i == array_length(module_substitutions)) return parser_unexpected_value;

    for (i = 0; i < array_length(command_substitutions); i++) {
        const char *substStr = command_substitutions[i].name;
        if (strlen(substStr) == command_length && !MEMCMP(substStr, command, command_length)) {
            tx_obj->command_id = command_substitutions[i].id;
            break;
        }
    }

    if(i == array_length(command_substitutions)) return parser_unexpected_value;

    return parser_ok;
}

uint8_t _getTxNumItems() {
    return tx_num_items;
}

parser_error_t initializeItemArray() {
    for(uint8_t i = 0; i < MAX_ITEM_ARRAY; i++) {
        itemArray[i] = 0xFF;
    }
    itemIndex = 0;
    tx_num_items=0;
    return parser_ok;
}

parser_error_t display_item(uint8_t type, uint8_t len) {
    for(uint8_t i = 0; i < len; i++) {
        CHECK_ERROR(addItem(type))          
        tx_num_items++;                   
    }
    return parser_ok;
}

parser_error_t addItem(uint8_t displayIdx) {
    if(itemIndex >= MAX_ITEM_ARRAY) {
        return parser_unexpected_buffer_end;
    }
    itemArray[itemIndex] = displayIdx;
    itemIndex++;

    return parser_ok;
}

parser_error_t getItem(uint8_t index, uint8_t* displayIdx) {
    if(index >= itemIndex) {
        return parser_display_page_out_of_range;
    }
    *displayIdx = itemArray[index];
    return parser_ok;
}

static parser_error_t parse_common(parser_context_t *ctx, parser_tx_t *tx_obj) {

    uint64_t tmp64 = 0;
    uint8_t module_length = 0;
    uint8_t command_length = 0;
    uint8_t module [32] = {0};
    uint8_t command [32] = {0};
    uint8_t tmpByte = 0;

    //Read Module
    CHECK_ERROR(_readBytes(ctx, &tmpByte, 1))
    CHECK_ERROR(_readBytes(ctx, &module_length, 1))
    if ( module_length > MAX_MODULE_NAME_LENGTH || module_length < MIN_MODULE_NAME_LENGTH) {
        return parser_value_out_of_range;
    }
    CHECK_ERROR(_readBytes(ctx, module, module_length))

    //Read Command
    CHECK_ERROR(_readBytes(ctx, &tmpByte, 1))
    CHECK_ERROR(_readBytes(ctx, &command_length, 1))
    if ( command_length > MAX_COMMAND_NAME_LENGTH || command_length < MIN_COMMAND_NAME_LENGTH) {
        return parser_value_out_of_range;
    }
    CHECK_ERROR(_readBytes(ctx, command, command_length))

    // Find module and command ID
    CHECK_ERROR(find_id(tx_obj, module, module_length, command, command_length));

    //Read binary key then nonce
    GET_KEY_AND_VARUINT(ctx, tmp64);
    tx_obj->nonce = tmp64;

    //Read binary key then fee
    GET_KEY_AND_VARUINT(ctx, tmp64);
    tx_obj->fee = tmp64;

    //Read binary key then pubkey size then pubkey
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if ((uint32_t)tmp64 != ENCODED_PUB_KEY) {
        return parser_value_out_of_range;
    }

    CHECK_ERROR(_readBytes(ctx, tx_obj->senderPublicKey, ENCODED_PUB_KEY))

    return parser_ok;
}

uint8_t _getNumCommonItems() {
    // Display nonce only for expert mode
    return 3 + (app_mode_expert() ? 1 : 0);
}

uint8_t _getNumItems(const parser_context_t *ctx) {
    uint8_t items = _getNumCommonItems();
    uint8_t dataItem = 0;

    switch (ctx->tx_obj->module_id) {
        case TX_MODULE_ID_TOKEN: {
            switch (ctx->tx_obj->command_id ) {
                case TX_COMMAND_ID_TRANSFER:
                    dataItem = (ctx->tx_obj->tx_command._token_transfer.dataLength > 0 && app_mode_expert()) ? 1 : 0;
                    items += 3 + dataItem;
                    break;
                case TX_COMMAND_ID_CROSSCHAIN_TRANSFER:
                    dataItem = (ctx->tx_obj->tx_command._token_crosschain_transfer.dataLength > 0 && app_mode_expert()) ? 1 : 0;
                    items += 4 + dataItem + ((app_mode_expert()) ? 2 : 0);
                    break;
                default:
                    items = 0;
            }
            break;
        }

        case TX_MODULE_ID_AUTH:
                items += _getTxNumItems();
            break;

        case TX_MODULE_ID_POS: {
            switch (ctx->tx_obj->command_id ) {
                case TX_COMMAND_ID_REGISTER_VALIDATOR:
                    items += 1 + (app_mode_expert() ? 3 : 0);
                    break;
                case TX_COMMAND_ID_STAKE:
                    items += _getTxNumItems();
                    break;
                case TX_COMMAND_ID_UNLOCK:
                case TX_COMMAND_ID_REPORT_MISBEHAVIOUR:
                case TX_COMMAND_ID_CLAIM_REWARDS:
                    items += 0;
                    break;
                case TX_COMMAND_ID_CHANGE_COMMISSION:
                    items += 1;
                    break;
                default:
                    items = 0;
            }
            break;
        }
        case TX_MODULE_ID_LEGACY:
            switch (ctx->tx_obj->command_id ) {
                case TX_COMMAND_ID_RECLAIM:
                    items += 1;
                    break;
                case TX_COMMAND_ID_REGISTER_KEYS:
                    items += (app_mode_expert() ? 3 : 0);
            }
            break;

        case TX_MODULE_ID_INTEROP: {
            switch (ctx->tx_obj->command_id ) {
                case TX_COMMAND_ID_MAINCHAIN_CC_UPDATE:
                case TX_COMMAND_ID_SIDECHAIN_CC_UPDATE:
                case TX_COMMAND_ID_MSG_RECOVERY:
                case TX_COMMAND_ID_MSG_RECOVERY_INIT:
                case TX_COMMAND_ID_STATE_RECOVERY_INIT:
                    items += 1;
                    break;
                case TX_COMMAND_ID_MAINCHAIN_REG:
                case TX_COMMAND_ID_STATE_RECOVERY:
                    items += 2;
                    break;
                case TX_COMMAND_ID_SIDECHAIN_REG:
                    items += 1 + (app_mode_expert() ? 1 : 0);
                    break;
                default:
                    items = 0;
            }
            break;
        }
        default:
            items = 0;
            break;
    }

    return items;
}

parser_error_t _read(parser_context_t *ctx, parser_tx_t *tx_obj) {
    CHECK_ERROR(parse_common(ctx, tx_obj))
    CHECK_ERROR(initializeItemArray()) 
    switch (tx_obj->module_id) {
        case TX_MODULE_ID_TOKEN:
            CHECK_ERROR(parse_token_module(ctx, tx_obj))
            break;

        case TX_MODULE_ID_AUTH:
            CHECK_ERROR(parse_auth_module(ctx, tx_obj))
            break;

        case TX_MODULE_ID_POS:
            CHECK_ERROR(parse_pos_module(ctx, tx_obj))
            break;

        case TX_MODULE_ID_LEGACY:
             CHECK_ERROR(parse_legacy_module(ctx, tx_obj))
            break;

        case TX_MODULE_ID_INTEROP:
            CHECK_ERROR(parse_interop_module(ctx, tx_obj))
            break;

        default:
            return parser_unexpected_type;
    }

    if (ctx->offset != ctx->bufferLen) {
        return parser_unexpected_unparsed_bytes;
    }

    return parser_ok;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_version:
            return "Unexpected version";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_duplicated_field:
            return "Unexpected duplicated field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_unexpected_chain:
            return "Unexpected chain";
        case parser_missing_field:
            return "missing field";
        case parser_display_idx_out_of_range:
            return "display index out of range";
        case parser_display_page_out_of_range:
            return "display page out of range";

        default:
            return "Unrecognized error code";
    }
}
