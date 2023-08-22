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

static parser_error_t parse_reg_multisign_group(parser_context_t *ctx, tx_command_auth_multisig_group_t *transfer) {

    uint64_t n_sigs = 0;
    uint64_t tmp64 = 0;
    uint64_t keytype = 0x0;

    // Read number of signatures
    GET_KEY_AND_VARUINT(ctx, tmp64);
    if (tmp64 > UINT32_MAX ) {
        return parser_unexpected_value;
    }
    transfer->n_signatures = (uint32_t) tmp64;
    display_item(AUTH_MULTI_NSIGS_TYPE,1);

    //Read binary key then mandatory keys
    transfer->n_mandatoryKeys = 0;
    transfer->n_optionalKeys = 0;

    //get first key type and save first key pointer
    CHECK_ERROR(_readUnsignedVarint(ctx, &keytype))
    CHECK_ERROR(_readUnsignedVarint(ctx, &tmp64))
    transfer->mandatoryKeys = ctx->buffer + ctx->offset;
    while (keytype == 0x12) {
        //check key availability
        CHECK_ERROR(_verifyBytes(ctx, ED25519_PUBLIC_KEY_LENGTH))
        if(transfer->n_mandatoryKeys > MAX_NUMBER_OF_KEYS) {
            return parser_unexpected_value;
        }
        transfer->n_mandatoryKeys++;
        //move on to next key
        CHECK_ERROR(_readUnsignedVarint(ctx, &keytype))
        CHECK_ERROR(_readUnsignedVarint(ctx, &tmp64))
    }
    display_item(AUTH_MULTI_KEY_TYPE,transfer->n_mandatoryKeys);

    //save first optional key pointer
    transfer->optionalKeys = ctx->buffer + ctx->offset;
    while (keytype == 0x1a) {
        //check key availability
        CHECK_ERROR(_verifyBytes(ctx, ED25519_PUBLIC_KEY_LENGTH))
        if(transfer->n_optionalKeys > MAX_NUMBER_OF_KEYS) {
            return parser_unexpected_value;
        }
        transfer->n_optionalKeys++;
        //move on to next key
        CHECK_ERROR(_readUnsignedVarint(ctx, &keytype))
        CHECK_ERROR(_readUnsignedVarint(ctx, &tmp64))
    }
    display_item(AUTH_MULTI_OPTKEY_TYPE,transfer->n_optionalKeys);

    if((transfer->n_mandatoryKeys + transfer->n_optionalKeys) > MAX_NUMBER_OF_SIGNATURES) {
        return parser_unexpected_value;
    }

    transfer->signatures = ctx->buffer + ctx->offset;
    while (n_sigs < (transfer->n_mandatoryKeys + transfer->n_optionalKeys)) {
        //check sig availability
        CHECK_ERROR(_verifyBytes(ctx, ED25519_SIGNATURE_LENGTH))
        n_sigs++;
        if(ctx->bufferLen == ctx->offset) break;
        //move on to next sig
        GET_KEY_AND_VARUINT(ctx,tmp64)
    }
    if(app_mode_expert()) {
        display_item(AUTH_MULTI_SIG_TYPE,transfer->n_mandatoryKeys + transfer->n_optionalKeys);
    }

    return parser_ok;
}

parser_error_t parse_auth_module(parser_context_t *ctx, parser_tx_t *tx_obj) {

    if (tx_obj->command_id != TX_COMMAND_ID_REGISTER_MULTISIG_GROUP) {
        return parser_unexpected_method;
    }
    CHECK_ERROR(parse_reg_multisign_group(ctx, &tx_obj->tx_command._reg_multisign_group))

    return parser_ok;
}



parser_error_t print_module_auth_reg(const parser_context_t *ctx,
                                  uint8_t displayIdx, uint8_t displayType,
                                  char *outKey, uint16_t outKeyLen,
                                  char *outVal, uint16_t outValLen,
                                  uint8_t pageIdx, uint8_t *pageCount) {

    *pageCount = 1;
    char element_str[65] = {0};
    char sig_str[200] = {0};
    switch (displayType) {
        case AUTH_MULTI_NSIGS_TYPE: {
            snprintf(outKey, outKeyLen, "NSignatures");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->tx_command._reg_multisign_group.n_signatures) != NULL) {
                return parser_unexpected_error;
            }
            return parser_ok;
        }

        case AUTH_MULTI_KEY_TYPE: {
            const uint8_t tmpIdx = displayIdx - 1;
            snprintf(outKey, outKeyLen, "Key %d", tmpIdx);
            array_to_hexstr((char*) &element_str, sizeof(element_str), ctx->tx_obj->tx_command._reg_multisign_group.mandatoryKeys+(tmpIdx*(2+ ED25519_PUBLIC_KEY_LENGTH)),
            ED25519_PUBLIC_KEY_LENGTH);
            pageString(outVal, outValLen, (const char*) &element_str, pageIdx, pageCount);
            return parser_ok;
        }

        case AUTH_MULTI_OPTKEY_TYPE: {
            const uint8_t tmpIdx = (displayIdx - ctx->tx_obj->tx_command._reg_multisign_group.n_mandatoryKeys) - 1;
            snprintf(outKey, outKeyLen, "OptKey %d", tmpIdx);
            array_to_hexstr((char*) &element_str, sizeof(element_str), ctx->tx_obj->tx_command._reg_multisign_group.optionalKeys+(tmpIdx*(2+ ED25519_PUBLIC_KEY_LENGTH)),
            ED25519_PUBLIC_KEY_LENGTH);
            pageString(outVal, outValLen, (const char*) &element_str, pageIdx, pageCount);
            return parser_ok;
        }

        case AUTH_MULTI_SIG_TYPE: {
            const uint8_t tmpIdx = (displayIdx - ctx->tx_obj->tx_command._reg_multisign_group.n_mandatoryKeys - ctx->tx_obj->tx_command._reg_multisign_group.n_optionalKeys) - 1;
            snprintf(outKey, outKeyLen, "Sign %d", tmpIdx);
            array_to_hexstr((char*) &sig_str, sizeof(sig_str), ctx->tx_obj->tx_command._reg_multisign_group.signatures+(tmpIdx*(2+ ED25519_SIGNATURE_LENGTH)),ED25519_SIGNATURE_LENGTH);
            pageString(outVal, outValLen, (const char*) &sig_str, pageIdx, pageCount);
            return parser_ok;
        }
        default:
            break;
    }

    return parser_display_idx_out_of_range;
}
