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

#include "parser_print_items.h"

#include "coin.h"
#include "zxformat.h"
#include "parser_utils.h"
#include "txn_token_module.h"

static parser_error_t print_module(uint32_t module_id, char *outKey,
                                   uint16_t outKeyLen, char *outVal,
                                   uint16_t outValLen, uint8_t *pageCount) {
  *pageCount = 1;
  snprintf(outKey, outKeyLen, "Module");
  switch (module_id) {
    case TX_MODULE_ID_TOKEN:
      snprintf(outVal, outValLen, "token");
      break;

    case TX_MODULE_ID_AUTH:
      snprintf(outVal, outValLen, "auth");
      break;

    case TX_MODULE_ID_POS:
      snprintf(outVal, outValLen, "pos");
      break;

    case TX_MODULE_ID_LEGACY:
      snprintf(outVal, outValLen, "legacy");
      break;

    case TX_MODULE_ID_INTEROP:
      snprintf(outVal, outValLen, "interoperability");
      break;

    default:
      return parser_display_idx_out_of_range;
  }

  return parser_ok;
}

// Print Command ID depending on module_id and command_id inputs
static parser_error_t print_command_id(const uint32_t module_id, const uint32_t command_id,
                                       char *outKey, uint16_t outKeyLen,
                                       char *outVal, uint16_t outValLen) {

  snprintf(outKey, outKeyLen, "Command");

  switch (module_id) {
    case TX_MODULE_ID_TOKEN:
      switch (command_id) {
        case TX_COMMAND_ID_TRANSFER:
          snprintf(outVal, outValLen, "transfer");
          break;
        case TX_COMMAND_ID_CROSSCHAIN_TRANSFER:
          snprintf(outVal, outValLen, "transferCrossChain");
          break;
        default:
          return parser_unexpected_value;
      }
      break;

    case TX_MODULE_ID_AUTH:
      if (command_id != TX_COMMAND_ID_REGISTER_MULTISIG_GROUP) {
        return parser_unexpected_value;
      }
      snprintf(outVal, outValLen, "registerMultisignature");
      break;

    case TX_MODULE_ID_POS:
        switch (command_id) {
            case TX_COMMAND_ID_REGISTER_VALIDATOR:
                snprintf(outVal, outValLen, "registerValidator");
                break;
            case TX_COMMAND_ID_STAKE:
                snprintf(outVal, outValLen, "stake");
                break;
            case TX_COMMAND_ID_UNLOCK:
                snprintf(outVal, outValLen, "unlock");
                break;
            case TX_COMMAND_ID_REPORT_MISBEHAVIOUR:
                snprintf(outVal, outValLen, "reportMisbehavior");
                break;
            case TX_COMMAND_ID_CLAIM_REWARDS:
                snprintf(outVal, outValLen, "claimRewards");
                break;
              case TX_COMMAND_ID_CHANGE_COMMISSION:
                snprintf(outVal, outValLen, "changeCommission");
                break;
            default:
                return parser_unexpected_value;
        }
        break;

    case TX_MODULE_ID_LEGACY:
        switch (command_id) {
          case TX_COMMAND_ID_RECLAIM:
              snprintf(outVal, outValLen, "reclaimLSK");
              break;
          case TX_COMMAND_ID_REGISTER_KEYS:
              snprintf(outVal, outValLen, "registerKeys");
              break;
          default:
              return parser_unexpected_value;
        }
        break;
    case TX_MODULE_ID_INTEROP:
        switch (command_id) {
            case TX_COMMAND_ID_MAINCHAIN_CC_UPDATE:
                snprintf(outVal, outValLen, "submitMainchainCrossChainUpdate");
                break;
            case TX_COMMAND_ID_SIDECHAIN_CC_UPDATE:
                snprintf(outVal, outValLen, "submitSidechainCrossChainUpdate");
                break;
            case TX_COMMAND_ID_MAINCHAIN_REG:
                snprintf(outVal, outValLen, "registerMainchain");
                break;
            case TX_COMMAND_ID_MSG_RECOVERY:
                snprintf(outVal, outValLen, "recoverMessage");
                break;
            case TX_COMMAND_ID_MSG_RECOVERY_INIT:
                snprintf(outVal, outValLen, "initializeMessageRecovery");
                break;
            case TX_COMMAND_ID_SIDECHAIN_REG:
                snprintf(outVal, outValLen, "registerSidechain");
                break;
            case TX_COMMAND_ID_STATE_RECOVERY:
                snprintf(outVal, outValLen, "recoverState");
                break;
            case TX_COMMAND_ID_STATE_RECOVERY_INIT:
                snprintf(outVal, outValLen, "initializeStateRecovery");
                break;
            default:
                return parser_unexpected_value;
        }
        break;

    default:
        return parser_display_idx_out_of_range;
  }

  return parser_ok;
}

parser_error_t print_common_items(const parser_context_t *ctx,
                                  uint8_t displayIdx, char *outKey,
                                  uint16_t outKeyLen, char *outVal,
                                  uint16_t outValLen, uint8_t pageIdx,
                                  uint8_t *pageCount) {
    *pageCount = 1;
    switch (displayIdx) {
        case 0:
            return print_module(ctx->tx_obj->module_id, outKey, outKeyLen, outVal,
                          outValLen, pageCount);

        case 1:
            return print_command_id(ctx->tx_obj->module_id, ctx->tx_obj->command_id,
                              outKey, outKeyLen, outVal, outValLen);

        case 2:
            snprintf(outKey, outKeyLen, "Fee");
            return _toStringBalance(&ctx->tx_obj->fee,
                              COIN_AMOUNT_DECIMAL_PLACES, "", COIN_TICKER,
                              outVal, outValLen, pageIdx, pageCount);

        case 3:
            snprintf(outKey, outKeyLen, "Nonce");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->nonce) != NULL) {
                return parser_unexpected_error;
            }
            return parser_ok;

        default:
            return  parser_unexpected_error;
    }

    return parser_display_idx_out_of_range;
}
