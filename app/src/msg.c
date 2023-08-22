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

#include <stdio.h>
#include "coin.h"
#include "parser_impl.h"
#include "zxerror.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "app_mode.h"
#include "crypto.h"
#include "parser_utils.h"
#include "crypto_helper.h"
#include "tx.h"

const char *msg_parse() {
    const uint8_t *data = tx_get_buffer();
    const size_t dataLen = tx_get_buffer_length();
    if (data == NULL || dataLen == 0) {
        return parser_getErrorDescription(parser_no_data);
    }
    if (MEMCMP(data, TAG_INIT, sizeof(TAG_INIT)) == 0) {
        return parser_getErrorDescription(parser_unexpected_tag_init);
    }
    return NULL;
}

zxerr_t msg_getNumItems(uint8_t *num_items) {
    zemu_log_stack("msg_getNumItems");
    *num_items = 1;
    return zxerr_ok;
}

zxerr_t msg_getItem(int8_t displayIdx,
                     char *outKey, uint16_t outKeyLen,
                     char *outVal, uint16_t outValLen,
                     uint8_t pageIdx, uint8_t *pageCount) {
    ZEMU_LOGF(200, "[msg_getItem] %d/%d\n", displayIdx, pageIdx)

    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
    *pageCount = 1;

    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    if (messageLength == 0) {
        return zxerr_no_data;
    }

    uint8_t tmp_hash[32] = {0};
    crypto_hash(message, messageLength, tmp_hash, sizeof(tmp_hash));

    if (displayIdx == 0) {
        snprintf(outKey, outKeyLen, "Msg sign");
        pageStringHex(outVal, outValLen, (const char*)tmp_hash, sizeof(tmp_hash), pageIdx, pageCount);
        return zxerr_ok;
    }

    return zxerr_no_data;
}
