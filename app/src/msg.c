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
#include "zxerror.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "app_mode.h"
#include "crypto.h"
#include "parser_utils.h"
#include "crypto_helper.h"
#include "tx.h"

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

    if(messageLength == 0) {
        return zxerr_no_data;
    }

     switch (displayIdx) {
         case 0: {
            snprintf(outKey, outKeyLen, "Msg hex");
            uint8_t npc = 0; //Non Printable Chars Counter
            
            for (uint8_t i=0; i < messageLength; i++) {
                npc += IS_PRINTABLE(message[i]) ?
                    0 /* Printable Char */:
                    1 /* Non Printable Char */;
            }

            // msg in hex in case >= than 40% is non printable
            // or first char is not printable.
            if ((npc*100) / messageLength >= 40 || ! IS_PRINTABLE(message[0])) {
                pageStringHex(outVal, outValLen, (const char*)message, messageLength, pageIdx, pageCount);
                return zxerr_ok;
            }

            //print message
            snprintf(outKey, outKeyLen, "Msg");
            pageStringExt(outVal, outValLen, (const char*)message, messageLength, pageIdx, pageCount);
            return zxerr_ok;
         }
         default:
             return zxerr_no_data;
     }

}
