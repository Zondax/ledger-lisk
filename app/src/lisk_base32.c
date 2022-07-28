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

#include "lisk_base32.h"
#include "zxmacros.h"

static const char* liskBase32 = "zxvcpmbn3465o978uyrtkqew2adsjhfg";

uint8_t lisk_base32_encode(const uint8_t *input, const uint8_t inputLen,
                            uint8_t *output, uint8_t outputLen) {

    if (!inputLen && inputLen > outputLen) {
        return 0;
    }
    for(uint8_t i = 0; i < inputLen; i++) {
        if(input[i] > 0x1F) {
            return 0;
        }
        output[i] = ((const char*)PIC(liskBase32))[input[i]];
    }

    return inputLen;
}
