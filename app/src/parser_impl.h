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
#pragma once

#include "parser_common.h"
#include <zxmacros.h>
#include "zxtypes.h"
#include "parser_txdef.h"

#ifdef __cplusplus
extern "C" {
#endif

parser_error_t initializeItemArray(void);
parser_error_t display_item(uint8_t type, uint8_t len);
parser_error_t getItem(uint8_t index, uint8_t* displayIdx);
parser_error_t addItem(uint8_t displayIdx);
parser_error_t _read(parser_context_t *c, parser_tx_t *v);
uint8_t _getNumCommonItems();
uint8_t _getTxNumItems();
uint8_t _getNumItems(const parser_context_t *ctx);

#ifdef __cplusplus
}
#endif
