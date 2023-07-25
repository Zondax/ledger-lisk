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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define CLA                             0x60

#define HDPATH_LEN_DEFAULT   5
#define HDPATH_0_DEFAULT     (0x80000000u | 0x2c)   //44
#define HDPATH_1_DEFAULT     (0x80000000u | 0x86)   //134
#define HDPATH_1_TESTNET     (0x80000000u | 0x1)    //1

#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define INS_SIGN_MSG                    0x03

#define SECP256K1_PK_LEN            65u

#define SK_LEN_25519 64u
#define SCALAR_LEN_ED25519 32u
#define SIG_PLUS_TYPE_LEN 65u

#define PK_LEN_25519 32u
#define LISK32_ADDRESS_LEN 41u

#define MAX_SIGN_SIZE 256u
#define BLAKE2B_DIGEST_SIZE 32u

#define COIN_AMOUNT_DECIMAL_PLACES 8
#define COIN_TICKER "LSK "
#define UNSTAKE_COIN_TICKER "LSK -"
#define COIN_HRP "lsk"
#define TAG_INIT "LSK_TX_"

#define MENU_MAIN_APP_LINE1 "Lisk"
#define MENU_MAIN_APP_LINE2 "Ready"
#define MENU_MAIN_APP_LINE2_SECRET          "???"
#define APPVERSION_LINE1 "Lisk"
#define APPVERSION_LINE2 "v" APPVERSION
#define SIGNED_MESSAGE_PREFIX "Lisk Signed Message:\n"

#ifdef __cplusplus
}
#endif
