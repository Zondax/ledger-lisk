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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define ENCODED_PUB_KEY 32
#define ADDRESS_HASH_LENGTH 20 // sha256(pubkey) -> first 20 bytes
#define ADDRESS_LISK32_LENGTH 41 // "lsk" + lisk32 encoded

#define DATA_MAX_LENGTH 65 //200 // data field max 64 utf8 char. let's be conservative
#define DELEGATE_MAX_LENGTH 21 //80 // max 20 utf8 chars. let's be conservative

#define NETWORK_ID_LENGTH 32

typedef struct tx_asset_2_0_transfer {
  uint64_t amount;
  unsigned char recipientAddress[ADDRESS_HASH_LENGTH];
  unsigned char data[DATA_MAX_LENGTH];
  uint32_t dataLength;
} tx_asset_2_0_transfer_t;

typedef struct tx_asset_5_0_register_delegate {
  unsigned char delegate[DELEGATE_MAX_LENGTH];
  uint32_t delegateLength;
} tx_asset_5_0_register_delegate_t;

typedef struct tx_asset_4_0_reg_multisign {
  uint32_t n_keys;
  uint32_t n_mandatoryKeys;
  uint32_t n_optionalKeys;
} tx_asset_4_0_reg_multisign_t;

typedef struct tx_asset_5_1_vote_delegate {
  uint32_t n_vote;
  uint32_t n_unvote;
  uint64_t totAmountVote;
  uint64_t totAmountUnVote;
  uint32_t lastObjectSize;
} tx_asset_5_1_vote_delegate_t;

typedef struct tx_asset_5_2_unlock_token {
  uint32_t n_unlock;
  uint64_t totAmountUnlock;
  uint32_t lastObjectSize;
} tx_asset_5_2_unlock_token_t;

typedef struct tx_asset_1000_0_reclaim {
  uint64_t amount;
} tx_asset_1000_0_reclaim_t;

typedef union tx_asset {
  tx_asset_2_0_transfer_t _2_0_transfer;
  tx_asset_4_0_reg_multisign_t _4_0_reg_multisig;
  tx_asset_5_0_register_delegate_t _5_0_reg_delegate;
  tx_asset_5_1_vote_delegate_t _5_1_vote_delegate;
  tx_asset_5_2_unlock_token_t _5_2_unlock_token;
  tx_asset_1000_0_reclaim_t _1000_0_reclaim;
  // TODO
} tx_asset_t;

typedef struct{
    // Common fields
    uint8_t network_id[NETWORK_ID_LENGTH];

    uint32_t module_id;
    uint32_t asset_id;
    uint64_t nonce;
    uint64_t fee;
    unsigned char senderPublicKey[ENCODED_PUB_KEY];

    tx_asset_t tx_asset;

} parser_tx_t;


#ifdef __cplusplus
}
#endif
