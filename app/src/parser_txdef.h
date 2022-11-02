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
#define MIN_MODULE_NAME_LENGTH 1
#define MAX_MODULE_NAME_LENGTH 32
#define MIN_COMMAND_NAME_LENGTH 1
#define MAX_COMMAND_NAME_LENGTH 32
#define NETWORK_ID_LENGTH 32
#define TOKEN_ID_LENGTH 8
#define CHAIN_ID_LENGTH 4
#define BLS_PUBLIC_KEY_LENGTH 48
#define BLS_POP_LENGTH 96
#define ED25519_PUBLIC_KEY_LENGTH 32
#define ED25519_SIGNATURE_LENGTH 64
#define MAX_NUMBER_OF_SIGNATURES 64
#define MAX_NUMBER_OF_KEYS 64
#define USER_ACCOUNT_INITIALIZATION_FEE 5000000
#define ESCROW_ACCOUNT_INITIALIZATION_FEE 5000000
#define MAX_NUMBER_SENT_VOTES 10
#define BASE_VOTE_AMOUNT 1000000000
#define BASE_VOTE_AMOUNT_DECIMALS 100000000

#define TX_MODULE_ID_TOKEN 0
#define TX_MODULE_ID_AUTH 1
#define TX_MODULE_ID_DPOS 2
#define TX_MODULE_ID_LEGACY 3

#define DPOS_VOTE_SIZE_OFFSET 2
#define DPOS_VOTE_ADDRESS_OFFSET 4

#define TX_COMMAND_ID_TRANSFER 0
#define TX_COMMAND_ID_CROSSCHAIN_TRANSFER 1
#define TX_COMMAND_ID_REGISTER_MULTISIG_GROUP 0
#define TX_COMMAND_ID_REGISTER_DELEGATE 0
#define TX_COMMAND_ID_VOTE_DELEGATE 1
#define TX_COMMAND_ID_UNLOCK_TOKEN 2
#define TX_COMMAND_ID_REPORT_DELEGATE_MISBEHAVIOUR 3
#define TX_COMMAND_ID_RECLAIM 0

#define RECLAIM_AMOUNT_TYPE 0

typedef enum token_transfer_fields {
  TOKEN_TRANSFER_TOKEN_ID_TYPE = 0,
  TOKEN_TRANSFER_AMOUNT_TYPE,
  TOKEN_TRANSFER_RX_ADDRESS_TYPE,
  TOKEN_TRANSFER_ACCNT_INIT_FEE_TYPE,
  TOKEN_TRANSFER_DATA_TYPE,
} token_transfer_fields;

typedef enum token_crosschain_fields {
  TOKEN_CROSSCHAIN_TOKEN_ID_TYPE = 0,
  TOKEN_CROSSCHAIN_AMOUNT_TYPE,
  TOKEN_CROSSCHAIN_RX_ADDRESS_TYPE,
  TOKEN_CROSSCHAIN_RX_CHAIN_ID_TYPE,
  TOKEN_CROSSCHAIN_ESCROW_FEE_TYPE,
  TOKEN_CROSSCHAIN_MSG_FEE_TYPE,
  TOKEN_CROSSCHAIN_DATA_TYPE,
} token_crosschain_fields;

typedef enum auth_multi_fields {
  AUTH_MULTI_NSIGS_TYPE = 0,
  AUTH_MULTI_KEY_TYPE,
  AUTH_MULTI_OPTKEY_TYPE,  
  AUTH_MULTI_SIG_TYPE,     
} auth_multi_fields;

typedef enum dpos_vote_fields {
  DPOS_VOTE_ADDRESS_TYPE = 0,
  DPOS_VOTE_AMOUNT_TYPE, 
} dpos_vote_fields;

typedef enum dpos_reg_delegate_fields {
  DPOS_REG_DELEGATE_NAME_TYPE = 0,
  DPOS_REG_DELEGATE_GENKEY_TYPE,
  DPOS_REG_DELEGATE_BLSKEY_TYPE,
  DPOS_REG_DELEGATE_POP_TYPE, 
} dpos_reg_delegate_fields;

typedef struct {
    char name[32];
    uint8_t id;
} string_subst_t;

typedef struct tx_command_token_transfer {
  const uint8_t *tokenid; 
  uint64_t amount;
  uint8_t recipientAddress[ADDRESS_HASH_LENGTH];
  const uint8_t *data;
  uint32_t dataLength;
  uint64_t accountInitializationFee;
} tx_command_token_transfer_t;

typedef struct tx_command_token_crosschain_transfer {
  const uint8_t *tokenid; 
  uint64_t amount;
  const uint8_t *receivingChainID;
  uint8_t recipientAddress[ADDRESS_HASH_LENGTH];
  const uint8_t *data;
  uint32_t dataLength;
  uint64_t messageFee;
  uint64_t escrowInitializationFee;
} tx_command_token_crosschain_transfer_t;

typedef struct tx_command_auth_multisig_group {
  uint8_t n_signatures;
  const uint8_t *mandatoryKeys;
  uint8_t n_mandatoryKeys;
  const uint8_t *optionalKeys;
  uint8_t n_optionalKeys;
  const uint8_t *signatures;

} tx_command_auth_multisig_group_t;

typedef struct tx_command_dpos_reg_delegate {
  const uint8_t *name;
  uint8_t nameLength;
  const uint8_t *blskey;
  const uint8_t *proofOfPossession;
  const uint8_t *generatorKey;
  uint64_t delegateRegistrationFee;
} tx_command_dpos_reg_delegate_t;

typedef struct tx_command_dpos_vote_delegate {
  const uint8_t *start;
  uint8_t n_vote;
  uint8_t voteSize[2*MAX_NUMBER_SENT_VOTES];
  int64_t amounts[2*MAX_NUMBER_SENT_VOTES];
} tx_command_dpos_vote_delegate_t;

typedef struct tx_command_dpos_unlock_token {
  uint32_t n_unlock;
} tx_command_dpos_unlock_token_t;

typedef struct tx_command_dpos_delegate_misbehavior {
  const uint8_t *header1;
  uint32_t header1Length;
  const uint8_t *header2;
  uint32_t header2Length;
} tx_command_dpos_delegate_misbehavior_t;

typedef struct tx_command_legacy_token_reclaim {
  uint64_t amount;
} tx_command_legacy_token_reclaim_t;

typedef union tx_command {
  tx_command_token_transfer_t _token_transfer;
  tx_command_token_crosschain_transfer_t _token_crosschain_transfer;

  tx_command_auth_multisig_group_t _reg_multisign_group;

  tx_command_dpos_reg_delegate_t _dpos_reg_delegate;
  tx_command_dpos_vote_delegate_t _dpos_vote_delegate;
  tx_command_dpos_unlock_token_t _dpos_unlock_token;
  tx_command_dpos_delegate_misbehavior_t _dpos_delegate_misbehavior;

  tx_command_legacy_token_reclaim_t _legacy_token_reclaim;
} tx_command_t;

typedef struct{
    // Common fields
    uint8_t network_id[NETWORK_ID_LENGTH];

    uint32_t module_id;
    uint32_t command_id;
    uint64_t nonce;
    uint64_t fee;
    uint8_t senderPublicKey[ENCODED_PUB_KEY];

    tx_command_t tx_command;

} parser_tx_t;


#ifdef __cplusplus
}
#endif
