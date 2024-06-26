# Lisk App

## Supported Lisk Transactions

- Token Transfer
- Cross Chain Token Transfer
- Multisignature Group Registration
- Pos Stake
- Pos Unlock
- Pos Register Validator
- Pos Report Misbehavior
- Interoperability MainChain CrossChain Update
- Interoperability SideChain CrossChain Update
- Interoperability MainChain Registration
- Interoperability SideChain Registration
- Interoperability Recovery Message
- Interoperability Recovery Message Initialization
- Interoperability Recovery State
- Interoperability Recovery State Initialization
- Legacy Reclaim
- Legacy Register Keys

## General structure

All commands will accept bip32 path as input parameter. BIP32 Path is encoded using hardened keys encoded in BigEndian Format.
PATH[1] = 134 for Mainnet
PATH[1] = 1 for Testnet

The general structure of commands and responses is as follows:

### Commands

| Field   | Type     | Content                | Note |
| :------ | :------- | :--------------------- | ---- |
| CLA     | byte (1) | Application Identifier | 0x60 |
| INS     | byte (1) | Instruction ID         |      |
| P1      | byte (1) | Parameter 1            |      |
| P2      | byte (1) | Parameter 2            |      |
| L       | byte (1) | Bytes in payload       |      |
| PAYLOAD | byte (L) | Payload                |      |

### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

### Return codes

| Return code | Description             |
| ----------- | ----------------------- |
| 0x6400      | Execution Error         |
| 0x6982      | Empty buffer            |
| 0x6983      | Output buffer too small |
| 0x6986      | Command not allowed     |
| 0x6D00      | INS not supported       |
| 0x6E00      | CLA not supported       |
| 0x6F00      | Unknown                 |
| 0x9000      | Success                 |

---

## Command definition

### GET_VERSION

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0x60     |
| INS   | byte (1) | Instruction ID         | 0x00     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field   | Type     | Content          | Note                            |
| ------- | -------- | ---------------- | ------------------------------- |
| TEST    | byte (1) | Test Mode        | 0xFF means test mode is enabled |
| MAJOR   | byte (2) | Version Major    | 0..65535                        |
| MINOR   | byte (2) | Version Minor    | 0..65535                        |
| PATCH   | byte (2) | Version Patch    | 0..65535                        |
| LOCKED  | byte (1) | Device is locked |                                 |
| SW1-SW2 | byte (2) | Return code      | see list of return codes        |

---

### INS_GET_ADDR

#### Command

| Field   | Type     | Content                   | Expected                |
| ------- | -------- | ------------------------- | ----------------------- |
| CLA     | byte (1) | Application Identifier    | 0x60                    |
| INS     | byte (1) | Instruction ID            | 0x01                    |
| P1      | byte (1) | Request User confirmation | No = 0                  |
| P2      | byte (1) | Parameter 2               | ignored                 |
| L       | byte (1) | Bytes in payload          | 0x03                    |
| Path[0] | byte (4) | Derivation Path Data      | 0x8000002c              |
| Path[1] | byte (4) | Derivation Path Data      | 0x80000086 / 0x80000001 |
| Path[2] | byte (4) | Derivation Path Data      | ?                       |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| PK      | byte (32) | Public Key  |                          |
| ADDR    | byte (??) | DOT address |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### INS_SIGN_ED25519

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0x60      |
| INS   | byte (1) | Instruction ID         | 0x02      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks contain data chunks that are described below

##### First Packet

| Field   | Type     | Content              | Expected                |
| ------- | -------- | -------------------- | ----------------------- |
| Path[0] | byte (4) | Derivation Path Data | 0x8000002c              |
| Path[1] | byte (4) | Derivation Path Data | 0x80000086 / 0x80000001 |
| Path[2] | byte (4) | Derivation Path Data | ?                       |

##### Other Chunks/Packets

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Message | bytes... | Message to Sign |          |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (65) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### INS_SIGN_MSG

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0x60      |
| INS   | byte (1) | Instruction ID         | 0x03      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

This instruction signs a message received in the payload

The resulting sequence of chunks is as follows:

##### First Packet

| Field   | Type     | Content              | Expected                |
| ------- | -------- | -------------------- | ----------------------- |
| Path[0] | byte (4) | Derivation Path Data | 0x8000002c              |
| Path[1] | byte (4) | Derivation Path Data | 0x80000086 / 0x80000001 |
| Path[2] | byte (4) | Derivation Path Data | ?                       |

##### Other Chunks/Packets

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Message | bytes... | Message to Sign |          |

#### Response

| Field     | Type      | Content        | Note                     |
| --------- | --------- | -------------- | ------------------------ |
| Signature | byte (64) | Signed message |                          |
| SW1-SW2   | byte (2)  | Return code    | see list of return codes |

---
