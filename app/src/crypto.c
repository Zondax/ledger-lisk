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

#include "crypto.h"
#include "coin.h"
#include "cx.h"
#include "zxmacros.h"
#include "crypto_helper.h"

hdpath_t hdPath;

zxerr_t crypto_extractPublicKey(uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519] = {0};

    if (pubKey == NULL || pubKeyLen < PK_LEN_25519) {
        return zxerr_invalid_crypto_settings;
    }

    zxerr_t err = zxerr_unknown;
    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(
        HDW_ED25519_SLIP10,
        CX_CURVE_Ed25519,
        hdPath.path,
        hdPath.pathLength,
        privateKeyData,
        NULL,
        NULL,
        0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_Ed25519, NULL, 0, &cx_publicKey));
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, &cx_publicKey, &cx_privateKey, 1));
    for (unsigned int i = 0; i < PK_LEN_25519; i++) {
        pubKey[i] = cx_publicKey.W[64 - i];
    }
    if ((cx_publicKey.W[PK_LEN_25519] & 1) != 0) {
        pubKey[31] |= 0x80;
    }
    err = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, SK_LEN_25519);
    if (err != zxerr_ok) {
        MEMZERO(pubKey, pubKeyLen);
    }

    return err;
}

zxerr_t crypto_sign(uint8_t *signature, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen) {
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519];

    zxerr_t err = zxerr_unknown;
    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(
        HDW_ED25519_SLIP10,
        CX_CURVE_Ed25519,
        hdPath.path,
        hdPath.pathLength,
        privateKeyData,
        NULL,
        NULL,
        0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, SCALAR_LEN_ED25519, &cx_privateKey));

    // Sign
    CATCH_CXERROR(cx_eddsa_sign_no_throw(
        &cx_privateKey,
        CX_SHA512,
        message,
        messageLen,
        signature,
        signatureMaxlen
    ));
    err = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, SK_LEN_25519);

    return err;
}

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *responseLen)
{
    if (bufferLen < PK_LEN_25519 + LISK32_ADDRESS_LEN) {
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);
    CHECK_ZXERR(crypto_extractPublicKey(buffer, bufferLen));

    uint8_t addrLen = 0;
    CHECK_ZXERR(crypto_encodePubkey(buffer + PK_LEN_25519, bufferLen - PK_LEN_25519, buffer, &addrLen));

    if (addrLen != LISK32_ADDRESS_LEN) {
        MEMZERO(buffer, bufferLen);
        return zxerr_encoding_failed;
    }

    *responseLen = PK_LEN_25519 + LISK32_ADDRESS_LEN;
    return zxerr_ok;
}
