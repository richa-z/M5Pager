#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include <esp_system.h>
#include <mbedtls/base64.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>

#include <cstdlib>
#include <cstring>

#include "security/device_key_store.h"

namespace MessageCrypto {

// Konštanty pre kryptografické operácie
constexpr size_t X25519_KEY_LEN = 32;
constexpr size_t AES_KEY_LEN = 32;
constexpr char X25519_DERIVE_CONTEXT[] = "M5PAGER_X25519_ID_V1";
constexpr char PAIR_KEY_CONTEXT[] = "M5PAGER_PAIR_AES_V1";
constexpr char MESSAGE_AAD[] = "M5PAGER_MSG_V1";

/// @brief Naplní pole náhodnými bajtmi pomocou esp_random.
/// @param  
/// @param out Pole, do ktorého sa majú uložiť náhodné bajty
/// @param len Dĺžka náhodných bajtov
/// @return Vždy 0
inline int espRandom(void*, unsigned char* out, size_t len) {
    esp_fill_random(out, len);
    return 0;
}

/// @brief Prevedie hexadecimálny znak na číslo.
/// @param c Hexadecimálny znak ('0'-'9', 'a'-'f', 'A'-'F')
/// @return Hodnota znaku alebo -1, ak je neplatný
inline int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// @brief Prevedie pole bajtov na hexadecimálny reťazec.
/// @param bytes Pole bajtov
/// @param len Dĺžka poľa bajtov
/// @return Hexadecimálny reťazec
inline String bytesToHex(const uint8_t* bytes, size_t len) {
    static const char* digits = "0123456789ABCDEF";
    String out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out += digits[(bytes[i] >> 4) & 0x0F];
        out += digits[bytes[i] & 0x0F];
    }
    return out;
}

/// @brief Prevedie hexadecimálny reťazec na pole bajtov.
/// @param hex Hexadecimálny reťazec
/// @param out Premenna pre uloženie poľa bajtov
/// @param outLen Dĺžka poľa bajtov
/// @return TRUE, ak bol reťazec úspešne prevedený, inak FALSE
inline bool hexToBytes(const String& hex, uint8_t* out, size_t outLen) {
    if (hex.length() != outLen * 2 || out == nullptr) return false;
    for (size_t i = 0; i < outLen; i++) {
        int hi = hexNibble(hex[i * 2]);
        int lo = hexNibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

/// @brief Zakóduje pole bajtov do base64 reťazca.
/// @param input Pole bajtov
/// @param inputLen Dĺžka poľa bajtov
/// @param out Referencia na premennú pre uloženie zakódovaného reťazca
/// @return TRUE, ak bol reťazec úspešne zakódovaný, inak FALSE
inline bool base64Encode(const uint8_t* input, size_t inputLen, String& out) {
    size_t outLen = ((inputLen + 2) / 3) * 4;
    uint8_t* encoded = static_cast<uint8_t*>(malloc(outLen + 1));
    if (encoded == nullptr) return false;

    size_t actualLen = 0;
    int rc = mbedtls_base64_encode(encoded, outLen + 1, &actualLen, input, inputLen);
    if (rc != 0) {
        free(encoded);
        return false;
    }

    encoded[actualLen] = '\0';
    out = String(reinterpret_cast<char*>(encoded));
    free(encoded);
    return true;
}

/// @brief Dekóduje base64 reťazec na pole bajtov.
/// @param input Zakódovaný reťazec
/// @param out Referencia na premennú pre uloženie dekódovaného poľa bajtov
/// @param outLen Referencia na premennú pre uloženie dĺžky dekódovaného poľa bajtov
/// @return TRUE, ak bol reťazec úspešne dekódovaný, inak FALSE
inline bool base64Decode(const String& input, uint8_t*& out, size_t& outLen) {
    out = nullptr;
    outLen = 0;

    size_t allocLen = ((input.length() * 3) / 4) + 3;
    out = static_cast<uint8_t*>(malloc(allocLen));
    if (out == nullptr) return false;

    int rc = mbedtls_base64_decode(out,
                                   allocLen,
                                   &outLen,
                                   reinterpret_cast<const uint8_t*>(input.c_str()),
                                   input.length());
    if (rc != 0) {
        free(out);
        out = nullptr;
        outLen = 0;
        return false;
    }
    return true;
}

/// @brief Obmedzí hodnotu X25519 skalára na platný rozsah.
/// @param scalar Pole bajtov reprezentujúce X25519 skalár (32 bajtov)
inline void clampX25519Scalar(uint8_t scalar[X25519_KEY_LEN]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// @brief Odvodí X25519 skalár z device private key pomocou HMAC-SHA256.
/// @param scalar Pole bajtov pre uloženie odvodenej hodnoty (32 bajtov)
inline bool deriveX25519Scalar(uint8_t scalar[X25519_KEY_LEN]) {
    const uint8_t* devicePrivate = Security::getDevicePrivateKey();
    if (devicePrivate == nullptr || scalar == nullptr) return false;

    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mdInfo == nullptr) return false;

    int rc = mbedtls_md_hmac(mdInfo,
                             devicePrivate,
                             Security::DEVICE_PRIVATE_KEY_LEN,
                             reinterpret_cast<const uint8_t*>(X25519_DERIVE_CONTEXT),
                             strlen(X25519_DERIVE_CONTEXT),
                             scalar);
    if (rc != 0) return false;

    clampX25519Scalar(scalar);
    return true;
}

/// @brief Skontroluje, či sú všetky bajty v poli nulové.
/// @param bytes Pole bajtov
/// @param len Dĺžka pola bajtov
/// @return TRUE, ak sú všetky bajty nulové, inak FALSE
inline bool isAllZero(const uint8_t* bytes, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc |= bytes[i];
    }
    return acc == 0;
}

/// @brief Vráti vlastný verejný kľúč X25519.
/// @param outPublic Pole bajtov pre uloženie verejného kľúča (32 bajty)
/// @return TRUE, ak bol kľúč úspešne získaný, inak FALSE
inline bool getOwnPublicKey(uint8_t outPublic[X25519_KEY_LEN]) {
    if (outPublic == nullptr) return false;

    uint8_t scalar[X25519_KEY_LEN];
    if (!deriveX25519Scalar(scalar)) return false;

    mbedtls_ecp_group group;
    mbedtls_mpi privateScalar;
    mbedtls_ecp_point publicPoint;
    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&privateScalar);
    mbedtls_ecp_point_init(&publicPoint);

    size_t written = 0;
    int rc = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519);
    if (rc == 0) rc = mbedtls_mpi_read_binary_le(&privateScalar, scalar, X25519_KEY_LEN);
    if (rc == 0) rc = mbedtls_ecp_mul(&group, &publicPoint, &privateScalar, &group.G, espRandom, nullptr);
    if (rc == 0) {
        rc = mbedtls_ecp_point_write_binary(&group,
                                            &publicPoint,
                                            MBEDTLS_ECP_PF_UNCOMPRESSED,
                                            &written,
                                            outPublic,
                                            X25519_KEY_LEN);
    }

    mbedtls_ecp_point_free(&publicPoint);
    mbedtls_mpi_free(&privateScalar);
    mbedtls_ecp_group_free(&group);
    Security::secureZero(scalar, sizeof(scalar));
    return rc == 0 && written == X25519_KEY_LEN;
}

/// @brief Vypočíta zdieľaný tajný kľúč X25519 s použitím verejného kľúča protistrany.
/// @param peerPublic Verejný kľúč protistrany (32 bajty)
/// @param outShared Pole bajtov pre uloženie zdieľaného tajného kľúča (32 bajty)
/// @return TRUE, ak bol kľúč úspešne vypočítaný, inak FALSE
inline bool computeSharedSecret(const uint8_t peerPublic[X25519_KEY_LEN],
                                uint8_t outShared[X25519_KEY_LEN]) {
    if (peerPublic == nullptr || outShared == nullptr) return false;

    uint8_t scalar[X25519_KEY_LEN];
    if (!deriveX25519Scalar(scalar)) return false;

    mbedtls_ecp_group group;
    mbedtls_mpi privateScalar;
    mbedtls_mpi sharedSecret;
    mbedtls_ecp_point peerPoint;
    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&privateScalar);
    mbedtls_mpi_init(&sharedSecret);
    mbedtls_ecp_point_init(&peerPoint);

    int rc = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519);
    if (rc == 0) rc = mbedtls_mpi_read_binary_le(&privateScalar, scalar, X25519_KEY_LEN);
    if (rc == 0) rc = mbedtls_ecp_point_read_binary(&group, &peerPoint, peerPublic, X25519_KEY_LEN);
    if (rc == 0) rc = mbedtls_ecdh_compute_shared(&group, &sharedSecret, &peerPoint, &privateScalar, espRandom, nullptr);
    if (rc == 0) rc = mbedtls_mpi_write_binary_le(&sharedSecret, outShared, X25519_KEY_LEN);

    mbedtls_ecp_point_free(&peerPoint);
    mbedtls_mpi_free(&sharedSecret);
    mbedtls_mpi_free(&privateScalar);
    mbedtls_ecp_group_free(&group);
    Security::secureZero(scalar, sizeof(scalar));

    return rc == 0 && !isAllZero(outShared, X25519_KEY_LEN);
}

/// @brief Odvodí AES kľúč z zdieľaného tajného kľúča X25519.
/// @param sharedSecret Zdieľaný tajný kľúč X25519 (32 bajty)
/// @param ownPublic Vlastný verejný kľúč X25519 (32 bajty)
/// @param peerPublic Verejný kľúč protistrany X25519 (32 bajty)
/// @param outKey Pole bajtov pre uloženie odvodeneého AES kľúča (32 bajty)
/// @return TRUE, ak bol kľúč úspešne odvodený, inak FALSE
inline bool deriveAesKey(const uint8_t sharedSecret[X25519_KEY_LEN],
                         const uint8_t ownPublic[X25519_KEY_LEN],
                         const uint8_t peerPublic[X25519_KEY_LEN],
                         uint8_t outKey[AES_KEY_LEN]) {
    if (sharedSecret == nullptr || ownPublic == nullptr || peerPublic == nullptr || outKey == nullptr) return false;

    uint8_t input[sizeof(PAIR_KEY_CONTEXT) - 1 + X25519_KEY_LEN * 2];
    size_t offset = 0;
    memcpy(input + offset, PAIR_KEY_CONTEXT, sizeof(PAIR_KEY_CONTEXT) - 1);
    offset += sizeof(PAIR_KEY_CONTEXT) - 1;

    const uint8_t* first = ownPublic;
    const uint8_t* second = peerPublic;
    if (memcmp(first, second, X25519_KEY_LEN) > 0) {
        first = peerPublic;
        second = ownPublic;
    }

    memcpy(input + offset, first, X25519_KEY_LEN);
    offset += X25519_KEY_LEN;
    memcpy(input + offset, second, X25519_KEY_LEN);

    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mdInfo == nullptr) {
        Security::secureZero(input, sizeof(input));
        return false;
    }

    int rc = mbedtls_md_hmac(mdInfo, sharedSecret, X25519_KEY_LEN, input, sizeof(input), outKey);
    Security::secureZero(input, sizeof(input));
    return rc == 0;
}

/// @brief Zabezpečí existenciu objektu pre kľúče v dokumente kontaktov.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param contactKey Kľúč kontaktu
/// @return Objekt pre kľúče kontaktu
inline JsonObject ensureKeyObject(DynamicJsonDocument& contacts, const String& contactKey) {
    JsonObject contact = contacts[contactKey].as<JsonObject>();
    JsonObject keys;
    if (contact["keys"].is<JsonObject>()) {
        keys = contact["keys"].as<JsonObject>();
    } else {
        keys = contact.createNestedObject("keys");
    }
    return keys;
}

/// @brief Uloží verejný kľúč protistrany a informácie o relácii.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param contactKey Kľúč kontaktu
/// @param peerPublicHex Verejný kľúč protistrany v hexadecimálnom tvare
/// @return TRUE, ak boli informácie úspešne uložené, inak FALSE
inline bool storePeerPublicAndSession(DynamicJsonDocument& contacts,
                                      const String& contactKey,
                                      const String& peerPublicHex) {
    uint8_t peerPublic[X25519_KEY_LEN];
    uint8_t ownPublic[X25519_KEY_LEN];
    uint8_t sharedSecret[X25519_KEY_LEN];
    uint8_t aesKey[AES_KEY_LEN];

    bool ok = hexToBytes(peerPublicHex, peerPublic, X25519_KEY_LEN) &&
              getOwnPublicKey(ownPublic) &&
              computeSharedSecret(peerPublic, sharedSecret) &&
              deriveAesKey(sharedSecret, ownPublic, peerPublic, aesKey);

    if (ok) {
        JsonObject keys = ensureKeyObject(contacts, contactKey);
        keys["status"] = "ready";
        keys["x25519_peer_pub"] = peerPublicHex;
        keys["x25519_own_pub"] = bytesToHex(ownPublic, X25519_KEY_LEN);
        keys["aes_gcm_key"] = bytesToHex(aesKey, AES_KEY_LEN);
    }

    Security::secureZero(peerPublic, sizeof(peerPublic));
    Security::secureZero(ownPublic, sizeof(ownPublic));
    Security::secureZero(sharedSecret, sizeof(sharedSecret));
    Security::secureZero(aesKey, sizeof(aesKey));
    return ok;
}

/// @brief Skontroluje, či existuje pripravená relácia s daným kontaktom.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param contactKey Kľúč kontaktu
/// @return TRUE, ak existuje pripravená relácia, inak FALSE
inline bool hasReadySession(DynamicJsonDocument& contacts, const String& contactKey) {
    if (!contacts.containsKey(contactKey)) return false;
    JsonObject keys = contacts[contactKey]["keys"].as<JsonObject>();
    const char* status = keys["status"];
    const char* aesKey = keys["aes_gcm_key"];
    return status != nullptr &&
           strcmp(status, "ready") == 0 &&
           aesKey != nullptr &&
           strlen(aesKey) == AES_KEY_LEN * 2;
}

/// @brief Načítá AES kľúč z dokumentu kontaktov pre daný kontakt.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param contactKey Kľúč kontaktu
/// @param outKey Pole bajtov pre uloženie AES kľúča (32 bajty)
/// @return TRUE, ak bol kľúč úspešne načítaný, inak FALSE
inline bool loadAesKey(DynamicJsonDocument& contacts, const String& contactKey, uint8_t outKey[AES_KEY_LEN]) {
    if (!hasReadySession(contacts, contactKey)) return false;
    const char* aesKeyHex = contacts[contactKey]["keys"]["aes_gcm_key"];
    return hexToBytes(String(aesKeyHex), outKey, AES_KEY_LEN);
}

/// @brief Vráti vlastný verejný kľúč X25519 v hexadecimálnom tvare.
/// @param outHex String pre uloženie hexadecimálneho kľúča
/// @return TRUE, ak bol kľúč úspešne získaný, inak FALSE
inline bool getOwnPublicKeyHex(String& outHex) {
    uint8_t ownPublic[X25519_KEY_LEN];
    bool ok = getOwnPublicKey(ownPublic);
    if (ok) outHex = bytesToHex(ownPublic, X25519_KEY_LEN);
    Security::secureZero(ownPublic, sizeof(ownPublic));
    return ok;
}

/// @brief Zašifruje správu pomocou AES-GCM.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param contactKey Kľúč kontaktu
/// @param plaintext Text na zašifrovanie
/// @param outBase64 String pre uloženie zašifrovaného payloadu v base64
/// @return TRUE, ak bola správa úspešne zašifrovaná, inak FALSE
inline bool encryptPayload(DynamicJsonDocument& contacts,
                           const String& contactKey,
                           const String& plaintext,
                           String& outBase64) {
    uint8_t aesKey[AES_KEY_LEN];
    if (!loadAesKey(contacts, contactKey, aesKey)) return false;

    size_t plaintextLen = plaintext.length();
    size_t blobLen = Security::GCM_IV_LEN + Security::GCM_TAG_LEN + plaintextLen;
    uint8_t* blob = static_cast<uint8_t*>(malloc(blobLen));
    uint8_t* ciphertext = blob == nullptr ? nullptr : blob + Security::GCM_IV_LEN + Security::GCM_TAG_LEN;
    if (blob == nullptr) {
        Security::secureZero(aesKey, sizeof(aesKey));
        return false;
    }

    uint8_t* iv = blob;
    uint8_t* tag = blob + Security::GCM_IV_LEN;
    bool ok = Security::aesGcmEncrypt(aesKey,
                                      reinterpret_cast<const uint8_t*>(plaintext.c_str()),
                                      plaintextLen,
                                      reinterpret_cast<const uint8_t*>(MESSAGE_AAD),
                                      strlen(MESSAGE_AAD),
                                      iv,
                                      ciphertext,
                                      tag);
    if (ok) {
        ok = base64Encode(blob, blobLen, outBase64);
    }

    Security::secureZero(aesKey, sizeof(aesKey));
    Security::secureZero(blob, blobLen);
    free(blob);
    return ok;
}

/// @brief Dešifruje správu pomocou AES-GCM.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param contactKey Kľúč kontaktu
/// @param encodedPayload Zašifrovaný payload v base64
/// @param outPlaintext String pre uloženie dešifrovaného textu
/// @return TRUE, ak bola správa úspešne dešifrovaná, inak FALSE
inline bool decryptPayload(DynamicJsonDocument& contacts,
                           const String& contactKey,
                           const String& encodedPayload,
                           String& outPlaintext) {
    uint8_t aesKey[AES_KEY_LEN];
    if (!loadAesKey(contacts, contactKey, aesKey)) return false;

    uint8_t* blob = nullptr;
    size_t blobLen = 0;
    bool ok = base64Decode(encodedPayload, blob, blobLen);
    if (!ok || blobLen < Security::GCM_IV_LEN + Security::GCM_TAG_LEN) {
        if (blob != nullptr) free(blob);
        Security::secureZero(aesKey, sizeof(aesKey));
        return false;
    }

    const uint8_t* iv = blob;
    const uint8_t* tag = blob + Security::GCM_IV_LEN;
    const uint8_t* ciphertext = blob + Security::GCM_IV_LEN + Security::GCM_TAG_LEN;
    size_t ciphertextLen = blobLen - Security::GCM_IV_LEN - Security::GCM_TAG_LEN;
    uint8_t* plaintext = static_cast<uint8_t*>(malloc(ciphertextLen + 1));
    if (plaintext == nullptr) {
        Security::secureZero(blob, blobLen);
        free(blob);
        Security::secureZero(aesKey, sizeof(aesKey));
        return false;
    }

    ok = Security::aesGcmDecrypt(aesKey,
                                 ciphertext,
                                 ciphertextLen,
                                 reinterpret_cast<const uint8_t*>(MESSAGE_AAD),
                                 strlen(MESSAGE_AAD),
                                 iv,
                                 tag,
                                 plaintext);
    if (ok) {
        plaintext[ciphertextLen] = '\0';
        outPlaintext = String(reinterpret_cast<char*>(plaintext));
    }

    Security::secureZero(plaintext, ciphertextLen + 1);
    free(plaintext);
    Security::secureZero(blob, blobLen);
    free(blob);
    Security::secureZero(aesKey, sizeof(aesKey));
    return ok;
}

}  // namespace MessageCrypto
