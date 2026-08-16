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
constexpr size_t CHAIN_KEY_LEN = 32;

// Kontexty pre odvodenie koreňového kľúča a oboch smerových reťazcov
constexpr char ROOT_KEY_CONTEXT[] = "M5PAGER_ROOT_V3";
constexpr char CHAIN_I2R_CONTEXT[] = "M5PAGER_CHAIN_I2R_V3";
constexpr char CHAIN_R2I_CONTEXT[] = "M5PAGER_CHAIN_R2I_V3";

// Koľko chýbajúcich správ vieme preskočiť. Reťazec sa musí posunúť ešte pred overením
// tagu, takže bez stropu by jediný podvrhnutý paket s obrovským počítadlom prinútil
// zariadenie počítať miliardy HMAC operácií.
constexpr uint32_t MAX_SKIPPED_MESSAGES = 256;
constexpr char MESSAGE_AAD[] = "M5PAGER_MSG_V3";
constexpr char FINGERPRINT_CONTEXT[] = "M5PAGER_FP_V1";

// Poradové číslo správy proti replay útoku. Ide do AAD (takže ho nemožno zmeniť
// bez zneplatnenia GCM tagu) a zároveň sa prenáša v blobe, aby ho príjemca vedel prečítať.
constexpr size_t MESSAGE_COUNTER_LEN = 4;
constexpr uint32_t MESSAGE_COUNTER_MAX = 0xFFFFFFFFUL;

// Text sa pred šifrovaním doplní na násobok PAD_BUCKET_LEN. Šifrovanie samo o sebe
// dĺžku neskrýva - z veľkosti paketu sa dá odhadnúť dĺžka správy ("ok" vs. odstavec).
// Doplnenie je vnútri AEAD, takže je chránené tagom.
//   [dĺžka textu: 2B LE][text][výplň núl do násobku PAD_BUCKET_LEN]
constexpr size_t PAD_LENGTH_PREFIX = 2;
constexpr size_t PAD_BUCKET_LEN = 32;

// Koľko bajtov SHA-256 sa zobrazuje ako fingerprint (4 bajty = 8 hex znakov)
constexpr size_t FINGERPRINT_BYTES = 4;

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

/// @brief Vypočíta verejný kľúč X25519 k zadanému skaláru.
/// @param scalar Súkromný skalár (32 bajtov)
/// @param outPublic Pole bajtov pre uloženie verejného kľúča (32 bajtov)
/// @return TRUE, ak bol kľúč úspešne vypočítaný, inak FALSE
inline bool publicKeyFromScalar(const uint8_t scalar[X25519_KEY_LEN],
                                uint8_t outPublic[X25519_KEY_LEN]) {
    if (scalar == nullptr || outPublic == nullptr) return false;

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
    return rc == 0 && written == X25519_KEY_LEN;
}

/// @brief Vráti vlastný dlhodobý (statický) verejný kľúč X25519.
/// @param outPublic Pole bajtov pre uloženie verejného kľúča (32 bajty)
/// @return TRUE, ak bol kľúč úspešne získaný, inak FALSE
inline bool getOwnPublicKey(uint8_t outPublic[X25519_KEY_LEN]) {
    uint8_t scalar[X25519_KEY_LEN];
    if (!deriveX25519Scalar(scalar)) return false;

    bool ok = publicKeyFromScalar(scalar, outPublic);
    Security::secureZero(scalar, sizeof(scalar));
    return ok;
}

/// @brief Vygeneruje efemérny (jednorazový) pár kľúčov X25519.
/// @note Súkromná časť sa nikdy neukladá na kartu - je to práve to, čo zabezpečuje
///       forward secrecy. Po dokončení handshake sa musí vynulovať.
/// @param outPrivate Pole pre súkromný skalár (32 bajtov)
/// @param outPublic Pole pre verejný kľúč (32 bajtov)
/// @return TRUE, ak sa pár podarilo vygenerovať, inak FALSE
inline bool generateEphemeralKeypair(uint8_t outPrivate[X25519_KEY_LEN],
                                     uint8_t outPublic[X25519_KEY_LEN]) {
    if (outPrivate == nullptr || outPublic == nullptr) return false;

    esp_fill_random(outPrivate, X25519_KEY_LEN);
    clampX25519Scalar(outPrivate);

    if (!publicKeyFromScalar(outPrivate, outPublic)) {
        Security::secureZero(outPrivate, X25519_KEY_LEN);
        return false;
    }
    return true;
}

/// @brief Vypočíta zdieľaný tajný kľúč X25519 s použitím verejného kľúča protistrany.
/// @param peerPublic Verejný kľúč protistrany (32 bajty)
/// @param outShared Pole bajtov pre uloženie zdieľaného tajného kľúča (32 bajty)
/// @return TRUE, ak bol kľúč úspešne vypočítaný, inak FALSE
inline bool x25519(const uint8_t scalar[X25519_KEY_LEN],
                   const uint8_t peerPublic[X25519_KEY_LEN],
                   uint8_t outShared[X25519_KEY_LEN]) {
    if (scalar == nullptr || peerPublic == nullptr || outShared == nullptr) return false;

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

    // Nulový výsledok znamená, že protistrana poslala bod malého rádu
    return rc == 0 && !isAllZero(outShared, X25519_KEY_LEN);
}

/// @brief Vypočíta zdieľaný tajný kľúč pomocou vlastného statického kľúča.
/// @param peerPublic Verejný kľúč protistrany (32 bajty)
/// @param outShared Pole bajtov pre uloženie zdieľaného tajného kľúča (32 bajty)
/// @return TRUE, ak bol kľúč úspešne vypočítaný, inak FALSE
inline bool computeSharedSecret(const uint8_t peerPublic[X25519_KEY_LEN],
                                uint8_t outShared[X25519_KEY_LEN]) {
    uint8_t scalar[X25519_KEY_LEN];
    if (!deriveX25519Scalar(scalar)) return false;

    bool ok = x25519(scalar, peerPublic, outShared);
    Security::secureZero(scalar, sizeof(scalar));
    return ok;
}

/// @brief Pomocník pre HMAC-SHA256.
/// @param key Kľúč
/// @param keyLen Dĺžka kľúča
/// @param data Dáta
/// @param dataLen Dĺžka dát
/// @param out Výstup (32 bajtov)
/// @return TRUE pri úspechu, inak FALSE
inline bool hmacSha256(const uint8_t* key, size_t keyLen,
                       const uint8_t* data, size_t dataLen,
                       uint8_t out[32]) {
    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mdInfo == nullptr) return false;
    return mbedtls_md_hmac(mdInfo, key, keyLen, data, dataLen, out) == 0;
}

/// @brief Odvodí koreňový kľúč a oba reťazce z výsledkov štyroch X25519 operácií.
///
/// Skladajú sa štyri Diffie-Hellmanove výmeny:
///   DH_s = statický(iniciátor)  x statický(odpovedajúci)   -> autentifikácia
///   DH_a = efemérny(iniciátor)  x statický(odpovedajúci)
///   DH_b = statický(iniciátor)  x efemérny(odpovedajúci)
///   DH_e = efemérny(iniciátor)  x efemérny(odpovedajúci)   -> forward secrecy
///
/// Statické časti viažu reláciu na overiteľnú identitu (fingerprint), efemérne
/// zabezpečujú, že po ich zahodení sa relácia nedá zrekonštruovať ani z dlhodobého
/// kľúča zariadenia. Poradie je určené ROLOU, nie tým, kto počíta - inak by každá
/// strana zložila vstup inak a kľúče by nesedeli.
///
/// @param dhStatic DH_s (32 bajtov)
/// @param dhEphInitiator DH_a (32 bajtov)
/// @param dhEphResponder DH_b (32 bajtov)
/// @param dhEphemeral DH_e (32 bajtov)
/// @param outChainInitToResp Reťazec pre smer iniciátor -> odpovedajúci (32 bajtov)
/// @param outChainRespToInit Reťazec pre smer odpovedajúci -> iniciátor (32 bajtov)
/// @return TRUE, ak sa reťazce podarilo odvodiť, inak FALSE
inline bool deriveHandshakeChains(const uint8_t dhStatic[X25519_KEY_LEN],
                                  const uint8_t dhEphInitiator[X25519_KEY_LEN],
                                  const uint8_t dhEphResponder[X25519_KEY_LEN],
                                  const uint8_t dhEphemeral[X25519_KEY_LEN],
                                  uint8_t outChainInitToResp[CHAIN_KEY_LEN],
                                  uint8_t outChainRespToInit[CHAIN_KEY_LEN]) {
    uint8_t ikm[X25519_KEY_LEN * 4];
    memcpy(ikm, dhStatic, X25519_KEY_LEN);
    memcpy(ikm + X25519_KEY_LEN, dhEphInitiator, X25519_KEY_LEN);
    memcpy(ikm + X25519_KEY_LEN * 2, dhEphResponder, X25519_KEY_LEN);
    memcpy(ikm + X25519_KEY_LEN * 3, dhEphemeral, X25519_KEY_LEN);

    uint8_t root[32];
    bool ok = hmacSha256(reinterpret_cast<const uint8_t*>(ROOT_KEY_CONTEXT),
                         sizeof(ROOT_KEY_CONTEXT) - 1,
                         ikm, sizeof(ikm), root);
    Security::secureZero(ikm, sizeof(ikm));
    if (!ok) return false;

    // Každý smer má vlastný reťazec, inak by obe strany posúvali ten istý stav
    ok = hmacSha256(root, sizeof(root),
                    reinterpret_cast<const uint8_t*>(CHAIN_I2R_CONTEXT),
                    sizeof(CHAIN_I2R_CONTEXT) - 1, outChainInitToResp);
    if (ok) {
        ok = hmacSha256(root, sizeof(root),
                        reinterpret_cast<const uint8_t*>(CHAIN_R2I_CONTEXT),
                        sizeof(CHAIN_R2I_CONTEXT) - 1, outChainRespToInit);
    }

    Security::secureZero(root, sizeof(root));
    return ok;
}

/// @brief Posunie reťazec o jeden krok a vydá kľúč správy pre aktuálnu pozíciu.
/// @param chain Aktuálny reťazec (32 bajtov)
/// @param outMessageKey Kľúč pre správu na tejto pozícii (32 bajtov)
/// @param outNextChain Reťazec pre nasledujúcu správu (32 bajtov)
/// @return TRUE pri úspechu, inak FALSE
inline bool ratchetStep(const uint8_t chain[CHAIN_KEY_LEN],
                        uint8_t outMessageKey[AES_KEY_LEN],
                        uint8_t outNextChain[CHAIN_KEY_LEN]) {
    const uint8_t messageLabel = 0x01;
    const uint8_t chainLabel = 0x02;

    if (!hmacSha256(chain, CHAIN_KEY_LEN, &messageLabel, 1, outMessageKey)) return false;
    return hmacSha256(chain, CHAIN_KEY_LEN, &chainLabel, 1, outNextChain);
}

/// @brief Posunie reťazec o zadaný počet krokov bez vydania kľúčov (preskočené správy).
/// @param chain Reťazec, ktorý sa posúva (na mieste)
/// @param steps Počet krokov
/// @return TRUE pri úspechu, inak FALSE
inline bool ratchetSkip(uint8_t chain[CHAIN_KEY_LEN], uint32_t steps) {
    const uint8_t chainLabel = 0x02;
    uint8_t next[CHAIN_KEY_LEN];

    for (uint32_t i = 0; i < steps; i++) {
        if (!hmacSha256(chain, CHAIN_KEY_LEN, &chainLabel, 1, next)) {
            Security::secureZero(next, sizeof(next));
            return false;
        }
        memcpy(chain, next, CHAIN_KEY_LEN);
    }

    Security::secureZero(next, sizeof(next));
    return true;
}

/// @brief Vypočíta skrátený SHA-256 fingerprint nad zadanými dátami (s doménovým kontextom).
/// @param data Dáta pre hashovanie
/// @param len Dĺžka dát
/// @return Fingerprint v hexadecimálnom tvare, alebo "UNSET" pri chybe
inline String hashFingerprint(const uint8_t* data, size_t len) {
    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mdInfo == nullptr || data == nullptr) return "UNSET";

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    uint8_t digest[32];
    int rc = mbedtls_md_setup(&ctx, mdInfo, 0);
    if (rc == 0) rc = mbedtls_md_starts(&ctx);
    if (rc == 0) {
        rc = mbedtls_md_update(&ctx,
                               reinterpret_cast<const uint8_t*>(FINGERPRINT_CONTEXT),
                               sizeof(FINGERPRINT_CONTEXT) - 1);
    }
    if (rc == 0) rc = mbedtls_md_update(&ctx, data, len);
    if (rc == 0) rc = mbedtls_md_finish(&ctx, digest);
    mbedtls_md_free(&ctx);

    if (rc != 0) return "UNSET";
    return bytesToHex(digest, FINGERPRINT_BYTES);
}

/// @brief Vráti fingerprint vlastného verejného kľúča.
/// @note Hashuje sa verejný kľúč, nikdy nie privátny - fingerprint je určený na zobrazenie.
/// @return Fingerprint vlastného verejného kľúča
inline String getOwnPublicKeyFingerprint() {
    uint8_t ownPublic[X25519_KEY_LEN];
    if (!getOwnPublicKey(ownPublic)) return "UNSET";
    return hashFingerprint(ownPublic, X25519_KEY_LEN);
}

/// @brief Vypočíta fingerprint dvojice kľúčov. Obe strany dostanú rovnakú hodnotu,
///        takže sa dá porovnať mimo kanála (osobne, telefonicky) a odhaliť MITM.
/// @param ownPublic Vlastný verejný kľúč
/// @param peerPublic Verejný kľúč protistrany
/// @return Fingerprint relácie
inline String pairFingerprint(const uint8_t ownPublic[X25519_KEY_LEN],
                              const uint8_t peerPublic[X25519_KEY_LEN]) {
    const uint8_t* first = ownPublic;
    const uint8_t* second = peerPublic;
    if (memcmp(first, second, X25519_KEY_LEN) > 0) {
        first = peerPublic;
        second = ownPublic;
    }

    uint8_t combined[X25519_KEY_LEN * 2];
    memcpy(combined, first, X25519_KEY_LEN);
    memcpy(combined + X25519_KEY_LEN, second, X25519_KEY_LEN);
    return hashFingerprint(combined, sizeof(combined));
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
/// @brief Dokončí handshake a uloží výsledné reťazce ku kontaktu.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param contactKey Kľúč kontaktu
/// @param peerStaticHex Statický verejný kľúč protistrany (hex)
/// @param peerEphemeralHex Efemérny verejný kľúč protistrany (hex)
/// @param ownEphemeralPrivate Vlastný efemérny súkromný skalár
/// @param isInitiator TRUE, ak sme výmenu začali my
/// @return TRUE, ak sa reláciu podarilo nadviazať, inak FALSE
inline bool completeHandshake(DynamicJsonDocument& contacts,
                              const String& contactKey,
                              const String& peerStaticHex,
                              const String& peerEphemeralHex,
                              const uint8_t ownEphemeralPrivate[X25519_KEY_LEN],
                              bool isInitiator) {
    uint8_t peerStatic[X25519_KEY_LEN];
    uint8_t peerEphemeral[X25519_KEY_LEN];
    uint8_t ownStaticScalar[X25519_KEY_LEN];
    uint8_t ownStaticPublic[X25519_KEY_LEN];

    uint8_t dhStatic[X25519_KEY_LEN];
    uint8_t dhEphInitiator[X25519_KEY_LEN];
    uint8_t dhEphResponder[X25519_KEY_LEN];
    uint8_t dhEphemeral[X25519_KEY_LEN];
    uint8_t chainI2R[CHAIN_KEY_LEN];
    uint8_t chainR2I[CHAIN_KEY_LEN];

    bool ok = hexToBytes(peerStaticHex, peerStatic, X25519_KEY_LEN) &&
              hexToBytes(peerEphemeralHex, peerEphemeral, X25519_KEY_LEN) &&
              deriveX25519Scalar(ownStaticScalar) &&
              publicKeyFromScalar(ownStaticScalar, ownStaticPublic);

    if (ok) {
        ok = x25519(ownStaticScalar, peerStatic, dhStatic);
    }

    if (ok) {
        // DH_a je vždy efemérny iniciátora x statický odpovedajúceho, DH_b naopak.
        // Podľa roly sa líši, ktorý skalár na to použijeme.
        if (isInitiator) {
            ok = x25519(ownEphemeralPrivate, peerStatic, dhEphInitiator) &&
                 x25519(ownStaticScalar, peerEphemeral, dhEphResponder);
        } else {
            ok = x25519(ownStaticScalar, peerEphemeral, dhEphInitiator) &&
                 x25519(ownEphemeralPrivate, peerStatic, dhEphResponder);
        }
    }

    if (ok) ok = x25519(ownEphemeralPrivate, peerEphemeral, dhEphemeral);
    if (ok) {
        ok = deriveHandshakeChains(dhStatic, dhEphInitiator, dhEphResponder,
                                   dhEphemeral, chainI2R, chainR2I);
    }

    if (ok) {
        JsonObject keys = ensureKeyObject(contacts, contactKey);

        keys["status"] = "ready";
        keys["x25519_peer_pub"] = peerStaticHex;
        keys["x25519_own_pub"] = bytesToHex(ownStaticPublic, X25519_KEY_LEN);
        keys["role"] = isInitiator ? "init" : "resp";

        // Každý smer dostane vlastný reťazec - kto posiela, ratchetuje tx_chain
        keys["tx_chain"] = bytesToHex(isInitiator ? chainI2R : chainR2I, CHAIN_KEY_LEN);
        keys["rx_chain"] = bytesToHex(isInitiator ? chainR2I : chainI2R, CHAIN_KEY_LEN);

        // Fingerprint sa počíta zo STATICKÝCH kľúčov, takže sa medzi reláciami nemení
        // a pripnutá identita z nálezu 1 ostáva v platnosti.
        keys["fingerprint"] = pairFingerprint(ownStaticPublic, peerStatic);

        // Každý handshake má nové efemérne kľúče, takže reťazce sú vždy čerstvé
        // a počítadlá sa smú bezpečne vynulovať.
        keys["tx_counter"] = 0;
        keys["rx_counter"] = 0;

        keys.remove("aes_gcm_key");
        keys.remove("rekey_offer");
        keys.remove("pending_id");
    }

    Security::secureZero(peerStatic, sizeof(peerStatic));
    Security::secureZero(peerEphemeral, sizeof(peerEphemeral));
    Security::secureZero(ownStaticScalar, sizeof(ownStaticScalar));
    Security::secureZero(ownStaticPublic, sizeof(ownStaticPublic));
    Security::secureZero(dhStatic, sizeof(dhStatic));
    Security::secureZero(dhEphInitiator, sizeof(dhEphInitiator));
    Security::secureZero(dhEphResponder, sizeof(dhEphResponder));
    Security::secureZero(dhEphemeral, sizeof(dhEphemeral));
    Security::secureZero(chainI2R, sizeof(chainI2R));
    Security::secureZero(chainR2I, sizeof(chainR2I));
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
    const char* txChain = keys["tx_chain"];
    const char* rxChain = keys["rx_chain"];
    return status != nullptr &&
           strcmp(status, "ready") == 0 &&
           txChain != nullptr && strlen(txChain) == CHAIN_KEY_LEN * 2 &&
           rxChain != nullptr && strlen(rxChain) == CHAIN_KEY_LEN * 2;
}

/// @brief Vráti uložený fingerprint relácie pre daný kontakt.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param contactKey Kľúč kontaktu
/// @return Fingerprint relácie, alebo prázdny reťazec, ak nie je k dispozícii
inline String getSessionFingerprint(DynamicJsonDocument& contacts, const String& contactKey) {
    if (!contacts.containsKey(contactKey)) return "";
    const char* fingerprint = contacts[contactKey]["keys"]["fingerprint"];
    return fingerprint == nullptr ? String("") : String(fingerprint);
}

/// @brief Skontroluje, či pre kontakt čaká neschválená žiadosť o prekľúčovanie.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param contactKey Kľúč kontaktu
/// @return TRUE, ak čaká žiadosť o prekľúčovanie, inak FALSE
inline bool hasPendingRekeyOffer(DynamicJsonDocument& contacts, const String& contactKey) {
    if (!contacts.containsKey(contactKey)) return false;
    const char* offer = contacts[contactKey]["keys"]["rekey_offer"];
    return offer != nullptr && strlen(offer) == X25519_KEY_LEN * 2;
}

/// @brief Načíta reťazec daného smeru pre kontakt.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param contactKey Kľúč kontaktu
/// @param field Názov poľa ("tx_chain" alebo "rx_chain")
/// @param outChain Pole bajtov pre uloženie reťazca (32 bajtov)
/// @return TRUE, ak bol reťazec úspešne načítaný, inak FALSE
inline bool loadChain(DynamicJsonDocument& contacts,
                      const String& contactKey,
                      const char* field,
                      uint8_t outChain[CHAIN_KEY_LEN]) {
    if (!hasReadySession(contacts, contactKey)) return false;
    const char* chainHex = contacts[contactKey]["keys"][field];
    if (chainHex == nullptr) return false;
    return hexToBytes(String(chainHex), outChain, CHAIN_KEY_LEN);
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

/// @brief Zapíše 32-bitové poradové číslo v little-endian formáte.
/// @param out Výstupné pole (4 bajty)
/// @param value Hodnota na zapísanie
inline void writeCounterLE(uint8_t out[MESSAGE_COUNTER_LEN], uint32_t value) {
    out[0] = static_cast<uint8_t>(value & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

/// @brief Načíta 32-bitové poradové číslo v little-endian formáte.
/// @param in Vstupné pole (4 bajty)
/// @return Načítaná hodnota
inline uint32_t readCounterLE(const uint8_t in[MESSAGE_COUNTER_LEN]) {
    return static_cast<uint32_t>(in[0]) |
           (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) |
           (static_cast<uint32_t>(in[3]) << 24);
}

// AAD správy = kontextový reťazec + poradové číslo
constexpr size_t MESSAGE_AAD_LEN = sizeof(MESSAGE_AAD) - 1 + MESSAGE_COUNTER_LEN;

/// @brief Zostaví AAD pre správu s daným poradovým číslom.
/// @param counter Poradové číslo správy
/// @param out Výstupné pole veľkosti MESSAGE_AAD_LEN
inline void buildMessageAad(uint32_t counter, uint8_t out[MESSAGE_AAD_LEN]) {
    constexpr size_t ctxLen = sizeof(MESSAGE_AAD) - 1;
    memcpy(out, MESSAGE_AAD, ctxLen);
    writeCounterLE(out + ctxLen, counter);
}

/// @brief Vráti dĺžku doplneného bloku pre text danej dĺžky.
/// @param textLen Dĺžka textu
/// @return Dĺžka bloku po doplnení výplne
inline size_t paddedPlaintextLen(size_t textLen) {
    size_t needed = PAD_LENGTH_PREFIX + textLen;
    size_t buckets = (needed + PAD_BUCKET_LEN - 1) / PAD_BUCKET_LEN;
    if (buckets == 0) buckets = 1;
    return buckets * PAD_BUCKET_LEN;
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
    uint8_t chain[CHAIN_KEY_LEN];
    if (!loadChain(contacts, contactKey, "tx_chain", chain)) return false;

    JsonObject keys = contacts[contactKey]["keys"].as<JsonObject>();
    uint32_t counter = keys["tx_counter"] | 0UL;
    if (counter >= MESSAGE_COUNTER_MAX) {
        // Priestor poradových čísel je vyčerpaný. Ďalej sa už bez prekľúčovania
        // šifrovať nesmie, inak by sa poradové číslo zopakovalo.
        Security::secureZero(chain, sizeof(chain));
        return false;
    }
    counter++;

    // Kľúč správy sa vydá z reťazca, ktorý sa hneď posunie ďalej. Starý stav reťazca
    // sa nikde neuchová, takže sa už nedá znovu vyrobiť kľúč k odoslanej správe.
    uint8_t aesKey[AES_KEY_LEN];
    uint8_t nextChain[CHAIN_KEY_LEN];
    if (!ratchetStep(chain, aesKey, nextChain)) {
        Security::secureZero(chain, sizeof(chain));
        Security::secureZero(aesKey, sizeof(aesKey));
        Security::secureZero(nextChain, sizeof(nextChain));
        return false;
    }

    size_t textLen = plaintext.length();
    if (textLen > 0xFFFF) {
        Security::secureZero(chain, sizeof(chain));
        Security::secureZero(aesKey, sizeof(aesKey));
        Security::secureZero(nextChain, sizeof(nextChain));
        return false;
    }

    // Text sa doplní na násobok PAD_BUCKET_LEN, aby veľkosť paketu neprezrádzala,
    // aká dlhá správa sa posiela
    size_t paddedLen = paddedPlaintextLen(textLen);
    uint8_t* padded = static_cast<uint8_t*>(malloc(paddedLen));
    if (padded == nullptr) {
        Security::secureZero(chain, sizeof(chain));
        Security::secureZero(aesKey, sizeof(aesKey));
        Security::secureZero(nextChain, sizeof(nextChain));
        return false;
    }
    memset(padded, 0, paddedLen);
    padded[0] = static_cast<uint8_t>(textLen & 0xFF);
    padded[1] = static_cast<uint8_t>((textLen >> 8) & 0xFF);
    memcpy(padded + PAD_LENGTH_PREFIX, plaintext.c_str(), textLen);

    size_t blobLen = Security::GCM_IV_LEN + Security::GCM_TAG_LEN + MESSAGE_COUNTER_LEN + paddedLen;
    uint8_t* blob = static_cast<uint8_t*>(malloc(blobLen));
    if (blob == nullptr) {
        Security::secureZero(padded, paddedLen);
        free(padded);
        Security::secureZero(chain, sizeof(chain));
        Security::secureZero(aesKey, sizeof(aesKey));
        Security::secureZero(nextChain, sizeof(nextChain));
        return false;
    }

    uint8_t* iv = blob;
    uint8_t* tag = blob + Security::GCM_IV_LEN;
    uint8_t* counterField = tag + Security::GCM_TAG_LEN;
    uint8_t* ciphertext = counterField + MESSAGE_COUNTER_LEN;
    writeCounterLE(counterField, counter);

    uint8_t aad[MESSAGE_AAD_LEN];
    buildMessageAad(counter, aad);

    bool ok = Security::aesGcmEncrypt(aesKey,
                                      padded,
                                      paddedLen,
                                      aad,
                                      sizeof(aad),
                                      iv,
                                      ciphertext,
                                      tag);
    if (ok) {
        ok = base64Encode(blob, blobLen, outBase64);
    }
    if (ok) {
        // Reťazec sa posunie až po úspechu, aby zlyhanie nezhodilo synchronizáciu
        keys["tx_chain"] = bytesToHex(nextChain, CHAIN_KEY_LEN);
        keys["tx_counter"] = counter;
    }

    Security::secureZero(padded, paddedLen);
    free(padded);
    Security::secureZero(chain, sizeof(chain));
    Security::secureZero(aesKey, sizeof(aesKey));
    Security::secureZero(nextChain, sizeof(nextChain));
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
    uint8_t chain[CHAIN_KEY_LEN];
    if (!loadChain(contacts, contactKey, "rx_chain", chain)) return false;

    constexpr size_t overheadLen = Security::GCM_IV_LEN + Security::GCM_TAG_LEN + MESSAGE_COUNTER_LEN;

    uint8_t* blob = nullptr;
    size_t blobLen = 0;
    bool ok = base64Decode(encodedPayload, blob, blobLen);
    if (!ok || blobLen < overheadLen) {
        if (blob != nullptr) free(blob);
        Security::secureZero(chain, sizeof(chain));
        return false;
    }

    const uint8_t* iv = blob;
    const uint8_t* tag = blob + Security::GCM_IV_LEN;
    const uint8_t* counterField = tag + Security::GCM_TAG_LEN;
    const uint8_t* ciphertext = counterField + MESSAGE_COUNTER_LEN;
    size_t ciphertextLen = blobLen - overheadLen;

    uint32_t counter = readCounterLE(counterField);
    JsonObject keys = contacts[contactKey]["keys"].as<JsonObject>();
    uint32_t lastSeen = keys["rx_counter"] | 0UL;

    // Replay: správu s už videným poradovým číslom zahodíme ešte pred dešifrovaním.
    // Poradové číslo je súčasťou AAD, takže ho útočník nevie zmeniť bez zneplatnenia tagu.
    // Kľúč staršej správy navyše už neexistuje - reťazec sa posunul a späť sa nedá.
    uint32_t skipped = counter - lastSeen - 1;
    if (counter <= lastSeen || skipped > MAX_SKIPPED_MESSAGES) {
        Security::secureZero(blob, blobLen);
        free(blob);
        Security::secureZero(chain, sizeof(chain));
        return false;
    }

    // Reťazec posúvame v kópii - zapíše sa až po overení tagu, inak by jediný
    // podvrhnutý paket natrvalo rozhodil synchronizáciu s protistranou.
    uint8_t aesKey[AES_KEY_LEN];
    uint8_t nextChain[CHAIN_KEY_LEN];
    if (!ratchetSkip(chain, skipped) || !ratchetStep(chain, aesKey, nextChain)) {
        Security::secureZero(blob, blobLen);
        free(blob);
        Security::secureZero(chain, sizeof(chain));
        Security::secureZero(aesKey, sizeof(aesKey));
        Security::secureZero(nextChain, sizeof(nextChain));
        return false;
    }

    uint8_t* plaintext = static_cast<uint8_t*>(malloc(ciphertextLen + 1));
    if (plaintext == nullptr) {
        Security::secureZero(blob, blobLen);
        free(blob);
        Security::secureZero(chain, sizeof(chain));
        Security::secureZero(aesKey, sizeof(aesKey));
        Security::secureZero(nextChain, sizeof(nextChain));
        return false;
    }

    uint8_t aad[MESSAGE_AAD_LEN];
    buildMessageAad(counter, aad);

    ok = Security::aesGcmDecrypt(aesKey,
                                 ciphertext,
                                 ciphertextLen,
                                 aad,
                                 sizeof(aad),
                                 iv,
                                 tag,
                                 plaintext);
    if (ok) {
        // Odstránenie výplne. Dĺžka je vnútri AEAD, takže jej už možno veriť,
        // aj tak ju ale overíme voči skutočnej veľkosti bloku.
        if (ciphertextLen < PAD_LENGTH_PREFIX) {
            ok = false;
        } else {
            size_t textLen = static_cast<size_t>(plaintext[0]) |
                             (static_cast<size_t>(plaintext[1]) << 8);
            if (textLen > ciphertextLen - PAD_LENGTH_PREFIX) {
                ok = false;
            } else {
                plaintext[PAD_LENGTH_PREFIX + textLen] = '\0';
                outPlaintext = String(reinterpret_cast<char*>(plaintext + PAD_LENGTH_PREFIX));
                // Posúvame až po overení tagu - podvrhnutým číslom sa nedá zablokovať príjem
                keys["rx_chain"] = bytesToHex(nextChain, CHAIN_KEY_LEN);
                keys["rx_counter"] = counter;
            }
        }
    }

    Security::secureZero(plaintext, ciphertextLen + 1);
    free(plaintext);
    Security::secureZero(blob, blobLen);
    free(blob);
    Security::secureZero(chain, sizeof(chain));
    Security::secureZero(aesKey, sizeof(aesKey));
    Security::secureZero(nextChain, sizeof(nextChain));
    return ok;
}

}  // namespace MessageCrypto
