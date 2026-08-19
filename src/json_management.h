#pragma once

#include <SD.h>
#include <ArduinoJson.h>
#include <M5Cardputer.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "util/util.h"
#include "security/device_key_store.h"


constexpr uint8_t ENC_FILE_MAGIC[] = {'M', '5', 'E', 'N', 'C', '0', '1'};
constexpr size_t ENC_FILE_MAGIC_LEN = sizeof(ENC_FILE_MAGIC); 
constexpr uint8_t ENC_FILE_VERSION = 1;
constexpr size_t ENC_FILE_LEN_FIELD = 4;
constexpr size_t ENC_FILE_HEADER_LEN =
    ENC_FILE_MAGIC_LEN + 1 + Security::GCM_IV_LEN + Security::GCM_TAG_LEN + ENC_FILE_LEN_FIELD; //hlavicka


/// @brief Zapíše 32-bitové číslo do pola v little-endian formáte
/// @param out Pole, do ktorého sa má číslo zapísať
/// @param value Číslo na zapísanie
inline void writeLE32(uint8_t out[4], uint32_t value) {
    out[0] = static_cast<uint8_t>(value & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

/// @brief Načíta 32-bitové číslo z pola v little-endian formáte
/// @param in Pole, z ktorého sa má číslo načítať
/// @return Načítané číslo
inline uint32_t readLE32(const uint8_t in[4]) {
    return static_cast<uint32_t>(in[0]) |
           (static_cast<uint32_t>(in[1]) << 8) |
           (static_cast<uint32_t>(in[2]) << 16) |
           (static_cast<uint32_t>(in[3]) << 24);
}

/// @brief Načíta bajty z súboru do dynamicky alokovaného pola.
/// @param filename Názov súboru
/// @param outBytes Pole, do ktorého sa načítajú bajty (alokované v rámci funkcie, po použití je potrebné ho uvoľniť)
/// @param outLen Premenná, do ktorej sa uloží dĺžka načítaných bajtov
/// @return 
inline bool readFileBytes(const char* filename, uint8_t*& outBytes, size_t& outLen) {
    outBytes = nullptr;
    outLen = 0;

    File file = SD.open(filename, FILE_READ);
    if (!file) return false;

    outLen = static_cast<size_t>(file.size());
    if (outLen == 0) {
        file.close();
        return true;
    }

    outBytes = static_cast<uint8_t*>(malloc(outLen));
    if (outBytes == nullptr) {
        file.close();
        return false;
    }

    size_t bytesRead = file.read(outBytes, outLen);
    file.close();
    if (bytesRead != outLen) {
        free(outBytes);
        outBytes = nullptr;
        outLen = 0;
        return false;
    }
    return true;
}

/// @brief Zapíše šifrované dáta do súboru na zadanú cestu.
/// @param filename Názov súboru
/// @param plaintext Šifrované dáta
/// @param plaintextLen Dĺžka šifrovaných dát
/// @return TRUE, ak sa operácia podarila, inak FALSE
inline bool writeEncryptedBlobAtPath(const char* filename,
                                     const uint8_t* plaintext,
                                     size_t plaintextLen) {
    uint8_t* ciphertext = nullptr;
    if (plaintextLen > 0) {
        ciphertext = static_cast<uint8_t*>(malloc(plaintextLen));
        if (ciphertext == nullptr) return false;
    }

    uint8_t iv[Security::GCM_IV_LEN];
    uint8_t tag[Security::GCM_TAG_LEN];
    bool ok = Security::encryptFilesystemBuffer(plaintext, plaintextLen, iv, ciphertext, tag);
    if (!ok) {
        if (ciphertext != nullptr) free(ciphertext);
        return false;
    }

    File file = SD.open(filename, FILE_WRITE);
    if (!file) {
        if (ciphertext != nullptr) free(ciphertext);
        return false;
    }

    uint8_t lenField[4];
    writeLE32(lenField, static_cast<uint32_t>(plaintextLen));

    bool writeOk = true;
    if (file.write(ENC_FILE_MAGIC, ENC_FILE_MAGIC_LEN) != ENC_FILE_MAGIC_LEN) writeOk = false;
    if (writeOk && file.write(&ENC_FILE_VERSION, 1) != 1) writeOk = false;
    if (writeOk && file.write(iv, Security::GCM_IV_LEN) != Security::GCM_IV_LEN) writeOk = false;
    if (writeOk && file.write(tag, Security::GCM_TAG_LEN) != Security::GCM_TAG_LEN) writeOk = false;
    if (writeOk && file.write(lenField, sizeof(lenField)) != sizeof(lenField)) writeOk = false;
    if (writeOk && plaintextLen > 0 &&
        file.write(ciphertext, plaintextLen) != plaintextLen) writeOk = false;

    file.close();
    if (ciphertext != nullptr) {
        Security::secureZero(ciphertext, plaintextLen);
        free(ciphertext);
    }

    return writeOk;
}

/// @brief Zapíše šifrované dáta do súboru atomicky (v rámci jednej operácie).
/// @param filename Názov súboru
/// @param plaintext Šifrované dáta
/// @param plaintextLen Dĺžka šifrovaných dát
/// @return TRUE, ak sa operácia podarila, inak FALSE
inline bool writeEncryptedBlobAtomic(const char* filename,
                                     const uint8_t* plaintext,
                                     size_t plaintextLen) {
    String tmpPath = String(filename) + ".tmp";
    String backupPath = String(filename) + ".bak";

    if (fileExists(tmpPath.c_str())) SD.remove(tmpPath.c_str());
    if (fileExists(backupPath.c_str())) SD.remove(backupPath.c_str());

    if (!writeEncryptedBlobAtPath(tmpPath.c_str(), plaintext, plaintextLen)) {
        SD.remove(tmpPath.c_str());
        return false;
    }

    bool hadOriginal = fileExists(filename);
    if (hadOriginal) {
        if (!SD.rename(filename, backupPath.c_str())) {
            SD.remove(tmpPath.c_str());
            return false;
        }
    }

    if (!SD.rename(tmpPath.c_str(), filename)) {
        if (hadOriginal) {
            SD.rename(backupPath.c_str(), filename);
        }
        SD.remove(tmpPath.c_str());
        return false;
    }

    if (hadOriginal) {
        SD.remove(backupPath.c_str());
    }
    return true;
}

/// @brief Dekryptuje šifrovaný blob načítaný zo súboru.
/// @param filename Názov súboru
/// @param fileBytes Bajty súboru
/// @param fileLen Dĺžka bajtov súboru
/// @param outPlain Dekryptované dáta (alokované v rámci funkcie)
/// @param outPlainLen Dĺžka dekryptovaných dát
/// @return TRUE, ak sa operácia podarila, inak FALSE
inline bool decryptEncryptedBlob(const uint8_t* fileBytes,
                                 size_t fileLen,
                                 uint8_t*& outPlain,
                                 size_t& outPlainLen) {
    outPlain = nullptr;
    outPlainLen = 0;

    if (fileBytes == nullptr || fileLen < ENC_FILE_HEADER_LEN) return false;
    if (memcmp(fileBytes, ENC_FILE_MAGIC, ENC_FILE_MAGIC_LEN) != 0) return false;

    size_t offset = ENC_FILE_MAGIC_LEN;
    uint8_t version = fileBytes[offset++];
    if (version != ENC_FILE_VERSION) return false;

    const uint8_t* iv = fileBytes + offset;
    offset += Security::GCM_IV_LEN;

    const uint8_t* tag = fileBytes + offset;
    offset += Security::GCM_TAG_LEN;

    uint32_t cipherLen = readLE32(fileBytes + offset);
    offset += ENC_FILE_LEN_FIELD;

    if (static_cast<size_t>(cipherLen) != (fileLen - offset)) return false;

    size_t allocLen = cipherLen == 0 ? 1 : cipherLen;
    outPlain = static_cast<uint8_t*>(malloc(allocLen));
    if (outPlain == nullptr) return false;

    if (!Security::decryptFilesystemBuffer(fileBytes + offset, cipherLen, iv, tag, outPlain)) {
        free(outPlain);
        outPlain = nullptr;
        return false;
    }

    outPlainLen = cipherLen;
    return true;
}

/// @brief Uloží JSON dokument do šifrovaného súboru.
/// @param doc JSON dokument
/// @param filename Názov súboru
/// @param label Popis súboru
/// @return TRUE, ak sa operácia podarila, inak FALSE
inline bool saveJsonEncrypted(const DynamicJsonDocument& doc, const char* filename, const char* label) {
    if (!Security::hasFilesystemKey()) {
        M5Cardputer.Display.println("[-] Storage key not available.");
        return false;
    }

    String serialized;
    if (serializeJsonPretty(doc, serialized) == 0) {
        M5Cardputer.Display.print("[-] Failed to serialize ");
        M5Cardputer.Display.print(label);
        M5Cardputer.Display.println(".");
        return false;
    }

    bool ok = writeEncryptedBlobAtomic(
        filename,
        reinterpret_cast<const uint8_t*>(serialized.c_str()),
        serialized.length());
    if (!ok) {
        M5Cardputer.Display.print("[-] Failed to write encrypted ");
        M5Cardputer.Display.print(label);
        M5Cardputer.Display.println(".");
    }
    return ok;
}

/// @brief Načíta JSON dokument zo šifrovaného súboru alebo vytvorí predvolený dokument.
/// @param doc JSON dokument (výstup)
/// @param filename Názov súboru
/// @param label Popis súboru
/// @param defaultJson Predvolený JSON obsah
/// @return TRUE, ak sa operácia podarila, inak FALSE
inline bool loadJsonEncryptedAware(DynamicJsonDocument& doc,
                                   const char* filename,
                                   const char* label,
                                   const char* defaultJson) {
    if (!fileExists("/m5pager")) SD.mkdir("/m5pager");

    if (!fileExists(filename)) {
        M5Cardputer.Display.print("[*] ");
        M5Cardputer.Display.print(label);
        M5Cardputer.Display.println(" file not found. Creating encrypted default...");
        doc.clear();
        if (deserializeJson(doc, defaultJson) != DeserializationError::Ok) {
            M5Cardputer.Display.println("[-] Failed to build default JSON.");
            return false;
        }
        return saveJsonEncrypted(doc, filename, label);
    }

    uint8_t* fileBytes = nullptr;
    size_t fileLen = 0;
    if (!readFileBytes(filename, fileBytes, fileLen)) {
        M5Cardputer.Display.print("[-] Failed to read ");
        M5Cardputer.Display.print(label);
        M5Cardputer.Display.println(" file.");
        return false;
    }

    if (fileLen == 0) {
        if (fileBytes != nullptr) free(fileBytes);
        M5Cardputer.Display.print("[*] ");
        M5Cardputer.Display.print(label);
        M5Cardputer.Display.println(" file empty. Writing encrypted default...");
        doc.clear();
        if (deserializeJson(doc, defaultJson) != DeserializationError::Ok) {
            M5Cardputer.Display.println("[-] Failed to build default JSON.");
            return false;
        }
        return saveJsonEncrypted(doc, filename, label);
    }

    // Súbor bez našej magic hlavičky nie je overený - nesmie sa načítať.
    // Inak by stačilo hlavičku odstrániť a GCM tag by sa nikdy neoveril,
    // čím by sa dal podstrčiť ľubovoľný obsah (vrátane cudzích session kľúčov).
    bool encrypted = (fileLen >= ENC_FILE_HEADER_LEN &&
                      memcmp(fileBytes, ENC_FILE_MAGIC, ENC_FILE_MAGIC_LEN) == 0);
    if (!encrypted) {
        free(fileBytes);
        M5Cardputer.Display.print("[-] ");
        M5Cardputer.Display.print(label);
        M5Cardputer.Display.println(" file is not encrypted - refusing to load.");
        M5Cardputer.Display.println("    Delete or restore it from a trusted backup.");
        return false;
    }

    uint8_t* jsonBytes = nullptr;
    size_t jsonLen = 0;
    if (!decryptEncryptedBlob(fileBytes, fileLen, jsonBytes, jsonLen)) {
        free(fileBytes);
        M5Cardputer.Display.print("[-] Failed to decrypt ");
        M5Cardputer.Display.print(label);
        M5Cardputer.Display.println(" file (wrong password or tampered data).");
        return false;
    }
    free(fileBytes);

    DeserializationError error = deserializeJson(doc, jsonBytes, jsonLen);
    free(jsonBytes);
    if (error) {
        M5Cardputer.Display.print("[-] JSON parse error in ");
        M5Cardputer.Display.print(label);
        M5Cardputer.Display.print(": ");
        M5Cardputer.Display.println(error.c_str());
        return false;
    }

    return true;
}

/// @brief Načíta kontakty zo súboru alebo vytvorí predvolený zoznam.
/// @param contacts Premenná, do ktorej sa načítajú kontakty (výstup)
/// @param filename Názov súboru
/// @return TRUE, ak sa operácia podarila, inak FALSE
bool loadContacts(DynamicJsonDocument &contacts, const char* filename) {
    M5Cardputer.Display.println("[*] Loading contacts...");
    return loadJsonEncryptedAware(contacts, filename, "contacts", "{}");
}

/// @brief Uloží kontakty do súboru.
/// @param contacts Kontakty, ktoré se majú uložiť
/// @param filename Názov súboru
/// @return TRUE, ak sa operácia podarila, inak FALSE
bool saveContacts(const DynamicJsonDocument &contacts, const char* filename) {
    return saveJsonEncrypted(contacts, filename, "contacts");
}

/// @brief Načíta konfiguráciu zo súboru alebo vytvorí predvolené nastavenie.
/// @param config Premenná, do ktorej sa načítajú konfiguračné nastavenia (výstup)
/// @param filename Názov súboru
/// @return TRUE, ak sa operácia podarila, inak FALSE
bool loadConfig(DynamicJsonDocument &config, const char* filename) {
    M5Cardputer.Display.println("[*] Loading config...");
    if (!loadJsonEncryptedAware(config, filename, "config", "{\"username\":\"User\"}")) {
        return false;
    }

    if (!config.containsKey("username")) {
        config["username"] = "User";
        return saveJsonEncrypted(config, filename, "config");
    }

    return true;
}

/// @brief Uloží konfiguráciu do súboru.
/// @param config Konfigurácia, ktorá sa má uložiť
/// @param filename Názov súboru
/// @return TRUE, ak sa operácia podarila, inak FALSE
bool saveConfig(const DynamicJsonDocument &config, const char* filename) {
    return saveJsonEncrypted(config, filename, "config");
}
