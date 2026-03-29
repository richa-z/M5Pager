#pragma once

#include <Arduino.h>
#include <M5Cardputer.h>
#include <esp_system.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

#include <cstring>

enum class DeviceKeyProvisionState : uint8_t {
    Error = 0,
    LoadedExisting,
    CreatedNew
};

namespace Security {

constexpr size_t DEVICE_PRIVATE_KEY_LEN = 32;
constexpr size_t FILESYSTEM_KEY_LEN = 32;
constexpr size_t PASSWORD_WRAP_KEY_LEN = 32;
constexpr size_t PASSWORD_SALT_LEN = 16;
constexpr size_t FILESYSTEM_SALT_LEN = 16;
constexpr size_t GCM_IV_LEN = 12;
constexpr size_t GCM_TAG_LEN = 16;
constexpr uint32_t PASSWORD_KDF_ITERATIONS = 60000;

constexpr const char* DEVICE_KEY_NAMESPACE = "crypto";
constexpr const char* LEGACY_DEVICE_KEY_NAME = "device_sk";
constexpr const char* WRAP_MARKER_KEY = "wrap_v1";
constexpr const char* PASSWORD_SALT_KEY = "pw_salt";
constexpr const char* PASSWORD_ITER_KEY = "pw_iter";
constexpr const char* WRAP_IV_KEY = "sk_iv";
constexpr const char* WRAP_TAG_KEY = "sk_tag";
constexpr const char* WRAP_CIPHERTEXT_KEY = "sk_ct";
constexpr const char* FILESYSTEM_SALT_KEY = "fs_salt";

constexpr char KEY_WRAP_AAD[] = "M5PAGER_SK_WRAP_V1";
constexpr char FILE_AAD[] = "M5PAGER_FILE_V1";
constexpr char FILESYSTEM_DERIVE_CONTEXT[] = "M5PAGER_FS_KEY_V1";

struct DeviceKeyRuntime {
    bool ready = false;
    bool filesystemReady = false;
    DeviceKeyProvisionState state = DeviceKeyProvisionState::Error;
    uint8_t privateKey[DEVICE_PRIVATE_KEY_LEN] = {0};
    uint8_t filesystemKey[FILESYSTEM_KEY_LEN] = {0};
};

inline DeviceKeyRuntime& deviceKeyRuntime() {
    static DeviceKeyRuntime runtime;
    return runtime;
}

inline void secureZero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

inline bool initNvsStorage() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        err = nvs_flash_erase();
        if (err != ESP_OK) {
            return false;
        }
        err = nvs_flash_init();
    }
    return err == ESP_OK;
}

inline bool readBlobExact(nvs_handle_t handle, const char* key, uint8_t* out, size_t expectedLen) {
    if (out == nullptr || expectedLen == 0) return false;

    size_t len = 0;
    esp_err_t err = nvs_get_blob(handle, key, nullptr, &len);
    if (err != ESP_OK || len != expectedLen) return false;

    len = expectedLen;
    err = nvs_get_blob(handle, key, out, &len);
    return err == ESP_OK && len == expectedLen;
}

inline bool derivePasswordWrapKey(const String& password,
                                  const uint8_t salt[PASSWORD_SALT_LEN],
                                  uint32_t iterations,
                                  uint8_t outKey[PASSWORD_WRAP_KEY_LEN]) {
    if (password.length() == 0) return false;

    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mdInfo == nullptr) return false;

    mbedtls_md_context_t mdCtx;
    mbedtls_md_init(&mdCtx);
    int rc = mbedtls_md_setup(&mdCtx, mdInfo, 1);
    if (rc == 0) {
        rc = mbedtls_pkcs5_pbkdf2_hmac(
            &mdCtx,
            reinterpret_cast<const unsigned char*>(password.c_str()),
            password.length(),
            salt,
            PASSWORD_SALT_LEN,
            iterations,
            PASSWORD_WRAP_KEY_LEN,
            outKey);
    }
    mbedtls_md_free(&mdCtx);
    return rc == 0;
}

inline bool aesGcmEncrypt(const uint8_t key[32],
                          const uint8_t* input,
                          size_t inputLen,
                          const uint8_t* aad,
                          size_t aadLen,
                          uint8_t iv[GCM_IV_LEN],
                          uint8_t* output,
                          uint8_t tag[GCM_TAG_LEN]) {
    if (key == nullptr || (inputLen > 0 && (input == nullptr || output == nullptr))) return false;
    if (aad == nullptr || aadLen == 0) return false;

    esp_fill_random(iv, GCM_IV_LEN);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_crypt_and_tag(&gcm,
                                       MBEDTLS_GCM_ENCRYPT,
                                       inputLen,
                                       iv,
                                       GCM_IV_LEN,
                                       aad,
                                       aadLen,
                                       input,
                                       output,
                                       GCM_TAG_LEN,
                                       tag);
    }

    mbedtls_gcm_free(&gcm);
    return rc == 0;
}

inline bool aesGcmDecrypt(const uint8_t key[32],
                          const uint8_t* input,
                          size_t inputLen,
                          const uint8_t* aad,
                          size_t aadLen,
                          const uint8_t iv[GCM_IV_LEN],
                          const uint8_t tag[GCM_TAG_LEN],
                          uint8_t* output) {
    if (key == nullptr || (inputLen > 0 && (input == nullptr || output == nullptr))) return false;
    if (aad == nullptr || aadLen == 0 || iv == nullptr || tag == nullptr) return false;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_auth_decrypt(&gcm,
                                      inputLen,
                                      iv,
                                      GCM_IV_LEN,
                                      aad,
                                      aadLen,
                                      tag,
                                      GCM_TAG_LEN,
                                      input,
                                      output);
    }

    mbedtls_gcm_free(&gcm);
    return rc == 0;
}

inline bool deriveFilesystemKey(const uint8_t privateKey[DEVICE_PRIVATE_KEY_LEN],
                                const uint8_t fsSalt[FILESYSTEM_SALT_LEN],
                                uint8_t outKey[FILESYSTEM_KEY_LEN]) {
    if (privateKey == nullptr || fsSalt == nullptr || outKey == nullptr) return false;

    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mdInfo == nullptr) return false;

    constexpr size_t ctxLen = sizeof(FILESYSTEM_DERIVE_CONTEXT) - 1;
    constexpr size_t inputLen = ctxLen + FILESYSTEM_SALT_LEN;
    uint8_t input[inputLen];
    memcpy(input, FILESYSTEM_DERIVE_CONTEXT, ctxLen);
    memcpy(input + ctxLen, fsSalt, FILESYSTEM_SALT_LEN);

    int rc = mbedtls_md_hmac(mdInfo, privateKey, DEVICE_PRIVATE_KEY_LEN, input, inputLen, outKey);
    secureZero(input, inputLen);
    return rc == 0;
}

inline String maskPassword(const String& password) {
    String masked = "";
    masked.reserve(password.length());
    for (size_t i = 0; i < password.length(); i++) {
        masked += '*';
    }
    return masked;
}

inline int waitForKeyboardKey() {
    while (true) {
        M5Cardputer.update();
        int key = 0;

        for (char c = 32; c <= 126; c++) {
            if (M5Cardputer.Keyboard.isKeyPressed(c)) {
                key = c;
                break;
            }
        }

        if (M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) key = KEY_ENTER;
        if (M5Cardputer.Keyboard.isKeyPressed(KEY_BACKSPACE)) key = KEY_BACKSPACE;

        if (key != 0) {
            delay(150);
            return key;
        }
        delay(10);
    }
}

inline void drawPasswordPrompt(const char* title, const String& password, const char* footer = nullptr) {
    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);
    M5Cardputer.Display.setTextColor(WHITE, BLACK);

    M5Cardputer.Display.println(title);
    M5Cardputer.Display.println("----------------");
    M5Cardputer.Display.println(maskPassword(password));
    M5Cardputer.Display.println("");
    M5Cardputer.Display.println("[ENTER] Confirm");
    M5Cardputer.Display.println("[BKSP ] Delete");
    if (footer != nullptr) {
        M5Cardputer.Display.println(footer);
    }
}

inline void showPasswordMessage(const char* msg, uint16_t color = WHITE, uint16_t waitMs = 1000) {
    M5Cardputer.Display.setTextColor(color, BLACK);
    M5Cardputer.Display.println(msg);
    delay(waitMs);
}

inline bool capturePassword(const char* title, String& outPassword, size_t maxLen = 32) {
    outPassword = "";
    while (true) {
        drawPasswordPrompt(title, outPassword);
        int key = waitForKeyboardKey();

        if (key == KEY_ENTER) {
            if (outPassword.length() == 0) {
                showPasswordMessage("Password cannot be empty", RED, 900);
                continue;
            }
            return true;
        }

        if (key == KEY_BACKSPACE) {
            if (outPassword.length() > 0) {
                outPassword.remove(outPassword.length() - 1);
            }
            continue;
        }

        if (key >= 32 && key <= 126 && outPassword.length() < maxLen) {
            outPassword += static_cast<char>(key);
        }
    }
}

inline bool buildRuntimeKeys(const uint8_t privateKey[DEVICE_PRIVATE_KEY_LEN],
                             const uint8_t fsSalt[FILESYSTEM_SALT_LEN],
                             DeviceKeyProvisionState state) {
    DeviceKeyRuntime& runtime = deviceKeyRuntime();
    memcpy(runtime.privateKey, privateKey, DEVICE_PRIVATE_KEY_LEN);
    if (!deriveFilesystemKey(privateKey, fsSalt, runtime.filesystemKey)) {
        secureZero(runtime.privateKey, DEVICE_PRIVATE_KEY_LEN);
        secureZero(runtime.filesystemKey, FILESYSTEM_KEY_LEN);
        runtime.ready = false;
        runtime.filesystemReady = false;
        runtime.state = DeviceKeyProvisionState::Error;
        return false;
    }

    runtime.ready = true;
    runtime.filesystemReady = true;
    runtime.state = state;
    return true;
}

inline bool setupPasswordProtection(nvs_handle_t handle,
                                    const uint8_t privateKey[DEVICE_PRIVATE_KEY_LEN],
                                    bool hadLegacyUnwrappedKey,
                                    bool generatedFreshKey) {
    String password;
    String passwordConfirm;

    while (true) {
        if (!capturePassword("Set unlock password", password)) {
            return false;
        }
        if (password.length() < 6) {
            showPasswordMessage("Min length is 6 chars", RED, 1000);
            continue;
        }

        if (!capturePassword("Confirm password", passwordConfirm)) {
            return false;
        }
        if (password != passwordConfirm) {
            showPasswordMessage("Passwords do not match", RED, 1200);
            continue;
        }
        break;
    }

    uint8_t passwordSalt[PASSWORD_SALT_LEN];
    uint8_t fsSalt[FILESYSTEM_SALT_LEN];
    uint8_t wrapKey[PASSWORD_WRAP_KEY_LEN];
    uint8_t wrappedPrivateKey[DEVICE_PRIVATE_KEY_LEN];
    uint8_t wrapIv[GCM_IV_LEN];
    uint8_t wrapTag[GCM_TAG_LEN];

    esp_fill_random(passwordSalt, PASSWORD_SALT_LEN);
    esp_fill_random(fsSalt, FILESYSTEM_SALT_LEN);

    bool ok = derivePasswordWrapKey(password, passwordSalt, PASSWORD_KDF_ITERATIONS, wrapKey);
    password = "";
    passwordConfirm = "";

    if (!ok) {
        secureZero(passwordSalt, PASSWORD_SALT_LEN);
        secureZero(fsSalt, FILESYSTEM_SALT_LEN);
        secureZero(wrapKey, PASSWORD_WRAP_KEY_LEN);
        return false;
    }

    ok = aesGcmEncrypt(wrapKey,
                       privateKey,
                       DEVICE_PRIVATE_KEY_LEN,
                       reinterpret_cast<const uint8_t*>(KEY_WRAP_AAD),
                       strlen(KEY_WRAP_AAD),
                       wrapIv,
                       wrappedPrivateKey,
                       wrapTag);
    secureZero(wrapKey, PASSWORD_WRAP_KEY_LEN);
    if (!ok) {
        secureZero(passwordSalt, PASSWORD_SALT_LEN);
        secureZero(fsSalt, FILESYSTEM_SALT_LEN);
        secureZero(wrappedPrivateKey, DEVICE_PRIVATE_KEY_LEN);
        secureZero(wrapIv, GCM_IV_LEN);
        secureZero(wrapTag, GCM_TAG_LEN);
        return false;
    }

    esp_err_t err = ESP_OK;
    err = nvs_set_u8(handle, WRAP_MARKER_KEY, 1);
    if (err == ESP_OK) err = nvs_set_u32(handle, PASSWORD_ITER_KEY, PASSWORD_KDF_ITERATIONS);
    if (err == ESP_OK) err = nvs_set_blob(handle, PASSWORD_SALT_KEY, passwordSalt, PASSWORD_SALT_LEN);
    if (err == ESP_OK) err = nvs_set_blob(handle, FILESYSTEM_SALT_KEY, fsSalt, FILESYSTEM_SALT_LEN);
    if (err == ESP_OK) err = nvs_set_blob(handle, WRAP_IV_KEY, wrapIv, GCM_IV_LEN);
    if (err == ESP_OK) err = nvs_set_blob(handle, WRAP_TAG_KEY, wrapTag, GCM_TAG_LEN);
    if (err == ESP_OK) err = nvs_set_blob(handle, WRAP_CIPHERTEXT_KEY, wrappedPrivateKey, DEVICE_PRIVATE_KEY_LEN);
    if (err == ESP_OK && hadLegacyUnwrappedKey) err = nvs_erase_key(handle, LEGACY_DEVICE_KEY_NAME);
    if (err == ESP_OK) err = nvs_commit(handle);

    secureZero(passwordSalt, PASSWORD_SALT_LEN);
    secureZero(wrappedPrivateKey, DEVICE_PRIVATE_KEY_LEN);
    secureZero(wrapIv, GCM_IV_LEN);
    secureZero(wrapTag, GCM_TAG_LEN);

    if (err != ESP_OK) {
        secureZero(fsSalt, FILESYSTEM_SALT_LEN);
        return false;
    }

    DeviceKeyProvisionState state = generatedFreshKey
                                        ? DeviceKeyProvisionState::CreatedNew
                                        : DeviceKeyProvisionState::LoadedExisting;
    bool runtimeOk = buildRuntimeKeys(privateKey, fsSalt, state);
    secureZero(fsSalt, FILESYSTEM_SALT_LEN);
    return runtimeOk;
}

inline bool unlockExistingKey(nvs_handle_t handle) {
    uint8_t passwordSalt[PASSWORD_SALT_LEN];
    uint8_t fsSalt[FILESYSTEM_SALT_LEN];
    uint8_t wrapIv[GCM_IV_LEN];
    uint8_t wrapTag[GCM_TAG_LEN];
    uint8_t wrappedPrivateKey[DEVICE_PRIVATE_KEY_LEN];
    uint32_t iterations = 0;

    if (!readBlobExact(handle, PASSWORD_SALT_KEY, passwordSalt, PASSWORD_SALT_LEN) ||
        !readBlobExact(handle, FILESYSTEM_SALT_KEY, fsSalt, FILESYSTEM_SALT_LEN) ||
        !readBlobExact(handle, WRAP_IV_KEY, wrapIv, GCM_IV_LEN) ||
        !readBlobExact(handle, WRAP_TAG_KEY, wrapTag, GCM_TAG_LEN) ||
        !readBlobExact(handle, WRAP_CIPHERTEXT_KEY, wrappedPrivateKey, DEVICE_PRIVATE_KEY_LEN) ||
        nvs_get_u32(handle, PASSWORD_ITER_KEY, &iterations) != ESP_OK ||
        iterations == 0) {
        secureZero(passwordSalt, PASSWORD_SALT_LEN);
        secureZero(fsSalt, FILESYSTEM_SALT_LEN);
        secureZero(wrapIv, GCM_IV_LEN);
        secureZero(wrapTag, GCM_TAG_LEN);
        secureZero(wrappedPrivateKey, DEVICE_PRIVATE_KEY_LEN);
        return false;
    }

    String password;
    uint8_t wrapKey[PASSWORD_WRAP_KEY_LEN];
    uint8_t privateKey[DEVICE_PRIVATE_KEY_LEN];

    while (true) {
        if (!capturePassword("Unlock data", password)) {
            secureZero(passwordSalt, PASSWORD_SALT_LEN);
            secureZero(fsSalt, FILESYSTEM_SALT_LEN);
            secureZero(wrapIv, GCM_IV_LEN);
            secureZero(wrapTag, GCM_TAG_LEN);
            secureZero(wrappedPrivateKey, DEVICE_PRIVATE_KEY_LEN);
            return false;
        }

        bool ok = derivePasswordWrapKey(password, passwordSalt, iterations, wrapKey);
        password = "";
        if (!ok) {
            showPasswordMessage("KDF error", RED, 1200);
            continue;
        }

        ok = aesGcmDecrypt(wrapKey,
                           wrappedPrivateKey,
                           DEVICE_PRIVATE_KEY_LEN,
                           reinterpret_cast<const uint8_t*>(KEY_WRAP_AAD),
                           strlen(KEY_WRAP_AAD),
                           wrapIv,
                           wrapTag,
                           privateKey);
        secureZero(wrapKey, PASSWORD_WRAP_KEY_LEN);

        if (!ok) {
            secureZero(privateKey, DEVICE_PRIVATE_KEY_LEN);
            showPasswordMessage("Wrong password", RED, 1200);
            continue;
        }

        bool runtimeOk = buildRuntimeKeys(privateKey, fsSalt, DeviceKeyProvisionState::LoadedExisting);
        secureZero(privateKey, DEVICE_PRIVATE_KEY_LEN);
        secureZero(passwordSalt, PASSWORD_SALT_LEN);
        secureZero(fsSalt, FILESYSTEM_SALT_LEN);
        secureZero(wrapIv, GCM_IV_LEN);
        secureZero(wrapTag, GCM_TAG_LEN);
        secureZero(wrappedPrivateKey, DEVICE_PRIVATE_KEY_LEN);
        return runtimeOk;
    }
}

inline uint32_t fnv1a32(const uint8_t* data, size_t len) {
    uint32_t hash = 2166136261UL;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619UL;
    }
    return hash;
}

inline DeviceKeyProvisionState ensureDevicePrivateKey() {
    DeviceKeyRuntime& runtime = deviceKeyRuntime();
    if (runtime.ready) {
        return runtime.state;
    }

    if (!initNvsStorage()) {
        runtime.state = DeviceKeyProvisionState::Error;
        return runtime.state;
    }

    nvs_handle_t nvsHandle = 0;
    esp_err_t err = nvs_open(DEVICE_KEY_NAMESPACE, NVS_READWRITE, &nvsHandle);
    if (err != ESP_OK) {
        runtime.state = DeviceKeyProvisionState::Error;
        return runtime.state;
    }

    uint8_t wrappedMarker = 0;
    bool hasWrappedKey = (nvs_get_u8(nvsHandle, WRAP_MARKER_KEY, &wrappedMarker) == ESP_OK && wrappedMarker == 1);

    bool ok = false;
    if (hasWrappedKey) {
        ok = unlockExistingKey(nvsHandle);
        nvs_close(nvsHandle);
        if (!ok) {
            runtime.state = DeviceKeyProvisionState::Error;
            runtime.ready = false;
            runtime.filesystemReady = false;
        }
        return runtime.state;
    }

    uint8_t privateKey[DEVICE_PRIVATE_KEY_LEN];
    bool hasLegacyUnwrappedKey = readBlobExact(nvsHandle, LEGACY_DEVICE_KEY_NAME, privateKey, DEVICE_PRIVATE_KEY_LEN);
    bool generatedFreshKey = false;
    if (!hasLegacyUnwrappedKey) {
        esp_fill_random(privateKey, DEVICE_PRIVATE_KEY_LEN);
        generatedFreshKey = true;
    }

    ok = setupPasswordProtection(nvsHandle, privateKey, hasLegacyUnwrappedKey, generatedFreshKey);
    secureZero(privateKey, DEVICE_PRIVATE_KEY_LEN);
    nvs_close(nvsHandle);

    if (!ok) {
        runtime.state = DeviceKeyProvisionState::Error;
        runtime.ready = false;
        runtime.filesystemReady = false;
    }
    return runtime.state;
}

inline bool hasDevicePrivateKey() {
    return deviceKeyRuntime().ready;
}

inline const uint8_t* getDevicePrivateKey() {
    const DeviceKeyRuntime& runtime = deviceKeyRuntime();
    if (!runtime.ready) {
        return nullptr;
    }
    return runtime.privateKey;
}

inline bool hasFilesystemKey() {
    const DeviceKeyRuntime& runtime = deviceKeyRuntime();
    return runtime.ready && runtime.filesystemReady;
}

inline const uint8_t* getFilesystemKey() {
    const DeviceKeyRuntime& runtime = deviceKeyRuntime();
    if (!runtime.ready || !runtime.filesystemReady) {
        return nullptr;
    }
    return runtime.filesystemKey;
}

inline bool encryptFilesystemBuffer(const uint8_t* plaintext,
                                    size_t plaintextLen,
                                    uint8_t iv[GCM_IV_LEN],
                                    uint8_t* ciphertext,
                                    uint8_t tag[GCM_TAG_LEN]) {
    const uint8_t* key = getFilesystemKey();
    if (key == nullptr) return false;

    return aesGcmEncrypt(key,
                         plaintext,
                         plaintextLen,
                         reinterpret_cast<const uint8_t*>(FILE_AAD),
                         strlen(FILE_AAD),
                         iv,
                         ciphertext,
                         tag);
}

inline bool decryptFilesystemBuffer(const uint8_t* ciphertext,
                                    size_t ciphertextLen,
                                    const uint8_t iv[GCM_IV_LEN],
                                    const uint8_t tag[GCM_TAG_LEN],
                                    uint8_t* plaintext) {
    const uint8_t* key = getFilesystemKey();
    if (key == nullptr) return false;

    return aesGcmDecrypt(key,
                         ciphertext,
                         ciphertextLen,
                         reinterpret_cast<const uint8_t*>(FILE_AAD),
                         strlen(FILE_AAD),
                         iv,
                         tag,
                         plaintext);
}

inline String getDeviceKeyFingerprint() {
    const DeviceKeyRuntime& runtime = deviceKeyRuntime();
    if (!runtime.ready) {
        return "UNSET";
    }

    uint32_t fingerprint = fnv1a32(runtime.privateKey, DEVICE_PRIVATE_KEY_LEN);
    char out[9];
    snprintf(out, sizeof(out), "%08lX", static_cast<unsigned long>(fingerprint));
    return String(out);
}

}  // namespace Security
