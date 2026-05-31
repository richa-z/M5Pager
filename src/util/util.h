#pragma once

#include <SD.h>

/// @brief Skontroluje, či súbor existuje.
/// @param path Cesta k súboru
/// @return TRUE, ak súbor existuje, inak FALSE
bool fileExists(const char* path) {
    File f = SD.open(path, FILE_READ);
    if (f) {
        f.close();
        return true;
    }
    return false;
}

/// @brief Prevedie MAC adresu na string.
/// @param mac MAC adresa jako pole 6 bajtov
/// @return String reprezentujúci MAC adresu vo formáte "XX:XX:XX:XX:XX:XX"
String macToString(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}
