#pragma once

#include <WiFi.h>
#include <cstring>
#include <stdio.h>
#include <stdint.h>

/// @brief Skontroluje či je dostupná WiFi sieť s daným SSID.
/// @param ssid Meno Wifi siete
/// @return TRUE, ak je sieť dostupná, inak FALSE
bool ScanAP(const char* ssid) {
    int ssid_amnt = WiFi.scanNetworks();
    if (ssid_amnt == -1) {
        Serial.println("[!] No networks found.");
        return false;
    } else {
        for (size_t i = 0; i < ssid_amnt; i++) {
            if (WiFi.SSID(i) == ssid) {
                return true;
            }
        }
    }
    return false;
}

/// @brief Prevedie reťazec s MAC adresou na pole bajtov.
/// @param macStr Reťazec s MAC adresou vo formáte "XX:XX:XX:XX:XX:XX"
/// @param outMac Pole 6 bajtov pre uloženie MAC adresy
/// @return TRUE, ak bol reťazec úspešne prevedený, inak FALSE
bool parseMacAddress(const char* macStr, uint8_t outMac[6]) {
    if (macStr == nullptr || outMac == nullptr) return false;
    if (strlen(macStr) != 17) return false;

    unsigned int parts[6];
    if (sscanf(macStr, "%2x:%2x:%2x:%2x:%2x:%2x",
               &parts[0], &parts[1], &parts[2],
               &parts[3], &parts[4], &parts[5]) != 6) {
        return false;
    }

    for (int i = 0; i < 6; i++) {
        outMac[i] = static_cast<uint8_t>(parts[i]);
    }
    return true;
}
