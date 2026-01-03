#include <WiFi.h>

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