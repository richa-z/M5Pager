#pragma once

#include "menus.h"
#include "gui_handlers.h"
#include <M5Cardputer.h>
#include <ArduinoJson.h>
#include <json_management.h>
#include "util/text_input.h"
#include "util/network_util.h"

extern MenuState currentMenu;
extern DynamicJsonDocument config;
extern int menuIndex;

String newWifiSsid = "";
String newWifiPass = "";

/// @brief Vráti sa do nastavení a zahodí rozpísanú hodnotu.
static void cancelWifiEdit() {
    newWifiSsid = "";
    newWifiPass = "";
    menuIndex = 0;
    currentMenu = MENU_SETTINGS;
}

/// @brief Otvorí úpravu SSID s predvyplnenou aktuálnou hodnotou.
void beginSsidEdit() {
    newWifiSsid = config["wifi_ssid"] | "";
    menuIndex = 0;
    currentMenu = MENU_CHANGE_SSID;
}

/// @brief Otvorí úpravu hesla siete. Staré heslo sa zámerne nepredvypĺňa.
void beginSsidPassEdit() {
    newWifiPass = "";
    menuIndex = 0;
    currentMenu = MENU_CHANGE_SSID_PASS;
}

void drawChangeSsid() {
    beginScreenFrame();
    drawSectionTitle("WIFI SSID");
    drawInputCard("Network name", newWifiSsid, "e.g. PAGER_COM", UI_CONTENT_TOP_Y + 20, 24);
    drawHintLine("All devices must use the same SSID", UI_CONTENT_TOP_Y + 48, uiTextMutedColor());
    drawHintLine("` Back    Enter Save", UI_CONTENT_TOP_Y + 58, uiTextMutedColor());
}

void handleChangeSsidInput(int key) {
    if (key == '`') {
        cancelWifiEdit();
        return;
    }

    if (key == KEY_ENTER) {
        if (!isValidSsid(newWifiSsid)) {
            drawChangeSsid();
            showErrorToast("SSID must be 1-32 chars");
            drawChangeSsid();
            return;
        }

        config["wifi_ssid"] = newWifiSsid;
        if (!saveConfig(config, "/m5pager/config.json")) {
            drawChangeSsid();
            showErrorToast("Failed to save config");
            return;
        }

        drawChangeSsid();
        showSuccessToast("Saved - reboot to apply", 1200);
        cancelWifiEdit();
        return;
    }

    if (handleTextInput(key, newWifiSsid, WIFI_SSID_MAX_LEN)) {
        drawChangeSsid();
    }
}

void drawChangeSsidPass() {
    beginScreenFrame();
    drawSectionTitle("WIFI PASSWORD");
    drawInputCard("Network password", newWifiPass, "min 8 chars", UI_CONTENT_TOP_Y + 20, 24);
    drawHintLine("WPA2 requires 8-63 characters", UI_CONTENT_TOP_Y + 48, uiTextMutedColor());
    drawHintLine("` Back    Enter Save", UI_CONTENT_TOP_Y + 58, uiTextMutedColor());
}

void handleChangeSsidPassInput(int key) {
    if (key == '`') {
        cancelWifiEdit();
        return;
    }

    if (key == KEY_ENTER) {
        if (!isValidWifiPassword(newWifiPass)) {
            drawChangeSsidPass();
            showErrorToast("Password must be 8-63 chars");
            drawChangeSsidPass();
            return;
        }

        config["wifi_pass"] = newWifiPass;
        if (!saveConfig(config, "/m5pager/config.json")) {
            drawChangeSsidPass();
            showErrorToast("Failed to save config");
            return;
        }

        drawChangeSsidPass();
        showSuccessToast("Saved - reboot to apply", 1200);
        cancelWifiEdit();
        return;
    }

    if (handleTextInput(key, newWifiPass, WIFI_PASS_MAX_LEN)) {
        drawChangeSsidPass();
    }
}
