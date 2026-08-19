#pragma once

#include "menus.h"
#include "gui_handlers.h"
#include <M5Cardputer.h>
#include <ArduinoJson.h>

extern MenuState currentMenu;
extern DynamicJsonDocument config;
extern int menuIndex;

void beginSsidEdit();
void beginSsidPassEdit();

void lockAndPrompt();

void drawSettingsMenu() {
    drawSettings(menuIndex);
}

void handleSettingsMenuInput(int key) {
    if (key == KEY_BACKSPACE) {
        menuIndex = 0;
        currentMenu = MENU_MAIN;
    } else if (key == ';') {
        if (menuIndex == 0) return;
        menuIndex--;
        drawSettingsMenu();
    } else if (key == '.') {
        if (menuIndex >= SETTINGS_COUNT - 1) return;
        menuIndex++;
        drawSettingsMenu();
    } else if (key == KEY_ENTER) {
        switch (menuIndex) {
            case SETTINGS_USERNAME:
                menuIndex = 0;
                currentMenu = MENU_CHANGE_USERNAME;
                break;
            case SETTINGS_WIFI_SSID:
                beginSsidEdit();
                break;
            case SETTINGS_WIFI_PASS:
                beginSsidPassEdit();
                break;
            case SETTINGS_LOCK:
                menuIndex = 0;
                lockAndPrompt();
                break;
            case SETTINGS_MAC: //read only
                break;
        }
    }
}