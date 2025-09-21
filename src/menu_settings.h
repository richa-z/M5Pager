#pragma once

#include "menus.h"
#include "gui_handlers.h"
#include <M5Cardputer.h>
#include <ArduinoJson.h>

extern MenuState currentMenu;
extern DynamicJsonDocument config;
extern int menuIndex;

void drawSettingsMenu() {
    drawSettings(menuIndex);
}

void handleSettingsMenuInput(int key) {
    if (key == KEY_BACKSPACE) {
        currentMenu = MENU_MAIN;
    }

    
}