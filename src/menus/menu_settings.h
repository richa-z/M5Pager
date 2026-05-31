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
        menuIndex = 0;
        currentMenu = MENU_MAIN;
    } else if (key == ';') {
        if (menuIndex == 0) return;
        menuIndex--;
        drawSettingsMenu();
    } else if (key == '.') {
        if (menuIndex == 1) return;
        menuIndex++;
        drawSettingsMenu();
    } else if (key == KEY_ENTER) {
        switch (menuIndex) {
            case 0: //zmena username
                menuIndex = 0;
                currentMenu = MENU_CHANGE_USERNAME;
                break;
            case 1: //mac adresa - read-only, takže žiadna akcia
                break;
        }
    }
}