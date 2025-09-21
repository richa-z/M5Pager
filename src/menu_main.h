#pragma once

#include "gui_handlers.h"
#include "menus.h"

extern int menuIndex;
extern const char* mainMenuItems[];
extern const int mainMenuSize;

void drawMainMenu() {
    drawMenu(mainMenuItems, mainMenuSize, menuIndex);
}

void handleMainMenuInput(int key) {
    if (key == ';') {
        menuIndex = (menuIndex - 1 + mainMenuSize) % mainMenuSize;
        drawMainMenu();
    } else if (key == '.') {
        menuIndex = (menuIndex + 1) % mainMenuSize;
        drawMainMenu();
    } else if (key == KEY_ENTER) {
        switch (menuIndex) {
            case 0: currentMenu = MENU_CONTACTS; break;
            case 1: currentMenu = MENU_NETWORK; break;
            case 2: currentMenu = MENU_SETTINGS; break;
        }
    }
}