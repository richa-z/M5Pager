#pragma once
#include <M5Cardputer.h>
#include "menus.h"
#include "gui_handlers.h"

extern DynamicJsonDocument contacts;
extern int menuIndex;
extern const char* selectedContact;

void drawContactsMenu() {
    selectedContact = drawContacts(contacts, menuIndex);
}

void handleContactsMenuInput(int key) {
    //TODO: Implement contact menu input handling here
    if (key == KEY_BACKSPACE) {
        currentMenu = MENU_MAIN;
    } else if (key == ';') {
        menuIndex = (menuIndex - 1 + mainMenuSize) % mainMenuSize;
        drawContactsMenu();
    } else if (key == '.') {
        menuIndex = (menuIndex + 1) % mainMenuSize;
        drawContactsMenu();
    }
    else if (key == KEY_ENTER) {
        if (selectedContact != nullptr) {
            currentMenu = MENU_MESSAGE;
        }
    }
}
