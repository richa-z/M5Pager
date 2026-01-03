#pragma once

#include <M5Cardputer.h>
#include "menus.h"
#include "gui_handlers.h"

extern MenuState currentMenu;
extern int menuIndex;
extern const char* selectedContact;
extern DynamicJsonDocument contacts;

void drawMessageMenu() {
    drawMessages(contacts, selectedContact);
}

void handleMessageInput(int key) {
    if (key == KEY_BACKSPACE) {
        currentMenu = MENU_CONTACTS;
    }

    if (key == '`') {
        menuIndex = 0;
        currentMenu = MENU_CONTACT_OPTIONS;
        return;
    }
    // TODO: Implement message sending, scrolling, etc.
}