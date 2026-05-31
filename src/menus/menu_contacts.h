#pragma once
#include <M5Cardputer.h>
#include "menus.h"
#include "gui_handlers.h"

extern DynamicJsonDocument contacts;
extern int menuIndex;
extern const char* selectedContact;
bool selectContactPeer(const char* contactMac);

void drawContactsMenu() {
    selectedContact = drawContacts(contacts, menuIndex);
}

void handleContactsMenuInput(int key) {
    
    if (key == KEY_BACKSPACE) {
        currentMenu = MENU_MAIN;
        return;
    }

    int totalItems = contactsSize + 1;
    
    if (key == ';') {
        menuIndex = (menuIndex - 1 + totalItems) % totalItems;
        drawContactsMenu();
    } else if (key == '.') {
        menuIndex = (menuIndex + 1) % totalItems;
        drawContactsMenu();
    }
    else if (key == KEY_ENTER) {
        if (selectedContact == nullptr)  return;

        if (strcmp(selectedContact, "ADD_CONTACT_BTN") != 0) {
            if (!selectContactPeer(selectedContact)) {
                drawContactsMenu();
                showErrorToast("Invalid contact MAC");
                drawContactsMenu();
                return;
            }
            messageScroll = 0;
            currentMenu = MENU_MESSAGE;
        } else {
            currentMenu = MENU_ADD_CONTACT; 
        }
    }
}
