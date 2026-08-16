#pragma once
#include <M5Cardputer.h>
#include "menus.h"
#include "gui_handlers.h"

extern DynamicJsonDocument contacts;
extern int menuIndex;
extern String selectedContact;
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
        if (selectedContact.length() == 0) return;

        if (selectedContact != "ADD_CONTACT_BTN") {
            if (!selectContactPeer(selectedContact.c_str())) {
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
