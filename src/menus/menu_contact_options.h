#pragma once

#include <M5Cardputer.h>
#include "menus.h"
#include "gui_handlers.h"
#include "json_management.h"

extern MenuState currentMenu;
extern int menuIndex;
extern const char* selectedContact;
extern DynamicJsonDocument contacts;
extern String editContactName;

const char* contactOptions[] = {
    "Edit Username",
    "Delete Contact",
    "Back"
};

constexpr int CONTACT_OPTIONS_SIZE = 3;

void drawContactOptions() {
    beginScreenFrame();

    M5Cardputer.Display.println("Contact Options");
    drawSeparator();

    for (int i = 0; i < CONTACT_OPTIONS_SIZE; i++) {
        if (i == menuIndex)
            M5Cardputer.Display.setTextColor(BLACK, WHITE);
        else
            M5Cardputer.Display.setTextColor(WHITE, BLACK);

        M5Cardputer.Display.println(contactOptions[i]);
    }
}

void handleContactOptionsInput(int key) {
    if (key == KEY_BACKSPACE) {
        currentMenu = MENU_MESSAGE;
        return;
    }

    if (key == ';') {
        menuIndex = (menuIndex - 1 + CONTACT_OPTIONS_SIZE) % CONTACT_OPTIONS_SIZE;
        drawContactOptions();
        return;
    }

    if (key == '.') {
        menuIndex = (menuIndex + 1) % CONTACT_OPTIONS_SIZE;
        drawContactOptions();
        return;
    }

    if (key == KEY_ENTER) {
        switch (menuIndex) {
            case 0: // Edit name
                editContactName = contacts[selectedContact]["username"].as<String>();
                currentMenu = MENU_EDIT_CONTACT;
                break;

            case 1: // Delete
                contacts.remove(selectedContact);
                saveContacts(contacts, "/m5pager/contacts.json");
                selectedContact = nullptr;
                currentMenu = MENU_CONTACTS;
                break;

            case 2: // Back
                currentMenu = MENU_MESSAGE;
                break;
        }
    }
}
