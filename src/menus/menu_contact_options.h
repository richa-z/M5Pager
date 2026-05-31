#pragma once

#include <M5Cardputer.h>
#include "menus.h"
#include "gui_handlers.h"
#include "json_management.h"
#include "security/message_crypto.h"

extern MenuState currentMenu;
extern int menuIndex;
extern const char* selectedContact;
extern DynamicJsonDocument contacts;
extern String editContactName;
bool requestKeyExchange(const char* contactMac);

const char* contactOptions[] = {
    "Start Key Exchange",
    "Edit Username",
    "Delete Contact",
    "Back"
};

constexpr int CONTACT_OPTIONS_SIZE = 4;

/// @brief Nakreslí obrazovku s možnosťami pre aktuálne vybraný kontakt.
void drawContactOptions() {
    beginScreenFrame();
    drawSectionTitle("CONTACT");

    String contactName = "Unknown";
    if (selectedContact != nullptr && contacts.containsKey(selectedContact)) {
        contactName = contacts[selectedContact]["username"].as<const char*>();
    }
    String keyLabel = MessageCrypto::hasReadySession(contacts, String(selectedContact))
                          ? "Selected contact - secure"
                          : "Selected contact - no key";
    drawInputCard(keyLabel, contactName, "-", UI_CONTENT_TOP_Y + 14, 24);

    const int optionStartY = UI_CONTENT_TOP_Y + 38;
    for (int i = 0; i < CONTACT_OPTIONS_SIZE; i++) {
        drawCardRow(contactOptions[i], i, i == menuIndex, optionStartY);
        if (i == 2 && i == menuIndex) {
            int x = 4;
            int y = optionStartY + i * (UI_CARD_HEIGHT + UI_CARD_GAP);
            M5Cardputer.Display.fillRect(x, y, 3, UI_CARD_HEIGHT, uiDangerColor());
        }
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
            case 0: // Start key exchange
                if (requestKeyExchange(selectedContact)) {
                    drawContactOptions();
                    showSuccessToast("Key exchange started", 700);
                } else {
                    drawContactOptions();
                    showErrorToast("Key exchange failed");
                }
                break;

            case 1: // Edit name
                editContactName = contacts[selectedContact]["username"].as<String>();
                currentMenu = MENU_EDIT_CONTACT;
                break;

            case 2: // Delete
                contacts.remove(selectedContact);
                saveContacts(contacts, "/m5pager/contacts.json");
                selectedContact = nullptr;
                currentMenu = MENU_CONTACTS;
                break;

            case 3: // Back
                currentMenu = MENU_MESSAGE;
                break;
        }
    }
}
