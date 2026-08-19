#pragma once

#include <M5Cardputer.h>
#include "menus.h"
#include "gui_handlers.h"
#include "json_management.h"
#include "security/message_crypto.h"

extern MenuState currentMenu;
extern int menuIndex;
extern String selectedContact;
extern DynamicJsonDocument contacts;
extern String editContactName;
bool requestKeyExchange(const char* contactMac);
void clearSession(const String& contactKey);

const char* contactOptions[] = {
    "Start Key Exchange",
    "Edit Username",
    "Delete Contact",
    "Back"
};

constexpr int CONTACT_OPTIONS_SIZE = 4;

/// @brief Nakreslí obrazovku s možnosťami pre aktuálne vybraný kontakt (D:).
void drawContactOptions() {
    beginScreenFrame();
    drawSectionTitle("CONTACT");

    String contactName = "Unknown";
    if (selectedContact.length() > 0 && contacts.containsKey(selectedContact)) {
        contactName = contacts[selectedContact]["username"] | "Unknown";
    }

    String keyLabel;
    if (MessageCrypto::hasPendingRekeyOffer(contacts, selectedContact)) {
        keyLabel = "Re-key requested - verify!";
    } else if (MessageCrypto::hasReadySession(contacts, selectedContact)) {
        keyLabel = "Secure - " + MessageCrypto::getSessionFingerprint(contacts, selectedContact);
    } else {
        keyLabel = "Selected contact - no key";
    }
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
                // Prichadzajuci paket ju prepisať nemoze -> handleKeyExchangePacket
                clearSession(selectedContact);
                if (requestKeyExchange(selectedContact.c_str())) {
                    drawContactOptions();
                    showSuccessToast("Key exchange started", 700);
                } else {
                    drawContactOptions();
                    showErrorToast("Key exchange failed");
                }
                break;

            case 1: // Edit name
                editContactName = contacts[selectedContact]["username"] | "";
                currentMenu = MENU_EDIT_CONTACT;
                break;

            case 2: // Delete
                contacts.remove(selectedContact);
                saveContacts(contacts, "/m5pager/contacts.json");
                selectedContact = "";
                currentMenu = MENU_CONTACTS;
                break;

            case 3: // Back
                currentMenu = MENU_MESSAGE;
                break;
        }
    }
}
