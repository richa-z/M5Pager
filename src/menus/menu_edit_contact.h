#pragma once

#include <M5Cardputer.h>
#include "menus.h"
#include <ArduinoJson.h>
#include "gui_handlers.h"
#include "json_management.h"
#include "util/text_input.h"

extern MenuState currentMenu;
extern DynamicJsonDocument contacts;
extern String editContactName;
extern const char* selectedContact;


void drawEditContact() {
    beginScreenFrame();
    M5Cardputer.Display.setTextColor(WHITE, BLACK);

    M5Cardputer.Display.println("Edit Contact");
    drawSeparator();
    M5Cardputer.Display.println("New name:");
    M5Cardputer.Display.println(editContactName);
    M5Cardputer.Display.println("");
    M5Cardputer.Display.println("[ENTER] Save");
    M5Cardputer.Display.println("[` ] Cancel");
}

void handleEditContactInput(int key) {
    if (key == '`') {
        editContactName = "";
        currentMenu = MENU_CONTACT_OPTIONS;
        return;
    }

    if (key == KEY_ENTER) {
        if (editContactName.length() == 0) return;

        contacts[selectedContact]["username"] = editContactName;
        saveContacts(contacts, "/m5pager/contacts.json");

        editContactName = "";
        currentMenu = MENU_MESSAGE;
        return;
    }

    if (handleTextInput(key, editContactName, 16)) {
        drawEditContact();
    }
}
