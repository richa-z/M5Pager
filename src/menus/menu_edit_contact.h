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
extern String selectedContact;


void drawEditContact() {
    beginScreenFrame();
    drawSectionTitle("EDIT CONTACT");
    drawInputCard("Username", editContactName, "type new name", UI_CONTENT_TOP_Y + 24, 30);
    drawHintLine("Enter Save", UI_CONTENT_TOP_Y + 58, uiAccentColor());
    drawHintLine("` Cancel", UI_CONTENT_TOP_Y + 68, uiTextMutedColor());
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
