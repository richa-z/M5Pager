#pragma once

#include "menus.h"
#include "gui_handlers.h"
#include "json_management.h"
#include "enums/add_contact_type.h"

#include <M5Cardputer.h>
#include <ArduinoJson.h>

#include "util/text_input.h"
#include "util/network_util.h"
#include "util/util.h"

extern MenuState currentMenu;
extern DynamicJsonDocument contacts;

extern String newContactName = "";
extern String newContactMac  = "";

extern AddContactStep addStep = ADD_NAME;

inline const char* addContactStepLabel(AddContactStep step) {
    switch (step) {
        case ADD_NAME: return "NAME";
        case ADD_MAC: return "MAC";
        case ADD_CONFIRM: return "CONFIRM";
        default: return "";
    }
}

void drawAddContact() {
    beginScreenFrame();
    drawSectionTitle("ADD CONTACT");

    String progress = String("Step ") + String(static_cast<int>(addStep) + 1) + "/3 - " + addContactStepLabel(addStep);
    drawHintLine(progress, UI_CONTENT_TOP_Y + 14, uiTextMutedColor());

    switch (addStep) {
        case ADD_NAME:
            drawInputCard("Username", newContactName, "type contact name", UI_CONTENT_TOP_Y + 24, 30);
            drawHintLine("Enter Next", UI_CONTENT_TOP_Y + 58, uiAccentColor());
            drawHintLine("` Back", UI_CONTENT_TOP_Y + 68, uiTextMutedColor());
            break;

        case ADD_MAC:
            drawInputCard("MAC (AA:BB:CC:DD:EE:FF)", newContactMac, "12:34:56:78:9A:BC", UI_CONTENT_TOP_Y + 24, 30);
            drawHintLine("Enter Next", UI_CONTENT_TOP_Y + 58, uiAccentColor());
            drawHintLine("` Back", UI_CONTENT_TOP_Y + 68, uiTextMutedColor());
            break;

        case ADD_CONFIRM:
            drawCardRow("Name: " + newContactName, 0, false, UI_CONTENT_TOP_Y + 24);
            drawCardRow("MAC: " + newContactMac, 1, false, UI_CONTENT_TOP_Y + 24);
            drawHintLine("Enter Save", UI_CONTENT_TOP_Y + 66, uiAccentColor());
            drawHintLine("` Back", UI_CONTENT_TOP_Y + 76, uiTextMutedColor());
            break;
    }
}

void handleAddContactInput(int key) {
    bool changed = false;

    if (key == '`') {
        if (addStep == ADD_NAME) {
            currentMenu = MENU_CONTACTS;
            return;
        }
        addStep = (AddContactStep)(addStep - 1);
        drawAddContact();
        return;
    }

    if (key == KEY_ENTER) {
        if (addStep == ADD_NAME) {
            if (newContactName.length() == 0) return;
            addStep = ADD_MAC;
            drawAddContact();
            return;
        }

        if (addStep == ADD_MAC) {
            uint8_t parsedMac[6];
            if (!parseMacAddress(newContactMac.c_str(), parsedMac)) {
                drawAddContact();
                showErrorToast("Invalid MAC format");
                drawAddContact();
                return;
            }

            newContactMac = macToString(parsedMac);
            addStep = ADD_CONFIRM;
            drawAddContact();
            return;
        }

        if (addStep == ADD_CONFIRM) {
            String keyMac = findContactKeyByMac(contacts, newContactMac);
            if (keyMac.length() == 0) {
                keyMac = newContactMac;
            }

            JsonObject obj;
            if (contacts.containsKey(keyMac.c_str())) {
                obj = contacts[keyMac.c_str()];
            } else {
                obj = contacts.createNestedObject(keyMac.c_str());
            }

            obj["username"] = newContactName;
            if (!obj.containsKey("messages")) {
                obj.createNestedArray("messages");
            }

            JsonObject keys;
            if (obj.containsKey("keys")) {
                keys = obj["keys"].as<JsonObject>();
            } else {
                keys = obj.createNestedObject("keys");
            }
            if (!keys.containsKey("status")) {
                keys["status"] = "none";
            }

            saveContacts(contacts, "/m5pager/contacts.json");

            newContactName = "";
            newContactMac  = "";
            addStep = ADD_NAME;

            currentMenu = MENU_CONTACTS;
            return;
        }
    }

    if (addStep == ADD_NAME) {
        changed = handleTextInput(key, newContactName, 20);
    } else if (addStep == ADD_MAC) {
        changed = handleTextInput(key, newContactMac, 17); //XX:XX:XX:XX:XX:XX
    }

    if (changed) {
        drawAddContact();
    }
}
