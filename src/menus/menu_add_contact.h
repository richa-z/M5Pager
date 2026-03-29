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

// input buffers
extern String newContactName = "";
extern String newContactMac  = "";

extern AddContactStep addStep = ADD_NAME;

void drawAddContact() {
    beginScreenFrame();
    M5Cardputer.Display.setTextColor(WHITE, BLACK);

    M5Cardputer.Display.println("Add Contact");
    drawSeparator();

    switch (addStep) {
        case ADD_NAME:
            M5Cardputer.Display.println("Enter username:");
            M5Cardputer.Display.println(newContactName);
            break;

        case ADD_MAC:
            M5Cardputer.Display.println("Enter MAC address:");
            M5Cardputer.Display.println("AA:BB:CC:DD:EE:FF");
            M5Cardputer.Display.println(newContactMac);
            break;

        case ADD_CONFIRM:
            M5Cardputer.Display.println("Confirm contact:");
            M5Cardputer.Display.println("Name: " + newContactName);
            M5Cardputer.Display.println("MAC:  " + newContactMac);
            M5Cardputer.Display.println("");
            M5Cardputer.Display.println("[ENTER] Save");
            M5Cardputer.Display.println("[ESC] Back");
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
                M5Cardputer.Display.setTextColor(RED, BLACK);
                M5Cardputer.Display.println("[-] Invalid MAC format");
                delay(800);
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
