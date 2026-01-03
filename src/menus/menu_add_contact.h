#pragma once

#include "menus.h"
#include "gui_handlers.h"
#include "json_management.h"
#include "enums/add_contact_type.h"

#include <M5Cardputer.h>
#include <ArduinoJson.h>

#include "util/text_input.h"

extern MenuState currentMenu;
extern DynamicJsonDocument contacts;

// input buffers
extern String newContactName = "";
extern String newContactMac  = "";

extern AddContactStep addStep = ADD_NAME;

void drawAddContact() {
    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.setTextFont(2);
    M5Cardputer.Display.setTextSize(1);
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
            M5Cardputer.Display.println("[BKSP] Cancel");
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
        if (addStep == ADD_CONFIRM) {
            JsonObject obj = contacts.createNestedObject(newContactMac);
            obj["username"] = newContactName;
            obj.createNestedArray("messages");

            JsonObject keys = obj.createNestedObject("keys");
            keys["status"] = "none";

            saveContacts(contacts, "/m5pager/contacts.json");

            newContactName = "";
            newContactMac  = "";
            addStep = ADD_NAME;

            currentMenu = MENU_CONTACTS;
            return;
        }

        addStep = (AddContactStep)(addStep + 1);
        drawAddContact();
        return;
    }

    if (addStep == ADD_NAME) {
        changed = handleTextInput(key, newContactName, 16);
    } else if (addStep == ADD_MAC) {
        changed = handleTextInput(key, newContactMac, 17); //XX:XX:XX:XX:XX:XX
    }

    if (changed) {
        drawAddContact();
    }
}