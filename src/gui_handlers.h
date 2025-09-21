#pragma once

#include <M5Cardputer.h>
#include <ArduinoJson.h>
#include <String.h>
#include <cstring>

#include "menus.h"

extern MenuState currentMenu;
extern int contactsSize;

extern DynamicJsonDocument config;

void drawSeparator() {
    int count = M5Cardputer.Display.width() / 6; // ~6px per char with small font
    String line = "";
    for (int i = 0; i < count; i++) {
        line += '-';
    }
    M5Cardputer.Display.println(line);
}

inline void drawMenu(const char* items[], int itemCount, int selectedIdx = 0) {
    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);

    for (size_t i = 0; i < itemCount; i++) {
        if (i == selectedIdx) {
            M5Cardputer.Display.setTextColor(BLACK, WHITE);
        } else {
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
        }
        M5Cardputer.Display.println(items[i]);
    } 
}

const char* drawContacts(DynamicJsonDocument& contacts, int selectedIdx = 0) {
    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);

    //names are main object keys
    int counter = 0;
    int contactCount = 0;
    const char* temp = nullptr;
    for (JsonPair kvp : contacts.as<JsonObject>()) {
        contactCount++;
    }
    // Draw contacts
    for (JsonPair kvp : contacts.as<JsonObject>()) {
        if (counter == selectedIdx) {
            M5Cardputer.Display.setTextColor(BLACK, WHITE);
            temp = kvp.key().c_str();
        } else {
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
        }
        M5Cardputer.Display.println(kvp.key().c_str());
        counter++;
    }

    contactsSize = contactCount;

    // Draw '+ Add Contact...' as selectable
    if (selectedIdx == contactCount) {
        M5Cardputer.Display.setTextColor(BLACK, WHITE);
    } else {
        M5Cardputer.Display.setTextColor(WHITE, BLACK);
    }
    M5Cardputer.Display.println("+ Add Contact...");

    return temp;
}

void drawMessages(DynamicJsonDocument& contactsJson, const char* selectedContact) {
    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);

    if (selectedContact != nullptr) {
        M5Cardputer.Display.setTextColor(WHITE, BLACK);
        M5Cardputer.Display.println(selectedContact);
        drawSeparator();

        // Display messages for the selected contact
        if (contactsJson.containsKey(selectedContact)) {
            JsonArray messages = contactsJson[selectedContact]["messages"].as<JsonArray>();
            for (JsonVariant msg : messages) {
                const char* type = msg["type"];
                const char* text = msg["text"];
                String formattedLine = "[" + String(type) + "] " + String(text);
                M5Cardputer.Display.println(formattedLine);
            }
        } else {
            M5Cardputer.Display.println("No messages.");
        }
    } else {
        M5Cardputer.Display.setTextColor(WHITE, BLACK);
        M5Cardputer.Display.println("No contact selected.");
        currentMenu = MENU_CONTACTS;
    }
}

void drawSettings(int selectedIdx = 0) {
    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);

    M5Cardputer.Display.setTextColor(WHITE, BLACK);
    M5Cardputer.Display.println("Username: " + String((const char*)config["username"]));

    currentMenu = MENU_SETTINGS;
}

