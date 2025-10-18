#pragma once

#include <M5Cardputer.h>
#include <ArduinoJson.h>
#include <String.h>
#include <cstring>

#include "menus.h"

extern MenuState currentMenu;
extern int contactsSize;

extern DynamicJsonDocument config;
extern const char* user;
const char* settingsItems[] = {
    "Username",
    "MAC: " //read-only
};

extern const char* user;

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
        const char* name = kvp.value()["username"];
        M5Cardputer.Display.println(name);
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

    String person = String(contactsJson[selectedContact]["username"].as<const char*>());

    if (selectedContact != nullptr) {
        M5Cardputer.Display.setTextColor(WHITE, BLACK);
        M5Cardputer.Display.println(person);
        drawSeparator();

        // Display messages for the selected contact
        if (contactsJson.containsKey(selectedContact)) {
            JsonArray messages = contactsJson[selectedContact]["messages"].as<JsonArray>();
            for (JsonVariant msg : messages) {
                const char* type = msg["type"] == "in" ? person.c_str() : user;
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

    for (size_t i = 0; i < 2; i++) {
        if (i == selectedIdx) {
            M5Cardputer.Display.setTextColor(BLACK, WHITE);
        } else {
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
        }

        if (strcmp(settingsItems[i], "Username") == 0) {
            //append MAC address from config

            if (user == nullptr) {
                user = "NULLPTR";
            } else {
                user = config["username"];
            }

            M5Cardputer.Display.println(String("Username: " + String(user)).c_str());
            
        } else {
            M5Cardputer.Display.println(settingsItems[i]);
        }
        
    }
}

void changeUsername(String newUsername) {
    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);

    M5Cardputer.Display.setTextColor(WHITE, BLACK);
    String changeUserLabel = "Type your username below:";
    M5Cardputer.Display.setCursor(M5Cardputer.Display.width() / 2 - changeUserLabel.length() * 3.5, M5Cardputer.Display.height() / 2 - 4);
    M5Cardputer.Display.println(changeUserLabel);
    M5Cardputer.Display.setCursor(M5Cardputer.Display.width() / 2 - newUsername.length() * 2.5, M5Cardputer.Display.height() / 2 + 16);
    M5Cardputer.Display.println(newUsername);
}

