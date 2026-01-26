#pragma once

#include <M5Cardputer.h>
#include <ArduinoJson.h>
#include <String.h>
#include <cstring>
#include <WiFi.h>

#include "menus.h"
#include "enums/add_contact_type.h"

extern MenuState currentMenu;
extern int contactsSize;

extern DynamicJsonDocument config;
extern const char* user;
const char* settingsItems[] = {
    "Username",
    "MAC: " //read-only
};

extern const char* user;
extern int messageScroll;

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

    //Moznost pridania kontaktu
    if (selectedIdx == contactCount) {
        M5Cardputer.Display.setTextColor(BLACK, WHITE);
        temp = "ADD_CONTACT_BTN";
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
            int maxLines = (M5Cardputer.Display.height() / 12) - 4;

            JsonArray messages = contactsJson[selectedContact]["messages"];
            int total = messages.size();

            int start = max(0, total - maxLines - messageScroll);
            int end   = total - messageScroll;

            for (int i = start; i < end; i++) {
                JsonObject msg = messages[i];
                const char* who = msg["type"] == "in" ? person.c_str() : user;
                M5Cardputer.Display.println("[" + String(who) + "] " + msg["text"].as<String>());
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
            
        } else if (strcmp(settingsItems[i], "MAC: ") == 0) {
            M5Cardputer.Display.println(settingsItems[i] + WiFi.macAddress());
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

bool appendMessage(DynamicJsonDocument& contacts, const String& contactKey, const char* direction, const char* text) {
    if (!contacts.containsKey(contactKey)) return false;

    JsonObject contact = contacts[contactKey];
    if (!contact.containsKey("messages")) {
        contact.createNestedArray("messages");
    }

    JsonArray messages = contact["messages"].as<JsonArray>();
    JsonObject msg = messages.createNestedObject();
    msg["type"] = direction;
    msg["text"] = text;

    return saveContacts(contacts, "/m5pager/contacts.json");
}

