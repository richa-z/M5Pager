#pragma once

#include <M5Cardputer.h>
#include <ArduinoJson.h>

inline void drawMenu(const char* items[], int itemCount, int selectedIdx) {
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

void drawContacts(DynamicJsonDocument& contacts, int selectedIdx = 0) {
    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);

    //names are main object keys
    int counter = 0;
    int contactCount = 0;
    for (JsonPair kvp : contacts.as<JsonObject>()) {
        contactCount++;
    }
    // Draw contacts
    for (JsonPair kvp : contacts.as<JsonObject>()) {
        if (counter == selectedIdx) {
            M5Cardputer.Display.setTextColor(BLACK, WHITE);
        } else {
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
        }
        M5Cardputer.Display.println(kvp.key().c_str());
        counter++;
    }
    // Draw '+ Add Contact...' as selectable
    if (selectedIdx == contactCount) {
        M5Cardputer.Display.setTextColor(BLACK, WHITE);
    } else {
        M5Cardputer.Display.setTextColor(WHITE, BLACK);
    }
    M5Cardputer.Display.println("+ Add Contact...");
 
}