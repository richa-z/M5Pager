#pragma once

#include <M5Cardputer.h>
#include <ArduinoJson.h>
#include <String.h>
#include <cstring>
#include <WiFi.h>
#include <time.h>

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

constexpr int UI_TOPBAR_HEIGHT = 12;
constexpr int UI_TOPBAR_TEXT_Y = 2;
constexpr int UI_CONTENT_TOP_Y = UI_TOPBAR_HEIGHT + 2;

inline String trimToPixelWidth(const String& text, int maxWidthPx) {
    if (maxWidthPx <= 0) return "";
    if (M5Cardputer.Display.textWidth(text) <= maxWidthPx) return text;

    const String suffix = "...";
    if (M5Cardputer.Display.textWidth(suffix) > maxWidthPx) return "";

    String out = text;
    while (out.length() > 0 && M5Cardputer.Display.textWidth(out + suffix) > maxWidthPx) {
        out.remove(out.length() - 1);
    }
    return out + suffix;
}

inline String getTopbarTimeText() {
    if (M5.Rtc.isEnabled()) {
        m5::rtc_datetime_t dt;
        if (M5.Rtc.getDateTime(&dt)) {
            char buf[6];
            snprintf(buf, sizeof(buf), "%02d:%02d", dt.time.hours, dt.time.minutes);
            return String(buf);
        }
    }

    time_t now = time(nullptr);
    if (now > 100000) {
        struct tm localTm {};
        localtime_r(&now, &localTm);
        char buf[6];
        snprintf(buf, sizeof(buf), "%02d:%02d", localTm.tm_hour, localTm.tm_min);
        return String(buf);
    }

    return "--:--";
}

inline String getTopbarUsernameText() {
    const char* cfgUser = config["username"];
    if (cfgUser != nullptr && cfgUser[0] != '\0') return String(cfgUser);
    if (user != nullptr && user[0] != '\0') return String(user);
    return "User";
}

inline String getTopbarBatteryText() {
    int battery = M5Cardputer.Power.getBatteryLevel();
    if (battery < 0) return "--%";
    if (battery > 100) battery = 100;

    char buf[8];
    snprintf(buf, sizeof(buf), "%d%%", battery);
    return String(buf);
}

inline void drawTopbar() {
    const uint16_t barBg = M5Cardputer.Display.color565(18, 22, 30);
    const uint16_t barFg = M5Cardputer.Display.color565(235, 240, 250);
    const uint16_t barLine = M5Cardputer.Display.color565(70, 80, 95);

    const int width = M5Cardputer.Display.width();
    const int pad = 3;

    M5Cardputer.Display.fillRect(0, 0, width, UI_TOPBAR_HEIGHT, barBg);
    M5Cardputer.Display.drawFastHLine(0, UI_TOPBAR_HEIGHT - 1, width, barLine);

    M5Cardputer.Display.setTextFont(1);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(barFg, barBg);

    String left = getTopbarTimeText();
    String center = getTopbarUsernameText();
    String right = getTopbarBatteryText();

    int leftW = M5Cardputer.Display.textWidth(left);
    int rightW = M5Cardputer.Display.textWidth(right);

    int leftX = pad;
    int rightX = max(pad, width - pad - rightW);

    int middleLeft = leftX + leftW + 6;
    int middleRight = rightX - 6;
    int middleWidth = middleRight - middleLeft;
    if (middleWidth < 0) middleWidth = 0;

    center = trimToPixelWidth(center, middleWidth);
    int centerW = M5Cardputer.Display.textWidth(center);
    int centerX = middleLeft + max(0, (middleWidth - centerW) / 2);

    M5Cardputer.Display.setCursor(leftX, UI_TOPBAR_TEXT_Y);
    M5Cardputer.Display.print(left);

    if (center.length() > 0) {
        M5Cardputer.Display.setCursor(centerX, UI_TOPBAR_TEXT_Y);
        M5Cardputer.Display.print(center);
    }

    M5Cardputer.Display.setCursor(rightX, UI_TOPBAR_TEXT_Y);
    M5Cardputer.Display.print(right);
}

inline void beginScreenFrame() {
    M5Cardputer.Display.fillScreen(BLACK);
    drawTopbar();
    M5Cardputer.Display.setCursor(0, UI_CONTENT_TOP_Y);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);
}

void drawSeparator() {
    M5Cardputer.Display.setTextColor(WHITE, BLACK);
    int dashWidth = M5Cardputer.Display.textWidth("-");
    if (dashWidth <= 0) dashWidth = 6;
    int count = max(1, (M5Cardputer.Display.width() / dashWidth) - 1);
    String line = "";
    line.reserve(count);
    for (int i = 0; i < count; i++) {
        line += '-';
    }
    M5Cardputer.Display.println(line);
}

inline void drawMenu(const char* items[], int itemCount, int selectedIdx = 0) {
    beginScreenFrame();

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
    beginScreenFrame();

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
    beginScreenFrame();

    if (selectedContact != nullptr) {
        String person = String(contactsJson[selectedContact]["username"].as<const char*>());
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

String findContactKeyByMac(DynamicJsonDocument& contacts, const String& mac) {
    for (JsonPair kvp : contacts.as<JsonObject>()) {
        String key = kvp.key().c_str();
        if (key.equalsIgnoreCase(mac)) {
            return key;
        }
    }
    return "";
}

void drawSettings(int selectedIdx = 0) {
    beginScreenFrame();
    M5Cardputer.Display.setTextColor(WHITE, BLACK);

    M5Cardputer.Display.println("Settings");
    drawSeparator();

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
    beginScreenFrame();

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

