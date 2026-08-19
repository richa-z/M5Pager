#pragma once

#include <M5Cardputer.h>
#include <ArduinoJson.h>
#include <String.h>
#include <cstring>
#include <WiFi.h>
#include <time.h>

#include "menus.h"
#include "enums/add_contact_type.h"

extern MenuState currentMenu; //Akttivna ponuka pre input tracking
extern int contactsSize;

extern DynamicJsonDocument config; //global config dokument

extern String user;
// Poradie musi sediet s handleSettingsMenuInput()!!!!
enum SettingsRow {
    SETTINGS_USERNAME = 0,
    SETTINGS_WIFI_SSID,
    SETTINGS_WIFI_PASS,
    SETTINGS_LOCK,
    SETTINGS_MAC,        //read-only
    SETTINGS_COUNT
};

extern int messageScroll;

constexpr int UI_TOPBAR_HEIGHT = 12;
constexpr int UI_TOPBAR_TEXT_Y = 2;
constexpr int UI_CONTENT_TOP_Y = UI_TOPBAR_HEIGHT + 2;
constexpr int UI_CARD_GAP = 4;
constexpr int UI_CARD_HEIGHT = 18;

constexpr size_t MAX_MESSAGES_PER_CONTACT = 40;

inline uint16_t uiBgColor() { return M5Cardputer.Display.color565(8, 10, 14); }
inline uint16_t uiTopbarColor() { return M5Cardputer.Display.color565(14, 18, 24); }
inline uint16_t uiTopbarLineColor() { return M5Cardputer.Display.color565(44, 52, 64); }
inline uint16_t uiCardColor() { return M5Cardputer.Display.color565(18, 22, 30); }
inline uint16_t uiCardSelectedColor() { return M5Cardputer.Display.color565(28, 34, 44); }
inline uint16_t uiAccentColor() { return M5Cardputer.Display.color565(95, 140, 210); }
inline uint16_t uiTextPrimaryColor() { return M5Cardputer.Display.color565(236, 240, 248); }
inline uint16_t uiTextMutedColor() { return M5Cardputer.Display.color565(146, 160, 182); }
inline uint16_t uiDangerColor() { return M5Cardputer.Display.color565(232, 94, 110); }
inline uint16_t uiSuccessColor() { return M5Cardputer.Display.color565(64, 179, 126); }

/// @brief Oreže reťazec na určitú šírku v pixeloch.
/// @param text Vstupný reťazec
/// @param maxWidthPx Maximálna šírka v pixeloch
/// @return Orezaný reťazec
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

/// @brief Získa čas pre hornú lištu. Najprv sa pokúsi získať čas z RTC, ak nie je k dispozícii, použije systémový čas (null na M5).
/// @note Potreba RTC modul
/// @return Čas v reťazci
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

/// @brief Získa užívateľské meno pre hornú lištu.
/// @return Užívateľské meno v reťazci
inline String getTopbarUsernameText() {
    String cfgUser = config["username"] | "";
    if (cfgUser.length() > 0) return cfgUser;
    if (user.length() > 0) return user;
    return "User";
}

/// @brief Získa stav batérie pre hornú lištu.
/// @return Stav batérie v reťazci
inline String getTopbarBatteryText() {
    int battery = M5Cardputer.Power.getBatteryLevel();
    if (battery < 0) return "--%";
    if (battery > 100) battery = 100;

    char buf[8];
    snprintf(buf, sizeof(buf), "%d%%", battery);
    return String(buf);
}

/// @brief Nakreslí hornú lištu s časom, uživatelským jménom a stavom batérie.
inline void drawTopbar() {
    const uint16_t barBg = uiTopbarColor();
    const uint16_t barFg = uiTextPrimaryColor();
    const uint16_t barLine = uiTopbarLineColor();

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

/// @brief Začne nový rámec pre vykreslovánie obsahu, vyčistí obrazovku a nakreslí hornú lištu.
inline void beginScreenFrame() {
    M5Cardputer.Display.fillScreen(uiBgColor());
    drawTopbar();
    M5Cardputer.Display.setCursor(0, UI_CONTENT_TOP_Y);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);
    M5Cardputer.Display.setTextColor(uiTextPrimaryColor(), uiBgColor());
}

/// @brief Nakreslí názov sekcie s podfarbením a oddeľovačom.
/// @param title Názov sekcie
inline void drawSectionTitle(const String& title) {
    M5Cardputer.Display.setTextFont(1);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(uiTextMutedColor(), uiBgColor());
    M5Cardputer.Display.setCursor(4, UI_CONTENT_TOP_Y + 2);
    M5Cardputer.Display.print(title);

    int y = UI_CONTENT_TOP_Y + 10;
    M5Cardputer.Display.drawFastHLine(4, y, M5Cardputer.Display.width() - 8, uiTopbarLineColor());
}

/// @brief Nakreslí riadok karty.
/// @param label Text karty
/// @param index Index karty pre výpočet pozicie
/// @param selected Určuje, či je karta vybratá
/// @param startY Začiatočná Y pozícia pre prvú kartu, default UI_CONTENT_TOP_Y + 14
inline void drawCardRow(const String& label, int index, bool selected, int startY = UI_CONTENT_TOP_Y + 14) {
    int x = 4;
    int y = startY + index * (UI_CARD_HEIGHT + UI_CARD_GAP);
    int w = M5Cardputer.Display.width() - (x * 2);
    int h = UI_CARD_HEIGHT;

    uint16_t cardColor = selected ? uiCardSelectedColor() : uiCardColor();
    M5Cardputer.Display.fillRoundRect(x, y, w, h, 4, cardColor);
    if (selected) {
        M5Cardputer.Display.fillRect(x, y, 3, h, uiAccentColor());
    }

    M5Cardputer.Display.setTextFont(1);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(selected ? uiTextPrimaryColor() : uiTextMutedColor(), cardColor);

    String clipped = trimToPixelWidth(label, w - 12);
    M5Cardputer.Display.setCursor(x + 6, y + 5);
    M5Cardputer.Display.print(clipped);
}

/// @brief Nakreslí riadok nápovedy.
/// @param text Text nápovedy
/// @param y Y pozícia
/// @param textColor Farba textu
inline void drawHintLine(const String& text, int y, uint16_t textColor = uiTextMutedColor()) {
    M5Cardputer.Display.setTextFont(1);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(textColor, uiBgColor());
    M5Cardputer.Display.setCursor(6, y);
    M5Cardputer.Display.print(trimToPixelWidth(text, M5Cardputer.Display.width() - 12));
}

/// @brief Nakreslí vstupnú kartu.
/// @param label Text karty
/// @param value Hodnota karty
/// @param placeholder Zástupný text
/// @param y Y pozícia
/// @param height Výška karty
inline void drawInputCard(const String& label,
                          const String& value,
                          const String& placeholder,
                          int y,
                          int height = 24) {
    int x = 6;
    int w = M5Cardputer.Display.width() - 12;
    M5Cardputer.Display.fillRoundRect(x, y, w, height, 4, uiCardColor());
    M5Cardputer.Display.drawRoundRect(x, y, w, height, 4, uiTopbarLineColor());

    M5Cardputer.Display.setTextFont(1);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(uiTextMutedColor(), uiCardColor());
    M5Cardputer.Display.setCursor(x + 6, y + 3);
    M5Cardputer.Display.print(trimToPixelWidth(label, w - 12));

    String body = value.length() > 0 ? value : placeholder;
    uint16_t bodyColor = value.length() > 0 ? uiTextPrimaryColor() : uiTextMutedColor();
    M5Cardputer.Display.setTextColor(bodyColor, uiCardColor());
    M5Cardputer.Display.setCursor(x + 6, y + 13);
    M5Cardputer.Display.print(trimToPixelWidth(body, w - 12));
}

/// @brief Nakreslí vyskakovaciu správu.
/// @param message Správa
/// @param bgColor Farba pozadia
/// @param fgColor Farba textu
/// @param waitMs Čas zobrazenia
inline void showToast(const String& message,
                      uint16_t bgColor,
                      uint16_t fgColor = 0xFFFF,
                      uint16_t waitMs = 900) {
    int x = 6;
    int h = 18;
    int w = M5Cardputer.Display.width() - 12;
    int y = M5Cardputer.Display.height() - h - 4;

    M5Cardputer.Display.fillRoundRect(x, y, w, h, 4, bgColor);
    M5Cardputer.Display.setTextFont(1);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(fgColor, bgColor);
    M5Cardputer.Display.setCursor(x + 6, y + 5);
    M5Cardputer.Display.print(trimToPixelWidth(message, w - 12));
    delay(waitMs);
}

/// @brief Zobrazí chybovú správu.
/// @param message Chybová správa
/// @param waitMs Čas zobrazenia
inline void showErrorToast(const String& message, uint16_t waitMs = 900) {
    showToast(message, uiDangerColor(), uiTextPrimaryColor(), waitMs);
}

/// @brief Zobrazí úspešnú správu.
/// @param message Úspešná správa
/// @param waitMs Čas zobrazenia
inline void showSuccessToast(const String& message, uint16_t waitMs = 900) {
    showToast(message, uiSuccessColor(), uiTextPrimaryColor(), waitMs);
}

/// @brief Nakreslí oddeľovač
void drawSeparator() {
    int y = M5Cardputer.Display.getCursorY() + 1;
    M5Cardputer.Display.drawFastHLine(4, y, M5Cardputer.Display.width() - 8, uiTopbarLineColor());
    M5Cardputer.Display.setCursor(0, y + 3);
}

/// @brief Nakreslí ponuku s danými možnosťami a zvýrazní vybratú možnosť.
/// @param items Pole možností menu
/// @param itemCount Počet možností
/// @param selectedIdx Index vybranej možnosti
inline void drawMenu(const char* items[], int itemCount, int selectedIdx = 0) {
    beginScreenFrame();
    drawSectionTitle("MAIN");
    for (size_t i = 0; i < itemCount; i++) {
        drawCardRow(items[i], i, i == selectedIdx);
    }
}

/// @brief Nakreslí zoznam kontaktov.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param selectedIdx Index vybratého kontaktu
/// @return Kľúč vybratého kontaktu (vlastnená kópia, nie ukazovateľ do dokumentu)
String drawContacts(DynamicJsonDocument& contacts, int selectedIdx = 0) {
    beginScreenFrame();
    drawSectionTitle("CONTACTS");

    //meno je kluc
    int counter = 0;
    int contactCount = 0;
    String temp = "";
    for (JsonPair kvp : contacts.as<JsonObject>()) {
        contactCount++;
    }

    for (JsonPair kvp : contacts.as<JsonObject>()) {
        if (counter == selectedIdx) {
            temp = String(kvp.key().c_str());
        }
        String name = kvp.value()["username"] | "";
        drawCardRow(name, counter, counter == selectedIdx);
        counter++;
    }

    contactsSize = contactCount;

    if (selectedIdx == contactCount) {
        temp = "ADD_CONTACT_BTN";
    }
    drawCardRow("+ Add Contact", contactCount, selectedIdx == contactCount);

    return temp;
}

/// @brief Nakreslí správy pre vybratý kontakt.
/// @param contactsJson JSON dokument obsahujúci kontakty a ich správy
/// @param selectedContact Meno vybratého kontaktu
void drawMessages(DynamicJsonDocument& contactsJson, const String& selectedContact) {
    beginScreenFrame();

    if (selectedContact.length() > 0) {
        String person = String(contactsJson[selectedContact]["username"].as<const char*>());
        M5Cardputer.Display.setTextColor(uiTextPrimaryColor(), uiBgColor());
        M5Cardputer.Display.println(person);
        drawSeparator();

        if (contactsJson.containsKey(selectedContact)) {
            int maxLines = (M5Cardputer.Display.height() / 12) - 4;

            JsonArray messages = contactsJson[selectedContact]["messages"];
            int total = messages.size();

            int start = max(0, total - maxLines - messageScroll);
            int end   = total - messageScroll;

            for (int i = start; i < end; i++) {
                JsonObject msg = messages[i];
                bool incoming = String(msg["type"].as<const char*>()) == "in";
                String who = incoming ? person : user;
                M5Cardputer.Display.setTextColor(incoming ? uiTextMutedColor() : uiTextPrimaryColor(), uiBgColor());
                M5Cardputer.Display.println((incoming ? "< " : "> ") + who + ": " + msg["text"].as<String>());
            }
        } else {
            M5Cardputer.Display.setTextColor(uiTextMutedColor(), uiBgColor());
            M5Cardputer.Display.println("No messages.");
        }
    } else {
        M5Cardputer.Display.setTextColor(uiTextMutedColor(), uiBgColor());
        M5Cardputer.Display.println("No contact selected.");
        currentMenu = MENU_CONTACTS;
    }
}

/// @brief Nájde kľúč kontaktu podľa jeho MAC adresy.
/// @param contacts JSON dokument obsahujúci kontakty
/// @param mac MAC adresa kontaktu
/// @return Kľúč kontaktu alebo prázdny reťazec, ak nenájdený
String findContactKeyByMac(DynamicJsonDocument& contacts, const String& mac) {
    for (JsonPair kvp : contacts.as<JsonObject>()) {
        String key = kvp.key().c_str();
        if (key.equalsIgnoreCase(mac)) {
            return key;
        }
    }
    return "";
}

/// @brief Nakreslí nastavenia.
/// @param selectedIdx Index vybranej možnosti
void drawSettings(int selectedIdx = 0) {
    beginScreenFrame();
    drawSectionTitle("SETTINGS");

    user = config["username"] | "User";
    String wifiSsid = config["wifi_ssid"] | "";
    String wifiPass = config["wifi_pass"] | "";

    String maskedPass;
    for (size_t i = 0; i < wifiPass.length(); i++) maskedPass += '*';

    for (int i = 0; i < SETTINGS_COUNT; i++) {
        String rowText;
        switch (i) {
            case SETTINGS_USERNAME:
                rowText = "Username: " + user;
                break;
            case SETTINGS_WIFI_SSID:
                rowText = "WiFi SSID: " + (wifiSsid.length() > 0 ? wifiSsid : String("<not set>"));
                break;
            case SETTINGS_WIFI_PASS:
                rowText = "WiFi Pass: " + (maskedPass.length() > 0 ? maskedPass : String("<not set>"));
                break;
            case SETTINGS_LOCK:
                rowText = "Lock device now";
                break;
            case SETTINGS_MAC:
                rowText = "MAC: " + WiFi.macAddress();
                break;
        }
        drawCardRow(rowText, i, i == selectedIdx);
    }
}

/// @brief Menu pre zmenu mena.
/// @param newUsername Aktuálne alebo nové zadané uživateľské meno
void changeUsername(String newUsername) {
    beginScreenFrame();

    drawSectionTitle("USERNAME");
    drawInputCard("Type new username", newUsername, "username", UI_CONTENT_TOP_Y + 20, 24);
    drawHintLine("` Back    Enter Save", UI_CONTENT_TOP_Y + 50, uiTextMutedColor());
}

/// @brief Pridá správu do konkrétneho kontaktu.
/// @param contacts JSON dokument obsahujúcí kontakty a ich správy
/// @param contactKey Kľúč kontaktu
/// @param direction Smer správy ("in" alebo "out")
/// @param text Obsah správy
/// @return TRUE, ak bola správa úspešne pridaná, inak FALSE
bool appendMessage(DynamicJsonDocument& contacts, const String& contactKey, const char* direction, const char* text) {
    if (!contacts.containsKey(contactKey)) return false;

    JsonObject contact = contacts[contactKey];
    if (!contact.containsKey("messages")) {
        contact.createNestedArray("messages");
    }

    JsonArray messages = contact["messages"].as<JsonArray>();

    while (messages.size() >= MAX_MESSAGES_PER_CONTACT) {
        messages.remove(0);
    }

    JsonObject msg = messages.createNestedObject();
    if (msg.isNull()) return false;

    msg["type"] = direction;
    msg["text"] = text;

    if (contacts.overflowed()) {
        messages.remove(messages.size() - 1);
        return false;
    }

    return saveContacts(contacts, "/m5pager/contacts.json");
}

