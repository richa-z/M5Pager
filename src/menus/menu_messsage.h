#pragma once

#include <M5Cardputer.h>
#include <esp_now.h>
#include "menus.h"
#include "gui_handlers.h"
#include "util/text_input.h"
#include "types.h"

#define MSG_CHUNK_SIZE 180

#define ACK_TIMEOUT 2000

extern MenuState currentMenu;
extern int menuIndex;
extern const char* selectedContact;
extern DynamicJsonDocument contacts;
extern bool isTypingMsg;
extern String messageInput; 
extern uint8_t selectedMac[6];

extern bool awaitingAck;
extern uint16_t awaitingMsgId;
extern unsigned long sendTimestamp;
bool selectContactPeer(const char* contactMac);

String trimRightForWidth(const String& text, int maxChars) {
    if (maxChars <= 0) return "";
    if (text.length() <= static_cast<size_t>(maxChars)) return text;
    if (maxChars <= 3) return text.substring(text.length() - maxChars);
    return "..." + text.substring(text.length() - (maxChars - 3));
}

int getChatLineHeight() {
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);
    int lineHeight = M5Cardputer.Display.fontHeight();
    return max(10, lineHeight);
}

int getVisibleMessageLines() {
    const int lineHeight = getChatLineHeight();
    const int headerLines = 2;
    const int footerLines = 2;
    int headerPx = headerLines * lineHeight;
    int footerPx = footerLines * lineHeight;
    int messagePx = M5Cardputer.Display.height() - headerPx - footerPx;
    return max(1, messagePx / lineHeight);
}

int getMaxMessageScroll() {
    if (selectedContact == nullptr) return 0;
    if (!contacts.containsKey(selectedContact)) return 0;

    JsonArray messages = contacts[selectedContact]["messages"];
    int totalMessages = messages.size();
    int visibleLines = getVisibleMessageLines();
    return max(0, totalMessages - visibleLines);
}

void clampMessageScroll() {
    if (messageScroll < 0) messageScroll = 0;
    int maxScroll = getMaxMessageScroll();
    if (messageScroll > maxScroll) messageScroll = maxScroll;
}

uint16_t sendSplitMessage(const uint8_t* targetMac, const String& text) {
    static uint16_t messageCounter = 0;
    if (targetMac == nullptr || text.length() == 0) return 0;
    if (!esp_now_is_peer_exist(targetMac)) return 0;

    messageCounter++;

    uint16_t msgId = messageCounter;
    int totalLen = text.length();
    uint8_t totalParts = (totalLen + MSG_CHUNK_SIZE - 1) / MSG_CHUNK_SIZE;

    for (uint8_t i = 0; i < totalParts; i++) {
        MessageStruct pkt{};
        pkt.type = P_MSG;
        esp_read_mac(pkt.from, ESP_MAC_WIFI_STA);

        pkt.message_id = msgId;
        pkt.split_size = totalParts;
        pkt.split_index = i;

        int offset = i * MSG_CHUNK_SIZE;
        pkt.data_len = min(MSG_CHUNK_SIZE, totalLen - offset);
        memcpy(pkt.msg, text.c_str() + offset, pkt.data_len);

        esp_err_t sendResult = esp_now_send(targetMac, (uint8_t*)&pkt, sizeof(MessageStruct) - MSG_CHUNK_SIZE + pkt.data_len);
        if (sendResult != ESP_OK) {
            return 0;
        }
        delay(10);
    }

    return msgId;
}

void drawMessageMenu() {
    const int lineHeight = getChatLineHeight();
    const int footerLines = 2;

    M5Cardputer.Display.fillScreen(BLACK);
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(2);
    M5Cardputer.Display.setTextColor(WHITE, BLACK);

    if (selectedContact == nullptr || !contacts.containsKey(selectedContact)) {
        M5Cardputer.Display.println("No contact selected.");
        currentMenu = MENU_CONTACTS;
        return;
    }

    int maxChars = max(1, M5Cardputer.Display.width() / 6);
    String person = String(contacts[selectedContact]["username"].as<const char*>());
    M5Cardputer.Display.println(trimRightForWidth(person, maxChars));
    drawSeparator();

    JsonArray messages = contacts[selectedContact]["messages"];
    int totalMessages = messages.size();
    int visibleLines = getVisibleMessageLines();
    clampMessageScroll();

    int start = max(0, totalMessages - visibleLines - messageScroll);
    int end = min(totalMessages, start + visibleLines);

    for (int i = start; i < end; i++) {
        JsonObject msg = messages[i];
        bool incoming = String(msg["type"].as<const char*>()) == "in";
        const char* who = incoming ? person.c_str() : "You";
        String line = "[" + String(who) + "] " + msg["text"].as<String>();
        M5Cardputer.Display.println(trimRightForWidth(line, maxChars));
    }

    int footerY = M5Cardputer.Display.height() - (footerLines * lineHeight);
    M5Cardputer.Display.setCursor(0, footerY);
    drawSeparator();

    if (isTypingMsg) {
        int inputChars = max(1, maxChars - 2);
        M5Cardputer.Display.print("> ");
        M5Cardputer.Display.println(trimRightForWidth(messageInput, inputChars));
    } else {
        M5Cardputer.Display.println("[ENTER] Send message");
    }
}

void handleMessageInput(int key) {
    if (!isTypingMsg && key == KEY_BACKSPACE) {
        currentMenu = MENU_CONTACTS;
    }

    if (!isTypingMsg && key == '`') {
        menuIndex = 0;
        currentMenu = MENU_CONTACT_OPTIONS;
        return;
    }

    if (!isTypingMsg) {
        if (key == ';') {        // UP
            int maxScroll = getMaxMessageScroll();
            if (messageScroll < maxScroll) {
                messageScroll++;
            }
            drawMessageMenu();
        } 
        if (key == '.') {        // DOWN
            messageScroll = max(0, messageScroll - 1);
            drawMessageMenu();
        }
    }

    if (!isTypingMsg && key == KEY_ENTER) {
        isTypingMsg = true;
        messageInput = "";
        drawMessageMenu();
        return;
    }

    if (isTypingMsg) {
        if (key == KEY_ENTER) {
            if (messageInput.length() == 0) return;

            if (!selectContactPeer(selectedContact)) {
                M5Cardputer.Display.setTextColor(RED, BLACK);
                M5Cardputer.Display.println("[-] Invalid peer MAC");
                delay(800);
                isTypingMsg = false;
                drawMessageMenu();
                return;
            }

            uint16_t msgId = sendSplitMessage(selectedMac, messageInput);
            if (msgId == 0) {
                M5Cardputer.Display.setTextColor(RED, BLACK);
                M5Cardputer.Display.println("[-] Send failed");
                delay(800);
                isTypingMsg = false;
                drawMessageMenu();
                return;
            }

            appendMessage(contacts, selectedContact, "out", messageInput.c_str());

            awaitingAck = true;
            awaitingMsgId = msgId;
            sendTimestamp = millis();

            messageInput = "";
            isTypingMsg = false;
            drawMessageMenu();
            return;
        }

        if (key == KEY_BACKSPACE && messageInput.length() == 0) {
            isTypingMsg = false;
            drawMessageMenu();
            return;
        }
        
        if (handleTextInput(key, messageInput, 180)) {
            drawMessageMenu();
        }
    }


    // TODO: Implement message sending, scrolling, etc.
}
