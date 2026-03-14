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
    drawMessages(contacts, selectedContact);

    if (isTypingMsg) {
        drawSeparator();
        M5Cardputer.Display.print("> ");
        M5Cardputer.Display.println(messageInput);
    } else {
        drawSeparator();
        M5Cardputer.Display.println("");
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
            messageScroll++;
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
