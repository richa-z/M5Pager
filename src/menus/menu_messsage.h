#pragma once

#include <M5Cardputer.h>
#include <esp_now.h>
#include "menus.h"
#include "gui_handlers.h"
#include "security/message_crypto.h"
#include "util/text_input.h"
#include "types.h"

#define MSG_CHUNK_SIZE 180

#define ACK_TIMEOUT 2000

extern MenuState currentMenu;
extern int menuIndex;
extern String selectedContact;
extern DynamicJsonDocument contacts;
extern bool isTypingMsg;
extern String messageInput;
extern uint8_t selectedMac[6];

extern bool awaitingAck;
extern uint16_t awaitingMsgId;
extern uint8_t awaitingMac[6];
extern unsigned long sendTimestamp;
extern bool pendingOutgoingReady;
extern String pendingOutgoingContact;
extern String pendingOutgoingText;
bool selectContactPeer(const char* contactMac);
bool requestKeyExchange(const char* contactMac);

// Konštanty pre rozloženie chatovacej obrazovky
constexpr int CHAT_PANEL_X = 6;
constexpr int CHAT_HEADER_Y = UI_CONTENT_TOP_Y + 14;
constexpr int CHAT_HEADER_H = 24;
constexpr int CHAT_BUBBLE_H = 14;
constexpr int CHAT_BUBBLE_GAP = 3;
constexpr int CHAT_FOOTER_H = 34;
constexpr int CHAT_ROW_START_Y = CHAT_HEADER_Y + CHAT_HEADER_H + 4;
constexpr int CHAT_INPUT_PREVIEW_LINES = 2;

/// @brief Vráti výšku riadku v chatovej obrazovke.
/// @return Výška riadku v pixloch.
int getChatLineHeight() {
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextFont(1);
    int lineHeight = M5Cardputer.Display.fontHeight();
    return max(CHAT_BUBBLE_H, lineHeight + 4);
}

/// @brief Vypočíta, koľko riadkov správ sa zmestí do viditeľnej oblasti chatovej obrazovky.
/// @return Počet viditeľných riadkov správ.
int getVisibleMessageLines() {
    const int lineHeight = getChatLineHeight() + CHAT_BUBBLE_GAP;
    int messageBottom = M5Cardputer.Display.height() - CHAT_FOOTER_H - 4;
    int messagePx = messageBottom - CHAT_ROW_START_Y;
    return max(1, messagePx / lineHeight);
}

/// @brief Vráti šírku bubliny správy v chatovej obrazovke.
/// @return Šírka bubliny správy v pixeloch.
int getChatBubbleWidth() {
    return M5Cardputer.Display.width() - 34;
}

/// @brief Vráti šírku textu v bubline správy, zohľadňujúc padding.
/// @return Šírka textu v bubline správy v pixeloch.
int getChatBubbleTextWidth() {
    return getChatBubbleWidth() - 10;
}

/// @brief Nájde koniec riadku pre zalamovanie textu.
/// @param text Text, ktorý sa má zalamovať
/// @param start Index, od ktorého začať hľadať koniec riadku
/// @param maxWidthPx Maximální šírka riadku v pixeloch
/// @param prefixWidthPx Šírka prefixu v pixeloch
/// @return Index konca riadkov pre zalamovanie textu
int findWrapEnd(const String& text, int start, int maxWidthPx, int prefixWidthPx) {
    if (start >= static_cast<int>(text.length())) return start;

    int lastSpace = -1;
    for (int end = start; end < static_cast<int>(text.length()); end++) {
        if (text[end] == ' ') {
            lastSpace = end;
        }

        String candidate = text.substring(start, end + 1);
        if (M5Cardputer.Display.textWidth(candidate) + prefixWidthPx > maxWidthPx) {
            if (end == start) return end + 1;
            if (lastSpace >= start) return lastSpace;
            return end;
        }
    }

    return text.length();
}

/// @brief Spočíta počet riadkov pre zalamovanie textu.
/// @param text Text, ktorý sa má zalamovať
/// @param firstPrefix Prefix pre prvý riadok
/// @param nextPrefix Prefix pre ďalšie riadky
/// @param maxWidthPx Maximálna šírka riadku v pixeloch
/// @return Počet riadkov po zalamovaní
int countWrappedTextRows(const String& text,
                         const String& firstPrefix,
                         const String& nextPrefix,
                         int maxWidthPx) {
    if (text.length() == 0) return 1;

    int rows = 0;
    int start = 0;
    bool firstLine = true;

    M5Cardputer.Display.setTextFont(1);
    M5Cardputer.Display.setTextSize(1);

    while (start < static_cast<int>(text.length())) {
        const String& prefix = firstLine ? firstPrefix : nextPrefix;
        int end = findWrapEnd(text, start, maxWidthPx, M5Cardputer.Display.textWidth(prefix));
        if (end <= start) end = start + 1;

        rows++;
        start = end;
        while (start < static_cast<int>(text.length()) && text[start] == ' ') {
            start++;
        }
        firstLine = false;
    }

    return rows;
}

/// @brief Vráti maximálny počet riadkov, o ktoré je možné posunúť chat.
/// @return Maximálny počet riadkov pre posunutie chatu.
int getMaxMessageScroll() {
    if (selectedContact.length() == 0) return 0;
    if (!contacts.containsKey(selectedContact)) return 0;

    JsonArray messages = contacts[selectedContact]["messages"];
    int totalRows = 0;
    int maxTextWidth = getChatBubbleTextWidth();
    for (JsonObject msg : messages) {
        bool incoming = String(msg["type"].as<const char*>()) == "in";
        totalRows += countWrappedTextRows(msg["text"].as<String>(),
                                          incoming ? "< " : "> ",
                                          "  ",
                                          maxTextWidth);
    }

    int visibleLines = getVisibleMessageLines();
    return max(0, totalRows - visibleLines);
}

/// @brief Omezí hodnotu messageScroll na platný rozsah pre posúvánie chatu.
void clampMessageScroll() {
    if (messageScroll < 0) messageScroll = 0;
    int maxScroll = getMaxMessageScroll();
    if (messageScroll > maxScroll) messageScroll = maxScroll;
}


/// @brief Odošle správu vo viacerých častiach cez ESP-NOW.
/// @param targetMac MAC adresa cieľa
/// @param contactKey Kľúč kontaktu pre šifrovanie správy
/// @param text Text správy pre odoslanie
/// @return ID odoslanej správy, alebo 0 pri chybe
uint16_t sendSplitMessage(const uint8_t* targetMac, const String& contactKey, const String& text) {
    static uint16_t messageCounter = 0;
    if (targetMac == nullptr || text.length() == 0) return 0;
    if (!esp_now_is_peer_exist(targetMac)) return 0;

    String encryptedPayload;
    if (!MessageCrypto::encryptPayload(contacts, contactKey, text, encryptedPayload)) {
        return 0;
    }

    if (!saveContacts(contacts, "/m5pager/contacts.json")) {
        return 0;
    }

    //najvyssi bit len pre control pakety
    messageCounter = (messageCounter + 1) & MESSAGE_ID_VALUE_MASK;
    if (messageCounter == 0) messageCounter = 1;

    uint16_t msgId = messageCounter;
    int totalLen = encryptedPayload.length();
    uint8_t totalParts = (totalLen + MSG_CHUNK_SIZE - 1) / MSG_CHUNK_SIZE;
    if (totalParts == 0 || totalParts > MAX_MESSAGE_PARTS) return 0;

    awaitingAck = true;
    awaitingMsgId = msgId;
    memcpy(awaitingMac, targetMac, 6); //ACK len od toho co poslal
    sendTimestamp = millis();
    pendingOutgoingReady = true;
    pendingOutgoingContact = contactKey;
    pendingOutgoingText = text;

    for (uint8_t i = 0; i < totalParts; i++) {
        MessageStruct pkt{};
        pkt.type = P_MSG;
        esp_read_mac(pkt.from, ESP_MAC_WIFI_STA);

        pkt.message_id = msgId;
        pkt.split_size = totalParts;
        pkt.split_index = i;

        int offset = i * MSG_CHUNK_SIZE;
        pkt.data_len = min(MSG_CHUNK_SIZE, totalLen - offset);
        memcpy(pkt.msg, encryptedPayload.c_str() + offset, pkt.data_len);

        uint8_t wire[PACKET_MAX_LEN];
        size_t wireLen = serializePacket(pkt, wire);
        if (wireLen == 0) {
            awaitingAck = false;
            pendingOutgoingReady = false;
            pendingOutgoingContact = "";
            pendingOutgoingText = "";
            return 0;
        }

        esp_err_t sendResult = esp_now_send(targetMac, wire, wireLen);
        if (sendResult != ESP_OK) {
            awaitingAck = false;
            pendingOutgoingReady = false;
            pendingOutgoingContact = "";
            pendingOutgoingText = "";
            return 0;
        }
        delay(10);
    }

    return msgId;
}

/// @brief Nakreslí jednu časť bubliny správy.
/// @param line Text pre zobrazenie v tejto časti bubliny
/// @param incoming TRUE, ak je správa prichádzajúca, FALSE pre odchádzajúcu
/// @param bubbleY Y pozícia pre nakreslenie bubliny
/// @param bubbleW Šírka bubliny
void drawChatBubbleLine(const String& line,
                        bool incoming,
                        int bubbleY,
                        int bubbleW) {
    uint16_t bubbleColor = incoming ? uiCardColor() : uiCardSelectedColor();
    uint16_t accentColor = incoming ? uiTopbarLineColor() : uiAccentColor();
    uint16_t textColor = incoming ? uiTextMutedColor() : uiTextPrimaryColor();

    int bubbleX = incoming ? CHAT_PANEL_X : (M5Cardputer.Display.width() - CHAT_PANEL_X - bubbleW);
    M5Cardputer.Display.fillRoundRect(bubbleX, bubbleY, bubbleW, CHAT_BUBBLE_H, 3, bubbleColor);
    M5Cardputer.Display.fillRect(bubbleX, bubbleY, 2, CHAT_BUBBLE_H, accentColor);

    M5Cardputer.Display.setTextColor(textColor, bubbleColor);
    M5Cardputer.Display.setCursor(bubbleX + 5, bubbleY + 4);
    M5Cardputer.Display.print(trimToPixelWidth(line, bubbleW - 10));
}

/// @brief Nakreslí viacriadkovú správu s automatickým zalamovaním.
/// @param text Text správy pre zobrazenie
/// @param incoming TRUE, ak je správa prichádzajúca, FALSE pre odchádzajúcu
/// @param visualRow Aktuálny vizuálny riadok pre zobrazenie správy
/// @param firstVisibleRow Prvý viditeľný riadok v chatovej obrazovke
/// @param lastVisibleRow Posledný viditeľný riadok v chatovej obrazovke
/// @param bubbleY Y pozícia pre nakreslenie prvej časti bubliny
/// @param bubbleW Šírka bubliny
void drawWrappedMessageRows(const String& text,
                            bool incoming,
                            int& visualRow,
                            int firstVisibleRow,
                            int lastVisibleRow,
                            int& bubbleY,
                            int bubbleW) {
    String firstPrefix = incoming ? "< " : "> ";
    String nextPrefix = "  ";
    int maxTextWidth = bubbleW - 10;
    int start = 0;
    bool firstLine = true;

    if (text.length() == 0) {
        if (visualRow >= firstVisibleRow && visualRow < lastVisibleRow) {
            drawChatBubbleLine(firstPrefix, incoming, bubbleY, bubbleW);
            bubbleY += getChatLineHeight() + CHAT_BUBBLE_GAP;
        }
        visualRow++;
        return;
    }

    while (start < static_cast<int>(text.length())) {
        String prefix = firstLine ? firstPrefix : nextPrefix;
        int end = findWrapEnd(text, start, maxTextWidth, M5Cardputer.Display.textWidth(prefix));
        if (end <= start) end = start + 1;

        String line = prefix + text.substring(start, end);
        if (visualRow >= firstVisibleRow && visualRow < lastVisibleRow) {
            drawChatBubbleLine(line, incoming, bubbleY, bubbleW);
            bubbleY += getChatLineHeight() + CHAT_BUBBLE_GAP;
        }

        visualRow++;
        start = end;
        while (start < static_cast<int>(text.length()) && text[start] == ' ') {
            start++;
        }
        firstLine = false;
    }
}

/// @brief Zozbiera riadky správy s automatickým zalamovaním.
/// @param text Text správy pre zobrazenie
/// @param lines Pole pre uloženie riadkov
/// @param maxLines Maximálny počet riadkov
/// @param maxWidthPx Maximálna šírka riadku v pixeloch
/// @return Počet zozbieraných riadkov
int collectWrappedInputLines(const String& text, String lines[], int maxLines, int maxWidthPx) {
    int count = 0;
    int start = 0;
    bool firstLine = true;

    if (text.length() == 0) {
        if (maxLines > 0) lines[0] = "> ";
        return maxLines > 0 ? 1 : 0;
    }

    while (start < static_cast<int>(text.length()) && count < maxLines) {
        String prefix = firstLine ? "> " : "  ";
        int end = findWrapEnd(text, start, maxWidthPx, M5Cardputer.Display.textWidth(prefix));
        if (end <= start) end = start + 1;

        lines[count++] = prefix + text.substring(start, end);
        start = end;
        while (start < static_cast<int>(text.length()) && text[start] == ' ') {
            start++;
        }
        firstLine = false;
    }

    return count;
}

/// @brief Nakreslí chatovaciu obrazovku pre aktuálne vybraný kontakt.
void drawMessageMenu() {
    beginScreenFrame();
    drawSectionTitle("CHAT");

    if (selectedContact.length() == 0 || !contacts.containsKey(selectedContact)) {
        drawHintLine("No contact selected", UI_CONTENT_TOP_Y + 24, uiTextMutedColor());
        currentMenu = MENU_CONTACTS;
        return;
    }

    bool secureReady = MessageCrypto::hasReadySession(contacts, selectedContact);
    bool rekeyPending = MessageCrypto::hasPendingRekeyOffer(contacts, selectedContact);
    String person = contacts[selectedContact]["username"] | "";

    String headerLabel;
    if (rekeyPending) {
        headerLabel = "Re-key requested - verify!";
    } else if (secureReady) {
        headerLabel = "Secure - " + MessageCrypto::getSessionFingerprint(contacts, selectedContact);
    } else {
        headerLabel = "Key exchange needed";
    }
    drawInputCard(headerLabel, person, "-", CHAT_HEADER_Y, CHAT_HEADER_H);

    JsonArray messages = contacts[selectedContact]["messages"];
    int totalMessages = messages.size();
    int visibleLines = getVisibleMessageLines();
    clampMessageScroll();

    int totalRows = 0;
    for (JsonObject msg : messages) {
        bool incoming = String(msg["type"].as<const char*>()) == "in";
        totalRows += countWrappedTextRows(msg["text"].as<String>(),
                                          incoming ? "< " : "> ",
                                          "  ",
                                          getChatBubbleTextWidth());
    }

    int firstVisibleRow = max(0, totalRows - visibleLines - messageScroll);
    int lastVisibleRow = firstVisibleRow + visibleLines;

    M5Cardputer.Display.setTextFont(1);
    M5Cardputer.Display.setTextSize(1);
    String counter = String(min(totalRows, lastVisibleRow)) + "/" + String(totalRows);
    int counterW = M5Cardputer.Display.textWidth(counter);
    M5Cardputer.Display.setTextColor(uiTextMutedColor(), uiCardColor());
    M5Cardputer.Display.setCursor(M5Cardputer.Display.width() - 12 - counterW, CHAT_HEADER_Y + 3);
    M5Cardputer.Display.print(counter);

    int bubbleW = getChatBubbleWidth();
    int bubbleY = CHAT_ROW_START_Y;
    int visualRow = 0;

    for (int i = 0; i < totalMessages; i++) {
        JsonObject msg = messages[i];
        bool incoming = String(msg["type"].as<const char*>()) == "in";
        drawWrappedMessageRows(msg["text"].as<String>(),
                               incoming,
                               visualRow,
                               firstVisibleRow,
                               lastVisibleRow,
                               bubbleY,
                               bubbleW);
    }

    if (totalMessages == 0) {
        drawHintLine("No messages yet. Press Enter to start chat.", CHAT_ROW_START_Y + 20, uiTextMutedColor());
    }

    int footerY = M5Cardputer.Display.height() - CHAT_FOOTER_H - 4;
    int footerW = M5Cardputer.Display.width() - (CHAT_PANEL_X * 2);
    uint16_t footerColor = uiTopbarColor();
    M5Cardputer.Display.fillRoundRect(CHAT_PANEL_X, footerY, footerW, CHAT_FOOTER_H, 4, footerColor);
    M5Cardputer.Display.drawRoundRect(CHAT_PANEL_X, footerY, footerW, CHAT_FOOTER_H, 4, uiTopbarLineColor());

    M5Cardputer.Display.setTextFont(1);
    M5Cardputer.Display.setTextSize(1);

    if (isTypingMsg) {
        String inputLines[16];
        int inputLineCount = collectWrappedInputLines(messageInput, inputLines, 16, footerW - 12);
        int firstInputLine = max(0, inputLineCount - CHAT_INPUT_PREVIEW_LINES);

        M5Cardputer.Display.setTextColor(uiAccentColor(), footerColor);
        for (int i = firstInputLine; i < inputLineCount; i++) {
            int lineY = footerY + 3 + (i - firstInputLine) * 9;
            M5Cardputer.Display.setCursor(CHAT_PANEL_X + 6, lineY);
            M5Cardputer.Display.print(trimToPixelWidth(inputLines[i], footerW - 12));
        }

        M5Cardputer.Display.setTextColor(uiTextMutedColor(), footerColor);
        M5Cardputer.Display.setCursor(CHAT_PANEL_X + 6, footerY + 23);
        M5Cardputer.Display.print("Enter send, BKSP cancel");
    } else {
        M5Cardputer.Display.setTextColor(uiTextMutedColor(), footerColor);
        M5Cardputer.Display.setCursor(CHAT_PANEL_X + 6, footerY + 13);
        M5Cardputer.Display.print(secureReady ? "Enter compose, ;/. scroll" : "Enter starts key exchange");
    }
}

void handleMessageInput(int key) {
    if (!isTypingMsg && key == KEY_BACKSPACE) {
        currentMenu = MENU_CONTACTS;
        return;
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
            return;
        } 
        if (key == '.') {        // DOWN
            messageScroll = max(0, messageScroll - 1);
            drawMessageMenu();
            return;
        }
    }

    if (!isTypingMsg && key == KEY_ENTER) {
        if (!MessageCrypto::hasReadySession(contacts, selectedContact)) {
            if (requestKeyExchange(selectedContact.c_str())) {
                showSuccessToast("Key exchange started", 700);
            } else {
                showErrorToast("Key exchange failed");
            }
            drawMessageMenu();
            return;
        }
        isTypingMsg = true;
        messageInput = "";
        drawMessageMenu();
        return;
    }

    if (isTypingMsg) {
        if (key == KEY_ENTER) {
            if (messageInput.length() == 0) return;

            if (!selectContactPeer(selectedContact.c_str())) {
                drawMessageMenu();
                showErrorToast("Invalid peer MAC");
                isTypingMsg = false;
                drawMessageMenu();
                return;
            }

            if (!MessageCrypto::hasReadySession(contacts, selectedContact)) {
                if (requestKeyExchange(selectedContact.c_str())) {
                    showSuccessToast("Key exchange started", 700);
                } else {
                    showErrorToast("Key exchange failed");
                }
                drawMessageMenu();
                return;
            }

            uint16_t msgId = sendSplitMessage(selectedMac, selectedContact, messageInput);
            if (msgId == 0) {
                drawMessageMenu();
                showErrorToast("Send failed");
                isTypingMsg = false;
                drawMessageMenu();
                return;
            }

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
        
        if (handleTextInput(key, messageInput, MAX_MESSAGE_TEXT_LEN)) {
            drawMessageMenu();
        }
    }
}
