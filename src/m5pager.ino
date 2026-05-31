#include <WiFi.h>
#include <esp_now.h>
#include <ArduinoJson.h>
#include <cstring>
#include <String.h>
#include <M5Cardputer.h>
#include <SD.h>
#include <SPI.h>
#include <stdint.h>

#include "util/network_util.h"
#include "json_management.h"
#include "gui_handlers.h"
#include "security/device_key_store.h"
#include "security/message_crypto.h"

#include "enums/packet_types.h"

#include "menus.h"
#include "menus/menu_main.h"
#include "menus/menu_contacts.h"
#include "menus/menu_messsage.h"
#include "menus/menu_settings.h"
#include "menus/menu_change_user.h"
#include "menus/menu_add_contact.h"
#include "menus/menu_contact_options.h"
#include "menus/menu_edit_contact.h"



#define SD_CS 12
#define SD_MOSI 14
#define SD_CLK 40
#define SD_MISO 39

#define MSG_CHUNK_SIZE 180

// === CONFIG ===

MenuState currentMenu = MENU_MAIN;

int menuIndex = 0;
const char* mainMenuItems[] = {
    "Contacts",
    "Settings"
};

const int mainMenuSize = sizeof(mainMenuItems) / sizeof(mainMenuItems[0]);
int contactsSize = 0;

MenuHandler menus[] = {
  {drawMainMenu, handleMainMenuInput},
  {drawContactsMenu, handleContactsMenuInput},
  {drawMessageMenu, handleMessageInput},
  {drawSettingsMenu, handleSettingsMenuInput},
  {drawChangeUsername, handleChangeUsernameInput},
  {drawAddContact, handleAddContactInput},
  {drawContactOptions, handleContactOptionsInput},
  {drawEditContact, handleEditContactInput}
};

//Comm login -> TODO: do nastaveni
const char* ssid PROGMEM = "PAGER_COM";
const char* password PROGMEM = "sd65fd4Fd4_dKAIu::?_a5df4sd";

uint8_t selectedMac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const char* selectedContact = nullptr;

bool isAP = false;

MessageStruct msgIncoming;
MessageStruct msgOutgoing;

IncomingAssembly assembly{};

SPIClass spi = SPIClass(FSPI);
DynamicJsonDocument contacts(8192);
DynamicJsonDocument config(1024);

char inputBuffer[MSG_CHUNK_SIZE];
int bytesRead;
bool messageSentFlag = false;

const char* user = "User"; //username, nacitane/menene z configu, default "User"
String editContactName = "";
String messageInput = "";
bool isTypingMsg = false;

bool awaitingAck = false;
uint16_t awaitingMsgId = 0;
unsigned long sendTimestamp = 0;
bool pendingOutgoingReady = false;
String pendingOutgoingContact = "";
String pendingOutgoingText = "";
int messageScroll = 0;

/*

NETWORKING

*/

/// @brief Pridá peer do ESP-NOW, ak nie je pridaný.
/// @param peerMac Peer MAC adresa
/// @return TRUE ak bol peer pridaný/existuje, FALSE pri chybe
bool addOrRefreshPeer(const uint8_t* peerMac) {
    if (peerMac == nullptr) return false;
    if (esp_now_is_peer_exist(peerMac)) return true;

    esp_now_peer_info_t peer{};
    memcpy(peer.peer_addr, peerMac, 6);
    peer.channel = 0;
    peer.encrypt = false;

    return esp_now_add_peer(&peer) == ESP_OK;
}

/// @brief  Vyberie kontakt na základe MAC adresy a nastaví ho ako aktuálny peer pre komunikáciu. Ak peer neexistuje, pokúsi se ho pridať.
/// @param contactMac MAC adresa kontaktu
/// @return TRUE ak bol peer vybraný, FALSE pri chybe
bool selectContactPeer(const char* contactMac) {
    uint8_t parsedMac[6];
    if (!parseMacAddress(contactMac, parsedMac)) return false;

    memcpy(selectedMac, parsedMac, sizeof(selectedMac));
    return addOrRefreshPeer(selectedMac);
}

/// @brief Vráti nasledujúce ID pre kontrolné správy. Kontrolné správy sú tie, ktoré nie sú rozdelené na viacero paketov (napr. ACK, výmena kľúčov).
/// @return Nasledujúce ID pre kontrolné správy
uint16_t nextControlMessageId() {
    static uint16_t controlMessageCounter = 40000;
    return ++controlMessageCounter;
}

/// @brief Prevedie payload paketu na string.
/// @param pkt Paket
/// @return String obsahující payload paketu
String packetPayloadToString(const MessageStruct& pkt) {
    String payload;
    payload.reserve(pkt.data_len);
    for (uint8_t i = 0; i < pkt.data_len; i++) {
        payload += pkt.msg[i];
    }
    return payload;
}

/// @brief Odošle jednotlivý paket cez ESP-NOW.
/// @param type Typ paketu
/// @param targetMac MAC adresa cieľa
/// @param payload Payload paketu
/// @param messageId ID správy
/// @return TRUE ak bol paket odoslaný, FALSE pri chybe
bool sendSinglePacket(PacketType type, const uint8_t* targetMac, const String& payload, uint16_t messageId = 0) {
    if (targetMac == nullptr || payload.length() > MSG_CHUNK_SIZE) return false;
    if (!esp_now_is_peer_exist(targetMac) && !addOrRefreshPeer(targetMac)) return false;

    MessageStruct pkt{};
    pkt.type = type;
    esp_read_mac(pkt.from, ESP_MAC_WIFI_STA);
    pkt.message_id = messageId == 0 ? nextControlMessageId() : messageId;
    pkt.split_size = 1;
    pkt.split_index = 0;
    pkt.data_len = payload.length();
    if (pkt.data_len > 0) {
        memcpy(pkt.msg, payload.c_str(), pkt.data_len);
    }

    return esp_now_send(targetMac, (uint8_t*)&pkt, sizeof(MessageStruct) - MSG_CHUNK_SIZE + pkt.data_len) == ESP_OK;
}

/// @brief Odošle ACK správu cez ESP-NOW.
/// @param targetMac MAC adresa cieľa
/// @param messageId ID správy, ktorú ACKujem
void sendMessageAck(const uint8_t* targetMac, uint16_t messageId) {
    if (targetMac == nullptr) return;
    addOrRefreshPeer(targetMac);

    MessageStruct ack{};
    ack.type = P_MSG_ACK;
    ack.message_id = messageId;
    esp_now_send(targetMac, (uint8_t*)&ack, sizeof(MessageStruct) - MSG_CHUNK_SIZE);
}

/// @brief Zabezpečí existenciu kľúča pre danú MAC adresu. 
/// @param mac MAC adresa
/// @return Kľúč kontaktu
String ensureContactKeyForMac(const String& mac) {
    String contactKey = findContactKeyByMac(contacts, mac);
    if (contactKey.length() > 0) return contactKey;

    contactKey = mac;
    JsonObject obj = contacts.createNestedObject(contactKey.c_str());
    obj["username"] = "Peer " + mac.substring(12);
    obj.createNestedArray("messages");
    JsonObject keys = obj.createNestedObject("keys");
    keys["status"] = "none";
    saveContacts(contacts, "/m5pager/contacts.json");
    return contactKey;
}

/// @brief Vyžiada výmenu kľúčov s daným kontaktom.
/// @param contactMac MAC adresa kontaktu
/// @return TRUE ak bol požiadavka odoslaná, FALSE pri chybe
bool requestKeyExchange(const char* contactMac) {
    if (contactMac == nullptr) return false;

    uint8_t peerMac[6];
    if (!parseMacAddress(contactMac, peerMac)) return false;
    if (!addOrRefreshPeer(peerMac)) return false;

    String publicKeyHex;
    if (!MessageCrypto::getOwnPublicKeyHex(publicKeyHex)) return false;

    String contactKey = findContactKeyByMac(contacts, String(contactMac));
    if (contactKey.length() == 0) contactKey = String(contactMac);
    JsonObject keys = MessageCrypto::ensureKeyObject(contacts, contactKey);
    keys["status"] = "pending";
    keys["x25519_own_pub"] = publicKeyHex;
    saveContacts(contacts, "/m5pager/contacts.json");

    return sendSinglePacket(P_INIT_EXCH, peerMac, publicKeyHex);
}
/// @brief Spracuje paket výmeny kľúčov.
/// @param mac_addr MAC adresa odosielateľa
/// @param pkt Paket
void handleKeyExchangePacket(const uint8_t* mac_addr, const MessageStruct& pkt) {
    String senderMac = macToString(mac_addr);
    String contactKey = ensureContactKeyForMac(senderMac);
    String peerPublicHex = packetPayloadToString(pkt);

    if (pkt.type == P_EXCH_OK) {
        return;
    }

    bool ok = MessageCrypto::storePeerPublicAndSession(contacts, contactKey, peerPublicHex);
    if (!ok) {
        JsonObject keys = MessageCrypto::ensureKeyObject(contacts, contactKey);
        keys["status"] = "error";
        saveContacts(contacts, "/m5pager/contacts.json");
        return;
    }

    saveContacts(contacts, "/m5pager/contacts.json");

    String ownPublicHex;
    if (!MessageCrypto::getOwnPublicKeyHex(ownPublicHex)) return;

    if (pkt.type == P_INIT_EXCH) {
        sendSinglePacket(P_ACK_EXCH, mac_addr, ownPublicHex, pkt.message_id);
    } else if (pkt.type == P_ACK_EXCH) {
        sendSinglePacket(P_EXCH_OK, mac_addr, "", pkt.message_id);
    }

    if (currentMenu == MENU_MESSAGE && selectedContact && senderMac.equalsIgnoreCase(selectedContact)) {
        drawMessageMenu();
    }
}

/// @brief Handler pre prijaté ESP-NOW pakety. (nepoužítý, ale je ho treba)
/// @param mac_addr 
/// @param status 
void onDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
    Serial.print("[+] Last packet send status: ");
    Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}

/// @brief Handler pre prijaté ESP-NOW pakety. Spracuje prijaté pakety, zloží ich z častí, dešifruje a uloží do histórie zpráv. ACK a refresh
/// @param mac_addr MAC adresa odosielateľa
/// @param data Prijaté dáta
/// @param data_len Dĺžka prijatých dát
void onDataRecv(const uint8_t *mac_addr, const uint8_t *data, int data_len) {
    const int headerSize = sizeof(MessageStruct) - MSG_CHUNK_SIZE;
    if (data_len < headerSize || data_len > static_cast<int>(sizeof(MessageStruct))) return;

    MessageStruct pkt{};
    memcpy(&pkt, data, data_len);

    if (pkt.type == P_MSG_ACK) {
        if (awaitingAck && pkt.message_id == awaitingMsgId) {
            awaitingAck = false;
            if (pendingOutgoingReady) {
                String contactKey = pendingOutgoingContact;
                appendMessage(contacts, contactKey, "out", pendingOutgoingText.c_str());

                pendingOutgoingReady = false;
                pendingOutgoingContact = "";
                pendingOutgoingText = "";

                if (currentMenu == MENU_MESSAGE &&
                    selectedContact &&
                    contactKey.equalsIgnoreCase(selectedContact)) {
                    drawMessageMenu();
                }
            }
        }
        return;
    }

    if (pkt.type == P_INIT_EXCH || pkt.type == P_ACK_EXCH || pkt.type == P_EXCH_OK) {
        handleKeyExchangePacket(mac_addr, pkt);
        return;
    }

    if (pkt.type != P_MSG) return;
    if (pkt.split_size == 0 || pkt.split_size > 32) return;
    if (pkt.split_index >= pkt.split_size) return;
    if (pkt.split_index >= 32) return;

    int payloadLen = data_len - headerSize;
    if (pkt.data_len > payloadLen || pkt.data_len > MSG_CHUNK_SIZE) return;

    if (pkt.split_index == 0) {
        assembly = {};
        assembly.message_id = pkt.message_id;
        assembly.expected_parts = pkt.split_size;
        assembly.data.reserve(pkt.split_size * MSG_CHUNK_SIZE);
    }

    if (pkt.message_id != assembly.message_id) return;

    if (!assembly.received[pkt.split_index]) {
        assembly.received[pkt.split_index] = true;
        for (uint8_t i = 0; i < pkt.data_len; i++) {
            assembly.data += pkt.msg[i];
        }
    }

    bool complete = true;
    for (uint8_t i = 0; i < assembly.expected_parts; i++) {
        if (!assembly.received[i]) {
            complete = false;
            break;
        }
    }

    if (complete) {
        sendMessageAck(mac_addr, pkt.message_id);

        String senderMac = macToString(mac_addr);
        String contactKey = ensureContactKeyForMac(senderMac);
        if (contactKey.length() > 0) {
            String plaintext;
            if (MessageCrypto::decryptPayload(contacts, contactKey, assembly.data, plaintext)) {
                appendMessage(contacts, contactKey, "in", plaintext.c_str());
            } else if (MessageCrypto::hasReadySession(contacts, contactKey)) {
                appendMessage(contacts, contactKey, "in", "[Message decrypt failed]");
            } else {
                appendMessage(contacts, contactKey, "in", "[Encrypted message - key missing]");
            }
        }

        if (currentMenu == MENU_MESSAGE &&
            selectedContact &&
            senderMac.equalsIgnoreCase(selectedContact)) {
            drawMessageMenu();
        }
    }
}

/*

BASE

*/

void setup() {
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Display.setTextFont(2);
  M5Cardputer.Display.setTextSize(0.75);
  M5Cardputer.Display.setTextScroll(true);
  M5Cardputer.Display.setCursor(0, 0);
  M5Cardputer.Display.println("Starting...");

  DeviceKeyProvisionState keyState = Security::ensureDevicePrivateKey();
  if (keyState == DeviceKeyProvisionState::Error) {
      M5Cardputer.Display.println("[-] FATAL: Key provisioning failed.");
      return;
  }

  if (keyState == DeviceKeyProvisionState::CreatedNew) {
      M5Cardputer.Display.println("[+] Device private key provisioned.");
  } else {
      M5Cardputer.Display.println("[+] Device private key loaded.");
  }
  M5Cardputer.Display.println("[*] Key ID: " + Security::getDeviceKeyFingerprint());

  spi.begin(SD_CLK, SD_MISO, SD_MOSI, SD_CS);

  if (!SD.begin(SD_CS, spi)) {
	  M5Cardputer.Display.println("[-] SD Card Mount Failed");
	  return;
  }

  M5Cardputer.Display.println("[+] SD Card initialized.");  

  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();
  
  if (ScanAP(ssid)) {
    M5Cardputer.Display.println("[+] Network exists. Connecting.");
    WiFi.begin(ssid, password);
    unsigned long connectStart = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - connectStart < 5000) {
      delay(100);
    }
    if (WiFi.status() != WL_CONNECTED) {
      M5Cardputer.Display.println("[!] Connect timeout. Creating AP.");
      WiFi.softAP(ssid, password);
      isAP = true;
    }
  } else {
    M5Cardputer.Display.println("[+] Network not found. Creating.");
    WiFi.softAP(ssid, password);
    isAP = true;
  }

  M5Cardputer.Display.println("[+] Network established. Network details:");
  M5Cardputer.Display.println("Device MAC Address: " + WiFi.macAddress());

  //p2p setup
  if (esp_now_init() != ESP_OK) {
    M5Cardputer.Display.println("[-] FATAL: ESP-NOW init failed.");
    return;
  }

  esp_now_register_send_cb(onDataSent);
  esp_now_register_recv_cb(onDataRecv);
  M5Cardputer.Display.println("[+] ESP-NOW setup complete.");

  if (!loadContacts(contacts, "/m5pager/contacts.json")) {
      M5Cardputer.Display.println("[-] Failed to load contacts.");
  } else {
      M5Cardputer.Display.println("[+] Contacts loaded.");
  }

  if (!loadConfig(config, "/m5pager/config.json")) {
      M5Cardputer.Display.println("[-] Failed to load config.");
  } else {
      M5Cardputer.Display.println("[+] Config loaded.");
  }

  M5Cardputer.Display.println("[+] Setup complete.");

  delay(1000);
  M5Cardputer.Display.setTextScroll(false);
  M5Cardputer.Display.fillScreen(uiBgColor());
  M5Cardputer.Display.setCursor(0, 0);
  M5Cardputer.Display.setTextSize(1);
  M5Cardputer.Display.setTextColor(uiTextPrimaryColor(), uiBgColor());

  //animácia privítania
  user = config["username"] | "User";
  String welcomeMsg = "Welcome back, " + String(user) + "!\n";
  M5Cardputer.Display.setCursor(M5Cardputer.Display.width() / 2 - welcomeMsg.length() * 3, M5Cardputer.Display.height() / 2 - 4);
  for (size_t i = 0; i < welcomeMsg.length(); i++) {
      M5Cardputer.Display.print(welcomeMsg[i]);
      delay(100);
  }

  delay(2000);
  menus[currentMenu].draw();
}

MenuState previousMenu = MENU_MAIN;

void loop() {
  M5Cardputer.update();

  int key = 0;

  //check all ascii keys
    for (char c = 32; c <= 126; c++) {
        if (M5Cardputer.Keyboard.isKeyPressed(c)) {
            key = c;
            break;
        }
    }


  //up and down are ; and .
  if (M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) key = KEY_ENTER; //SELECT
  if (M5Cardputer.Keyboard.isKeyPressed(KEY_BACKSPACE)) key = KEY_BACKSPACE; //BACK

  if (key != 0) {
      menus[currentMenu].handleInput(key);
      delay(150);
  }

    //Ak nie je ACKed
    if (awaitingAck && millis() - sendTimestamp > ACK_TIMEOUT) {
        awaitingAck = false;
        pendingOutgoingReady = false;
        pendingOutgoingContact = "";
        pendingOutgoingText = "";
        showErrorToast("Message failed to send");
        if (currentMenu == MENU_MESSAGE) {
            drawMessageMenu();
        }
    }

  if (currentMenu != previousMenu) {
      M5Cardputer.Display.fillScreen(uiBgColor());
      menus[currentMenu].draw();
      previousMenu = currentMenu;
      menuIndex = 0;
      delay(150);
  }
}
