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

const char* user = "User";
String editContactName = "";
String messageInput = "";
bool isTypingMsg = false;

bool awaitingAck = false;
uint16_t awaitingMsgId = 0;
unsigned long sendTimestamp = 0;
int messageScroll = 0;

/*

NETWORKING

*/

bool addOrRefreshPeer(const uint8_t* peerMac) {
    if (peerMac == nullptr) return false;
    if (esp_now_is_peer_exist(peerMac)) return true;

    esp_now_peer_info_t peer{};
    memcpy(peer.peer_addr, peerMac, 6);
    peer.channel = 0;
    peer.encrypt = false;

    return esp_now_add_peer(&peer) == ESP_OK;
}

bool selectContactPeer(const char* contactMac) {
    uint8_t parsedMac[6];
    if (!parseMacAddress(contactMac, parsedMac)) return false;

    memcpy(selectedMac, parsedMac, sizeof(selectedMac));
    return addOrRefreshPeer(selectedMac);
}

void onDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
    Serial.print("[+] Last Packet Send Status: ");
    M5Cardputer.Display.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}

void onDataRecv(const uint8_t *mac_addr, const uint8_t *data, int data_len) {
    const int headerSize = sizeof(MessageStruct) - MSG_CHUNK_SIZE;
    if (data_len < headerSize || data_len > static_cast<int>(sizeof(MessageStruct))) return;

    MessageStruct pkt{};
    memcpy(&pkt, data, data_len);

    if (pkt.type == P_MSG_ACK) {
        if (awaitingAck && pkt.message_id == awaitingMsgId) {
            awaitingAck = false;
        }
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
        String senderMac = macToString(mac_addr);
        String contactKey = findContactKeyByMac(contacts, senderMac);
        if (contactKey.length() > 0) {
            appendMessage(contacts, contactKey, "in", assembly.data.c_str());
        }

        if (currentMenu == MENU_MESSAGE &&
            selectedContact &&
            senderMac.equalsIgnoreCase(selectedContact)) {
            drawMessageMenu();
        }
    }

    addOrRefreshPeer(mac_addr);
    MessageStruct ack{};
    ack.type = P_MSG_ACK;
    ack.message_id = pkt.message_id;
    esp_now_send(mac_addr, (uint8_t*)&ack, sizeof(MessageStruct) - MSG_CHUNK_SIZE);
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

  //wifi setup
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();
  

  //this might not be necessary, but just in case
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
  M5Cardputer.Display.fillScreen(0);
  M5Cardputer.Display.setCursor(0, 0);
  M5Cardputer.Display.setTextSize(1);

  //typewriter effect for nice welcome message :3
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


  //up and down are ; and . respectively, handled in the loop above
  if (M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) key = KEY_ENTER; //SELECT
  if (M5Cardputer.Keyboard.isKeyPressed(KEY_BACKSPACE)) key = KEY_BACKSPACE; //BACK

  if (key != 0) {
      menus[currentMenu].handleInput(key);
      delay(150);
  }

    if (awaitingAck && millis() - sendTimestamp > ACK_TIMEOUT) {
        awaitingAck = false;
        M5Cardputer.Display.setTextColor(RED, BLACK);
        M5Cardputer.Display.println("[-] Message failed to send");
        delay(800);
    }

  if (currentMenu != previousMenu) {
      M5Cardputer.Display.fillScreen(0);
      menus[currentMenu].draw();
      previousMenu = currentMenu;
      menuIndex = 0;
      delay(150);
  }
}
