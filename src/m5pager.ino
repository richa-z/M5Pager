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

#include "menus.h"
#include "menus/menu_main.h"
#include "menus/menu_contacts.h"
#include "menus/menu_messsage.h"
#include "menus/menu_settings.h"
#include "menus/menu_change_user.h"
#include "menus/menu_add_contact.h"

#include "enums/packet_types.h"

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
  {drawAddContact, handleAddContactInput}
};

const char* ssid PROGMEM = "PAGER_COM";
const char* password PROGMEM = "sd65fd4Fd4_dKAIu::?_a5df4sd";

uint8_t selectedMac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const char* selectedContact = nullptr;

bool isAP = false;

typedef struct MessageStruct {
  PacketType type;
  uint8_t from[6];

  uint16_t message_id;
  uint8_t split_size;
  uint8_t split_index;

  uint8_t data_len;
  char msg[MSG_CHUNK_SIZE];
} MessageStruct;

typedef struct IncomingAssembly {
    uint16_t message_id;
    uint8_t expected_parts;
    bool received[32];
    String data;
} IncomingAssembly;

MessageStruct msgIncoming;
MessageStruct msgOutgoing;

IncomingAssembly assembly{};

esp_now_peer_info_t peerInfo;

SPIClass spi = SPIClass(FSPI);
DynamicJsonDocument contacts(8192);
DynamicJsonDocument config(1024);

char inputBuffer[MSG_CHUNK_SIZE];
int bytesRead;
bool messageSentFlag = false;

const char* user = "User";

/*

NETWORKING

*/

void sendSplitMessage(const uint8_t* targetMac, const String& text) {
    static uint16_t messageCounter = 0;
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

        esp_now_send(targetMac, (uint8_t*)&pkt, sizeof(MessageStruct) - MSG_CHUNK_SIZE + pkt.data_len);
        delay(10); // brief delay to avoid overwhelming the receiver
    }
}

void onDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
    Serial.print("[+] Last Packet Send Status: ");
    M5Cardputer.Display.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}

void onDataRecv(const uint8_t *mac_addr, const uint8_t *data, int data_len) {
    if (data_len < sizeof(MessageStruct) - MSG_CHUNK_SIZE) return;

    MessageStruct pkt;
    memcpy(&pkt, data, data_len);

    if (pkt.type != P_MSG) return;

    if (pkt.split_index == 0) {
        assembly = {};
        assembly.message_id = pkt.message_id;
        assembly.expected_parts = pkt.split_size;
        assembly.data.reserve(pkt.split_size * MSG_CHUNK_SIZE);
    }

    if (pkt.message_id != assembly.message_id) return;
    if (pkt.split_index >= 32) return;

    if (!assembly.received[pkt.split_index]) {
        assembly.received[pkt.split_index] = true;
        assembly.data += String(pkt.msg).substring(0, pkt.data_len);
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
        appendMessage(contacts, senderMac, "in", assembly.data.c_str());

        if (currentMenu == MENU_MESSAGE &&
            selectedContact &&
            senderMac == selectedContact) {
            drawMessageMenu();
        }
    }
}

void setup() {
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Display.setTextFont(2);
  M5Cardputer.Display.setTextSize(0.75);
  M5Cardputer.Display.println("Starting...");
  spi.begin(SD_CLK, SD_MISO, SD_MOSI, SD_CS);

  if (!SD.begin(SD_CS, spi)) {
	  M5Cardputer.Display.println("[-] SD Card Mount Failed");
	  return;
  }

  M5Cardputer.Display.println("[+] SD Card initialized.");  

  //wifi setup
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  

  //this might not be necessary, but just in case
  if (ScanAP(ssid)) {
    M5Cardputer.Display.println("[+] Network exists. Connecting.");
    WiFi.begin(ssid, password);
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

  //do not connect to null mac
  bool macEmptyFlag = true;
  for (int i = 0; i < 6; i++) {
      if (selectedMac[i] != 0x00) {
          macEmptyFlag = false;
          break;
      }
  }

  if (!macEmptyFlag) {
    memcpy(peerInfo.peer_addr, selectedMac, 6);
    peerInfo.channel = 0;  
    peerInfo.encrypt = false;

    if (esp_now_add_peer(&peerInfo) != ESP_OK){
      M5Cardputer.Display.println("[-] Failed to add peer");
      return;
    }

    M5Cardputer.Display.println("[+] Peer added: " + String(selectedMac[0], HEX) + ":" + String(selectedMac[1], HEX) + ":" + String(selectedMac[2], HEX) + ":" + String(selectedMac[3], HEX) + ":" + String(selectedMac[4], HEX) + ":" + String(selectedMac[5], HEX));
    M5Cardputer.Display.println("[+] ESP-NOW setup complete.");
  } else {
    M5Cardputer.Display.println("[!] No peer selected. Skipping ESP-NOW peer add.");
    M5Cardputer.Display.println("[!] ESP-NOW setup incomplete.");
  }

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
  M5Cardputer.Display.fillScreen(0);
  M5Cardputer.Display.setCursor(0, 0);
  M5Cardputer.Display.setTextSize(1);

  //typewriter effect for nice welcome message :3
  user = config["username"];
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


  //up and down are ; and . respecively, handled in the loop above
  if (M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) key = KEY_ENTER; //SELECT
  if (M5Cardputer.Keyboard.isKeyPressed(KEY_BACKSPACE)) key = KEY_BACKSPACE; //BACK

  if (key != 0) {
      menus[currentMenu].handleInput(key);
      delay(150);
  }

  if (currentMenu != previousMenu) {
      M5Cardputer.Display.fillScreen(0);
      menus[currentMenu].draw();
      previousMenu = currentMenu;
      menuIndex = 0;
      delay(150);
  }
}
