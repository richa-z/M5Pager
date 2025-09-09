#include <WiFi.h>
#include <esp_now.h>
#include <ArduinoJson.h>
#include <cstring>
#include <String.h>
#include <M5Cardputer.h>
#include <SD.h>
#include <SPI.h>

#include "network_util.h"
#include "json_management.h"
#include "gui_handlers.h"
#include "menus.h"
#include "menu_main.h"
#include "menu_contacts.h"

#define SD_CS 12
#define SD_MOSI 14
#define SD_CLK 40
#define SD_MISO 39

// === CONFIG ===
const int BUFFER_SIZE PROGMEM = 4096;

MenuState currentMenu = MENU_MAIN;

int menuIndex = 0;
const char* mainMenuItems[] = {
    "Contacts",
    "Messages",
    "Network",
    "Settings"
};

const int mainMenuSize = sizeof(mainMenuItems) / sizeof(mainMenuItems[0]);

MenuHandler menus[] = {
  {drawMainMenu, handleMainMenuInput},
  {drawContactsMenu, handleContactsMenuInput}
  //TODO: Add other menus here later
};

const char* ssid PROGMEM = "PAGER_COM";
const char* password PROGMEM = "12345678";

uint8_t selectedMac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
bool isAP = false;

typedef struct MessageStruct {
  uint8_t from[6];
  char msg[BUFFER_SIZE];
} MessageStruct;

MessageStruct msgIncoming;
MessageStruct msgOutgoing;

esp_now_peer_info_t peerInfo;

SPIClass spi = SPIClass(FSPI);
DynamicJsonDocument contacts(8192);
DynamicJsonDocument config(1024);

JsonObject username;

char inputBuffer[BUFFER_SIZE];
int bytesRead;
bool messageSentFlag = false;
bool isCmd = false; // cli-testing

void onDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
    Serial.print("[+] Last Packet Send Status: ");
    M5Cardputer.Display.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}

void onDataRecv(const uint8_t *mac_addr, const uint8_t *data, int data_len) {
    if (data_len > sizeof(msgIncoming.msg) + sizeof(msgIncoming.from)) {
        M5Cardputer.Display.println("[-] Received data too large.");
        return;
    }

    if (data_len - 6 > BUFFER_SIZE) {
        M5Cardputer.Display.println("[-] Message too long.");
        return;
    }

    memcpy(msgIncoming.msg, data, data_len - sizeof(msgIncoming.from));
    msgIncoming.msg[data_len - sizeof(msgIncoming.from)] = '\0';
    memcpy(msgIncoming.from, mac_addr, 6);

    //TODO: Sound buzzer
    M5Cardputer.Display.println("[!] Message received.");
    Serial.printf("[+] From: %02X:%02X:%02X:%02X:%02X:%02X\n",
                  mac_addr[0], mac_addr[1], mac_addr[2],
                  mac_addr[3], mac_addr[4], mac_addr[5]);
    M5Cardputer.Display.println("[+] Message: " + String(msgIncoming.msg) + "\n");
}




void setup() {
  Serial.begin(9600);
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Display.setTextFont(2);
  M5Cardputer.Display.setTextSize(0.75);
  M5Cardputer.Display.println("Starting...");
  spi.begin(SD_CLK, SD_MISO, SD_MOSI, SD_CS);

  if (!SD.begin(SD_CS, spi, 4000000)) {
	  M5Cardputer.Display.println("[-] SD Card Mount Failed");
	  return;
  }

  M5Cardputer.Display.println("[+] SD Card initialized.");
  //M5 boiler
  

  //wifi setup
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  
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
  const char* user = config["username"];
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
  if (M5Cardputer.Keyboard.isKeyPressed(';')) key = ';'; //UP
  if (M5Cardputer.Keyboard.isKeyPressed('.')) key = '.'; //DOWN
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
  }
}
