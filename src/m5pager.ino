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
#include "menus/menu_wifi.h"



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
  {drawEditContact, handleEditContactInput},
  {drawChangeSsid, handleChangeSsidInput},
  {drawChangeSsidPass, handleChangeSsidPassInput}
};

// Prihlasovacie údaje siete sa NEZAPISUJÚ do zdrojáku - boli by v gite aj v každom
// vypísanom firmvéri a všetky zariadenia by zdieľali jedno heslo. Držia sa v config.json,
// ktorý je na karte šifrovaný kľúčom zariadenia, a menia sa v Settings.
constexpr const char* DEFAULT_WIFI_SSID = "PAGER_COM";

String wifiSsid = "";
String wifiPass = "";

uint8_t selectedMac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Vlastnená kópia kľúča kontaktu. Ukazovateľ do JSON dokumentu tu byť nesmie -
// dokument sa prealokuje pri raste a ukazovateľ by ostal visieť.
String selectedContact = "";

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

String user = "User"; //username, nacitane/menene z configu, default "User"
String editContactName = "";
String messageInput = "";
bool isTypingMsg = false;

bool awaitingAck = false;
uint16_t awaitingMsgId = 0;
uint8_t awaitingMac[6] = {0}; //komu sme poslali - ACK od nikoho iného neuznáme
unsigned long sendTimestamp = 0;
bool pendingOutgoingReady = false;
String pendingOutgoingContact = "";
String pendingOutgoingText = "";
int messageScroll = 0;
bool stealthMode = false;
unsigned long nextAliveBroadcast = 0;

// Po nečinnosti sa zariadenie zamkne - kľúče aj dešifrované dáta sa vymažú z RAM
// a znovu sa pýta heslo. Bez toho stačí odložené odomknuté zariadenie zdvihnúť.
constexpr unsigned long IDLE_LOCK_TIMEOUT_MS = 5UL * 60UL * 1000UL;
unsigned long lastActivityMs = 0;

// Efemérny súkromný kľúč rozpracovanej výmeny. Drží sa VÝHRADNE v RAM a po dokončení
// (alebo vypršaní) sa vynuluje - práve jeho zahodenie dáva forward secrecy.
constexpr unsigned long KEY_EXCHANGE_TIMEOUT_MS = 30UL * 1000UL;
bool pendingExchangeValid = false;
String pendingExchangeContact = "";
uint8_t pendingExchangeEphPriv[MessageCrypto::X25519_KEY_LEN] = {0};
unsigned long pendingExchangeStartedMs = 0;

/// @brief Zahodí rozpracovanú výmenu kľúčov a vynuluje efemérny kľúč.
void clearPendingExchange() {
    Security::secureZero(pendingExchangeEphPriv, sizeof(pendingExchangeEphPriv));
    pendingExchangeValid = false;
    pendingExchangeContact = "";
    pendingExchangeStartedMs = 0;
}

/*

NETWORKING

*/

// ESP-NOW receive callback beží vo WiFi tasku súbežne s loop(). Nesmie preto sahať
// na JSON dokument, SD kartu ani na displej - všetko to používa aj loop() a nič z toho
// nie je chránené zámkom. Callback preto paket iba odloží do fronty a spracuje ho loop().
constexpr uint8_t RX_QUEUE_SIZE = 8;
static RxQueueItem rxQueue[RX_QUEUE_SIZE];
static volatile uint8_t rxQueueHead = 0;  //zapisuje konzument (loop)
static volatile uint8_t rxQueueTail = 0;  //zapisuje producent (callback)

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
    // Kontrolné ID majú vždy nastavený najvyšší bit, dátové (sendSplitMessage) nikdy.
    // Predtým obe rady rástli v spoločnom 16-bitovom priestore a po pretečení sa
    // začali prekrývať - ACK alebo odpoveď na výmenu kľúčov sa tak mohli spárovať
    // s nesúvisiacou správou.
    static uint16_t controlMessageCounter = 0;
    controlMessageCounter = (controlMessageCounter + 1) & MESSAGE_ID_VALUE_MASK;
    if (controlMessageCounter == 0) controlMessageCounter = 1;
    return controlMessageCounter | MESSAGE_ID_CONTROL_FLAG;
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

    uint8_t wire[PACKET_MAX_LEN];
    size_t wireLen = serializePacket(pkt, wire);
    if (wireLen == 0) return false;

    return esp_now_send(targetMac, wire, wireLen) == ESP_OK;
}

/// @brief Odošle ACK správu cez ESP-NOW.
/// @param targetMac MAC adresa cieľa
/// @param messageId ID správy, ktorú ACKuje
void sendMessageAck(const uint8_t* targetMac, uint16_t messageId) {
    if (targetMac == nullptr) return;
    addOrRefreshPeer(targetMac);

    MessageStruct ack{};
    ack.type = P_MSG_ACK;
    esp_read_mac(ack.from, ESP_MAC_WIFI_STA);
    ack.message_id = messageId;
    ack.split_size = 1;
    ack.split_index = 0;
    ack.data_len = 0;

    uint8_t wire[PACKET_MAX_LEN];
    size_t wireLen = serializePacket(ack, wire);
    if (wireLen == 0) return;

    esp_now_send(targetMac, wire, wireLen);
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

    String staticPubHex;
    if (!MessageCrypto::getOwnPublicKeyHex(staticPubHex)) return false;

    // Pre každú výmenu sa vyrobí nový efemérny pár - vďaka nemu sa relácia nedá
    // zrekonštruovať ani neskôr z dlhodobého kľúča zariadenia
    uint8_t ephPriv[MessageCrypto::X25519_KEY_LEN];
    uint8_t ephPub[MessageCrypto::X25519_KEY_LEN];
    if (!MessageCrypto::generateEphemeralKeypair(ephPriv, ephPub)) return false;

    String contactKey = findContactKeyByMac(contacts, String(contactMac));
    if (contactKey.length() == 0) contactKey = String(contactMac);

    // ID si zapamätáme, aby sme vedeli overiť, že prichádzajúci P_ACK_EXCH
    // patrí k tejto našej žiadosti a nie je podvrhnutý cudzou stranou.
    uint16_t exchangeId = nextControlMessageId();

    JsonObject keys = MessageCrypto::ensureKeyObject(contacts, contactKey);
    keys["status"] = "pending";
    keys["x25519_own_pub"] = staticPubHex;
    keys["pending_id"] = exchangeId;
    keys.remove("rekey_offer");
    saveContacts(contacts, "/m5pager/contacts.json");

    clearPendingExchange();
    memcpy(pendingExchangeEphPriv, ephPriv, sizeof(pendingExchangeEphPriv));
    pendingExchangeContact = contactKey;
    pendingExchangeStartedMs = millis();
    pendingExchangeValid = true;

    String payload = staticPubHex + MessageCrypto::bytesToHex(ephPub, MessageCrypto::X25519_KEY_LEN);
    Security::secureZero(ephPriv, sizeof(ephPriv));

    bool sent = sendSinglePacket(P_INIT_EXCH, peerMac, payload, exchangeId);
    if (!sent) clearPendingExchange();
    return sent;
}

/// @brief Zruší nadviazanú reláciu s kontaktom (používa sa pred zámerným prekľúčovaním).
/// @param contactKey Kľúč kontaktu
void clearSession(const String& contactKey) {
    if (!contacts.containsKey(contactKey)) return;
    JsonObject keys = MessageCrypto::ensureKeyObject(contacts, contactKey);
    keys["status"] = "none";
    keys.remove("tx_chain");
    keys.remove("rx_chain");
    keys.remove("role");
    keys.remove("fingerprint");
    keys.remove("rekey_offer");
    keys.remove("pending_id");

    // Reťazce sa zahadzujú bez náhrady - staré kľúče správ sa už nedajú vyrobiť.
    // Počítadlá netreba zachovávať: každý handshake má nové efemérne kľúče,
    // takže nová relácia nikdy nepoužije rovnaké kľúče ako niektorá predošlá.
}
/// @brief Spracuje paket výmeny kľúčov.
/// @param mac_addr MAC adresa odosielateľa
/// @param pkt Paket
void handleKeyExchangePacket(const uint8_t* mac_addr, const MessageStruct& pkt) {
    String senderMac = macToString(mac_addr);
    String payload = packetPayloadToString(pkt);

    if (pkt.type == P_EXCH_OK) {
        return;
    }

    // Payload je statický aj efemérny verejný kľúč v hex tvare. Overíme ho skôr,
    // než kvôli nemu čokoľvek založíme.
    const size_t keyHexLen = MessageCrypto::X25519_KEY_LEN * 2;
    if (payload.length() != keyHexLen * 2) return;

    String peerPublicHex = payload.substring(0, keyHexLen);      //statický = identita
    String peerEphemeralHex = payload.substring(keyHexLen);      //efemérny = forward secrecy

    String contactKey = findContactKeyByMac(contacts, senderMac);
    bool knownContact = contactKey.length() > 0;

    if (pkt.type == P_ACK_EXCH) {
        // Odpoveď uznáme len vtedy, ak sme výmenu sami začali a ID sedí s našou žiadosťou.
        // Bez toho by hocikto mohol poslať nevyžiadaný P_ACK_EXCH a prepísať nám kľúč.
        if (!knownContact) return;

        JsonObject keys = MessageCrypto::ensureKeyObject(contacts, contactKey);
        const char* status = keys["status"];
        if (status == nullptr || strcmp(status, "pending") != 0) return;

        uint16_t pendingId = keys["pending_id"] | 0;
        if (pendingId == 0 || pendingId != pkt.message_id) return;

        // Bez nášho efemérneho kľúča sa handshake dokončiť nedá
        if (!pendingExchangeValid || !pendingExchangeContact.equalsIgnoreCase(contactKey)) return;
        if (millis() - pendingExchangeStartedMs > KEY_EXCHANGE_TIMEOUT_MS) {
            clearPendingExchange();
            return;
        }
    } else {  // P_INIT_EXCH
        if (knownContact && MessageCrypto::hasReadySession(contacts, contactKey)) {
            // S týmto kontaktom už bezpečnú reláciu máme. Nevyžiadanú žiadosť o novú
            // NEPRIJMEME automaticky - inak by stačilo podvrhnúť MAC kontaktu a kľúč
            // by sa ticho vymenil za útočníkov. Ponuku iba odložíme na schválenie.
            JsonObject keys = MessageCrypto::ensureKeyObject(contacts, contactKey);

            // Zaznamenáme len prvú ponuku a ďalšie ignorujeme, kým ju používateľ
            // nevybaví. Inak by opakovaný P_INIT_EXCH (zakaždým s iným kľúčom)
            // vynucoval zápis na SD a blokujúci toast pri každom pakete.
            if (keys["rekey_offer"].is<const char*>()) return;

            keys["rekey_offer"] = peerPublicHex;
            saveContacts(contacts, "/m5pager/contacts.json");

            if (currentMenu == MENU_MESSAGE && senderMac.equalsIgnoreCase(selectedContact)) {
                drawMessageMenu();
                showErrorToast("Re-key requested - verify first", 1500);
                drawMessageMenu();
            }
            return;
        }

        // Prvé spárovanie (TOFU) - kontakt vytvoríme až tu, keď je paket overený
        if (!knownContact) contactKey = ensureContactKeyForMac(senderMac);
    }

    bool isInitiator = (pkt.type == P_ACK_EXCH);

    // Iniciátor použije efemérny kľúč, ktorý si drží od odoslania žiadosti.
    // Odpovedajúci si vyrobí vlastný až teraz a hneď po výpočte ho zahodí.
    uint8_t ephPriv[MessageCrypto::X25519_KEY_LEN];
    uint8_t ephPub[MessageCrypto::X25519_KEY_LEN];
    String ownEphemeralHex;

    if (isInitiator) {
        memcpy(ephPriv, pendingExchangeEphPriv, sizeof(ephPriv));
    } else {
        if (!MessageCrypto::generateEphemeralKeypair(ephPriv, ephPub)) return;
        ownEphemeralHex = MessageCrypto::bytesToHex(ephPub, MessageCrypto::X25519_KEY_LEN);
    }

    bool ok = MessageCrypto::completeHandshake(contacts, contactKey, peerPublicHex,
                                               peerEphemeralHex, ephPriv, isInitiator);

    // Efemérny súkromný kľúč už nikdy nebude potrebný - zahodením vzniká forward secrecy
    Security::secureZero(ephPriv, sizeof(ephPriv));
    if (isInitiator) clearPendingExchange();

    if (!ok) {
        JsonObject keys = MessageCrypto::ensureKeyObject(contacts, contactKey);
        keys["status"] = "error";
        saveContacts(contacts, "/m5pager/contacts.json");
        return;
    }

    saveContacts(contacts, "/m5pager/contacts.json");

    if (pkt.type == P_INIT_EXCH) {
        String ownPublicHex;
        if (!MessageCrypto::getOwnPublicKeyHex(ownPublicHex)) return;
        sendSinglePacket(P_ACK_EXCH, mac_addr, ownPublicHex + ownEphemeralHex, pkt.message_id);
    } else if (pkt.type == P_ACK_EXCH) {
        sendSinglePacket(P_EXCH_OK, mac_addr, "", pkt.message_id);
    }

    if (currentMenu == MENU_MESSAGE && senderMac.equalsIgnoreCase(selectedContact)) {
        drawMessageMenu();
        // Fingerprint si majitelia oboch zariadení musia porovnať mimo kanála,
        // inak sa MITM pri prvom spárovaní nedá odhaliť.
        showSuccessToast("Key: " + MessageCrypto::getSessionFingerprint(contacts, contactKey), 2000);
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
    if (mac_addr == nullptr) return;

    // Formát paketu sa overí hneď tu - do fronty ide len to, čo je platné a konzistentné
    MessageStruct pkt;
    if (!deserializePacket(data, data_len, pkt)) return;

    uint8_t next = (rxQueueTail + 1) % RX_QUEUE_SIZE;
    if (next == rxQueueHead) return;  //fronta je plná, paket zahodíme

    RxQueueItem& item = rxQueue[rxQueueTail];
    memcpy(item.mac, mac_addr, 6);
    item.pkt = pkt;

    rxQueueTail = next;
}

/// @brief Spracuje jeden prijatý paket. Volá sa výhradne z loop(), nikdy z callbacku.
/// @param mac_addr MAC adresa odosielateľa
/// @param pkt Paket (už overený deserializePacket)
void processInboundPacket(const uint8_t *mac_addr, const MessageStruct& pkt) {
    if (pkt.type == P_MSG_ACK) {
        // ACK uznáme len od toho, komu sme správu naozaj poslali. Inak by ľubovoľné
        // zariadenie mohlo potvrdiť cudziu správu a označiť ju za doručenú.
        if (awaitingAck && memcmp(mac_addr, awaitingMac, 6) == 0 && pkt.message_id == awaitingMsgId) {
            awaitingAck = false;
            if (pendingOutgoingReady) {
                String contactKey = pendingOutgoingContact;
                appendMessage(contacts, contactKey, "out", pendingOutgoingText.c_str());

                pendingOutgoingReady = false;
                pendingOutgoingContact = "";
                pendingOutgoingText = "";

                if (currentMenu == MENU_MESSAGE &&
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
    if (pkt.split_size == 0 || pkt.split_size > MAX_MESSAGE_PARTS) return;
    if (pkt.split_index >= pkt.split_size) return;

    // Iba posledná časť smie byť kratšia. Vďaka tomu je offset každej časti
    // jednoznačne split_index * MSG_CHUNK_SIZE a poradie príchodu nehrá rolu.
    bool isLastPart = (pkt.split_index + 1 == pkt.split_size);
    if (!isLastPart && pkt.data_len != MSG_CHUNK_SIZE) return;
    if (isLastPart && pkt.data_len == 0) return;

    unsigned long now = millis();

    if (pkt.split_index == 0) {
        // Nová správa - zostavovanie vždy začína časťou 0
        resetAssembly(assembly);
        assembly.active = true;
        memcpy(assembly.from, mac_addr, 6);
        assembly.message_id = pkt.message_id;
        assembly.expected_parts = pkt.split_size;
        assembly.lastPacketMs = now;
    } else {
        // Bez prijatej časti 0 nevieme, koľko častí čakať. Predtým sa taký paket prijal
        // s expected_parts == 0, čo test úplnosti vyhodnotil ako hotovú správu -
        // jediný podvrhnutý paket tak vedel založiť kontakt a vynútiť zápis na SD.
        if (!assembly.active) return;
        if (memcmp(assembly.from, mac_addr, 6) != 0) return;
        if (pkt.message_id != assembly.message_id) return;
        if (pkt.split_size != assembly.expected_parts) return;
        if (now - assembly.lastPacketMs > ASSEMBLY_TIMEOUT_MS) {
            resetAssembly(assembly);
            return;
        }
        assembly.lastPacketMs = now;
    }

    if (pkt.split_index >= assembly.expected_parts) return;

    if (!assembly.received[pkt.split_index]) {
        assembly.received[pkt.split_index] = true;
        assembly.partLen[pkt.split_index] = pkt.data_len;
        memcpy(assembly.data + (pkt.split_index * MSG_CHUNK_SIZE), pkt.msg, pkt.data_len);
    }

    bool complete = assembly.expected_parts > 0;
    for (uint8_t i = 0; i < assembly.expected_parts; i++) {
        if (!assembly.received[i]) {
            complete = false;
            break;
        }
    }

    if (!complete) return;

    // Všetky časti okrem poslednej sú plné, takže dáta ležia v buffri súvisle za sebou
    size_t totalLen = 0;
    for (uint8_t i = 0; i < assembly.expected_parts; i++) {
        totalLen += assembly.partLen[i];
    }

    String senderMac = macToString(mac_addr);
    String payload;
    payload.reserve(totalLen);
    for (size_t i = 0; i < totalLen; i++) {
        payload += assembly.data[i];
    }
    resetAssembly(assembly);  //zostavovanie je hotové, stav zahodíme

    // Správu od neznámeho odosielateľa zahodíme bez zápisu. Kontakt sa zakladá výhradne
    // pri výmene kľúčov - inak by ľubovoľné zariadenie vedelo spoofnutými MAC adresami
    // donekonečna zakladať kontakty a vynucovať zápisy na SD kartu.
    String contactKey = findContactKeyByMac(contacts, senderMac);
    if (contactKey.length() == 0) return;

    sendMessageAck(mac_addr, pkt.message_id);

    String plaintext;
    if (MessageCrypto::decryptPayload(contacts, contactKey, payload, plaintext)) {
        appendMessage(contacts, contactKey, "in", plaintext.c_str());
    } else if (MessageCrypto::hasReadySession(contacts, contactKey)) {
        appendMessage(contacts, contactKey, "in", "[Message decrypt failed]");
    } else {
        appendMessage(contacts, contactKey, "in", "[Encrypted message - key missing]");
    }

    if (currentMenu == MENU_MESSAGE && senderMac.equalsIgnoreCase(selectedContact)) {
        drawMessageMenu();
    }
}

/*

ZAMYKANIE

*/

/// @brief Zamkne zariadenie - vymaže kľúče aj všetky dešifrované dáta z pamäte.
void lockDevice() {
    Security::lockRuntimeKeys();

    // Samotné kľúče nestačia - v RAM ostáva história správ aj session kľúče kontaktov
    contacts.clear();
    config.clear();

    selectedContact = "";
    messageInput = "";
    editContactName = "";
    newUsername = "";
    newWifiSsid = "";
    newWifiPass = "";
    isTypingMsg = false;
    messageScroll = 0;

    awaitingAck = false;
    pendingOutgoingReady = false;
    pendingOutgoingContact = "";
    pendingOutgoingText = "";

    // Zamknuté zariadenie nemá čím pakety dešifrovať, takže ich zahodíme
    resetAssembly(assembly);
    rxQueueHead = rxQueueTail;
    clearPendingExchange();

    currentMenu = MENU_MAIN;
    menuIndex = 0;
}

/// @brief Vypýta si heslo a znovu načíta dáta. Blokuje, kým sa zariadenie neodomkne.
/// @return TRUE, ak sa zariadenie podarilo odomknúť, inak FALSE
bool unlockDevice() {
    if (Security::ensureDevicePrivateKey() == DeviceKeyProvisionState::Error) {
        return false;
    }

    M5Cardputer.Display.setTextScroll(true);
    M5Cardputer.Display.setTextFont(2);
    M5Cardputer.Display.setTextSize(0.75);
    M5Cardputer.Display.fillScreen(TFT_BLACK);
    M5Cardputer.Display.setCursor(0, 0);

    if (!loadConfig(config, "/m5pager/config.json")) return false;
    if (!loadContacts(contacts, "/m5pager/contacts.json")) return false;

    user = config["username"] | "User";

    // Čokoľvek, čo prišlo počas zámku, je už neaktuálne
    rxQueueHead = rxQueueTail;
    lastActivityMs = millis();

    M5Cardputer.Display.setTextScroll(false);
    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.fillScreen(uiBgColor());
    M5Cardputer.Display.setCursor(0, 0);
    M5Cardputer.Display.setTextColor(uiTextPrimaryColor(), uiBgColor());
    menus[currentMenu].draw();
    return true;
}

/// @brief Zamkne zariadenie a hneď vypýta heslo. Volá sa pri nečinnosti aj z nastavení.
void lockAndPrompt() {
    lockDevice();
    if (!unlockDevice()) {
        M5Cardputer.Display.setTextScroll(true);
        M5Cardputer.Display.setCursor(0, 0);
        M5Cardputer.Display.println("[-] FATAL: Unlock failed. Reboot device.");
        while (true) delay(1000);
    }
}

/// @brief Vyberie a spracuje všetky pakety odložené vo fronte. Volá sa z loop().
void drainRxQueue() {
    while (rxQueueHead != rxQueueTail) {
        RxQueueItem& item = rxQueue[rxQueueHead];
        processInboundPacket(item.mac, item.pkt);
        rxQueueHead = (rxQueueHead + 1) % RX_QUEUE_SIZE;
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
  // Fingerprint sa počíta z VEREJNÉHO kľúča (SHA-256), nikdy nie z privátneho
  M5Cardputer.Display.println("[*] Key ID: " + MessageCrypto::getOwnPublicKeyFingerprint());

  spi.begin(SD_CLK, SD_MISO, SD_MOSI, SD_CS);

  if (!SD.begin(SD_CS, spi)) {
	  M5Cardputer.Display.println("[-] SD Card Mount Failed");
	  return;
  }

  M5Cardputer.Display.println("[+] SD Card initialized.");

  // Config sa načíta ešte pred sieťou - sú v ňom prihlasovacie údaje siete
  if (!loadConfig(config, "/m5pager/config.json")) {
      M5Cardputer.Display.println("[-] FATAL: Failed to load config.");
      return;
  }
  M5Cardputer.Display.println("[+] Config loaded.");

  wifiSsid = config["wifi_ssid"] | DEFAULT_WIFI_SSID;
  wifiPass = config["wifi_pass"] | "";

  // Bez hesla by softAP() buď zlyhal, alebo vytvoril otvorenú sieť. Necháme si ho
  // zadať hneď pri prvom štarte, meniť sa dá neskôr v Settings.
  if (!isValidWifiPassword(wifiPass)) {
      M5Cardputer.Display.println("[*] Network password not set.");
      while (true) {
          if (!Security::capturePassword("Set WiFi password", wifiPass, WIFI_PASS_MAX_LEN)) {
              M5Cardputer.Display.println("[-] FATAL: No network password.");
              return;
          }
          if (isValidWifiPassword(wifiPass)) break;
          Security::showPasswordMessage("Min length is 8 chars", RED, 1200);
      }

      config["wifi_ssid"] = wifiSsid;
      config["wifi_pass"] = wifiPass;
      if (!saveConfig(config, "/m5pager/config.json")) {
          M5Cardputer.Display.println("[-] FATAL: Failed to save network config.");
          return;
      }

      // Výzva na heslo prekreslila obrazovku a prepla font - vrátime pôvodné nastavenie
      M5Cardputer.Display.setTextFont(2);
      M5Cardputer.Display.setTextSize(0.75);
      M5Cardputer.Display.setTextScroll(true);
      M5Cardputer.Display.setCursor(0, 0);
      M5Cardputer.Display.println("[+] Network password saved.");
  }

  M5Cardputer.Display.println("[*] SSID: " + wifiSsid);

  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();

  if (ScanAP(wifiSsid.c_str())) {
    M5Cardputer.Display.println("[+] Network exists. Connecting.");
    WiFi.begin(wifiSsid.c_str(), wifiPass.c_str());
    unsigned long connectStart = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - connectStart < 5000) {
      delay(100);
    }
    if (WiFi.status() != WL_CONNECTED) {
      M5Cardputer.Display.println("[!] Connect timeout. Creating AP.");
      if (!WiFi.softAP(wifiSsid.c_str(), wifiPass.c_str())) {
        M5Cardputer.Display.println("[-] FATAL: Could not start AP.");
        return;
      }
      isAP = true;
    }
  } else {
    M5Cardputer.Display.println("[+] Network not found. Creating.");
    if (!WiFi.softAP(wifiSsid.c_str(), wifiPass.c_str())) {
      M5Cardputer.Display.println("[-] FATAL: Could not start AP.");
      return;
    }
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

  M5Cardputer.Display.println("[+] Setup complete.");

  delay(1000);
  M5Cardputer.Display.setTextScroll(false);
  M5Cardputer.Display.fillScreen(uiBgColor());
  M5Cardputer.Display.setCursor(0, 0);
  M5Cardputer.Display.setTextSize(1);
  M5Cardputer.Display.setTextColor(uiTextPrimaryColor(), uiBgColor());

  //animácia privítania
  user = config["username"] | "User";
  String welcomeMsg = "Welcome back, " + user + "!\n";
  M5Cardputer.Display.setCursor(M5Cardputer.Display.width() / 2 - welcomeMsg.length() * 3, M5Cardputer.Display.height() / 2 - 4);
  for (size_t i = 0; i < welcomeMsg.length(); i++) {
      M5Cardputer.Display.print(welcomeMsg[i]);
      delay(100);
  }

  delay(2000);
  lastActivityMs = millis();
  menus[currentMenu].draw();
}

MenuState previousMenu = MENU_MAIN;

void loop() {
  M5Cardputer.update();

  // Prijaté pakety sa spracúvajú tu, nie v ESP-NOW callbacku - JSON dokument,
  // SD karta a displej sa tak používajú len z jedného tasku.
  drainRxQueue();

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
      lastActivityMs = millis();
      menus[currentMenu].handleInput(key);
      delay(150);
  }

  if (millis() - lastActivityMs > IDLE_LOCK_TIMEOUT_MS) {
      lockAndPrompt();
      return;
  }

  // Nedokončená výmena kľúčov nesmie držať efemérny kľúč v pamäti donekonečna
  if (pendingExchangeValid && millis() - pendingExchangeStartedMs > KEY_EXCHANGE_TIMEOUT_MS) {
      clearPendingExchange();
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
