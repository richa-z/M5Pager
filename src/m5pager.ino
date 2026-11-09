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
#include "security/peer_auth.h"
#include "security/group_store.h"

#include "enums/packet_types.h"
#include "transport/reliable_delivery.h"
#include "transport/mesh.h"
#include "transport/discovery.h"
#include <utility>

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
#include "menus/menu_network.h"
#include "menus/menu_verify_peer.h"
#include "menus/menu_groups.h"



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
    "Settings",
    "Network",
    "Groups"
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
  {drawChangeSsidPass, handleChangeSsidPassInput},
  {drawNetworkMenu, handleNetworkInput},
  {drawNearbyMenu, handleNearbyInput},
  {drawPeerVerification, handlePeerVerification},
  {drawGroupsMenu, handleGroupsInput},
  {drawGroupCreate, handleGroupCreate},
  {drawGroupChat, handleGroupChat},
  {drawGroupManage, handleGroupManage},
  {drawGroupAdd, handleGroupAdd},
  {drawGroupActions, handleGroupActions},
  {drawGroupDelivery, handleGroupDelivery},
  {drawGroupRename, handleGroupRename},
  {drawGroupInfo, handleGroupInfo},
  {drawGroupMember, handleGroupMember}
};

constexpr const char* DEFAULT_WIFI_SSID = "PAGER_COM";

String wifiSsid = "";
String wifiPass = "";

uint8_t selectedMac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

String selectedContact = "";

bool isAP = false;

MessageStruct msgIncoming;
MessageStruct msgOutgoing;

IncomingAssembly assemblies[Delivery::REASSEMBLY_SLOTS]{};
Delivery::Pending pendingDelivery;

SPIClass spi = SPIClass(FSPI);
DynamicJsonDocument contacts(8192);
DynamicJsonDocument config(1024);
Groups::Document groups(Groups::STORE_CAPACITY);
String selectedGroup, groupInput, groupConfirm, groupActionMac;
uint32_t groupActionEpoch = 0;
uint32_t groupComposeEpoch = 0;
bool groupReviewRequired = false;
MenuState verificationReturnMenu = MENU_MESSAGE;
bool isTypingGroup = false;
int groupScroll = 0;
MessageCrypto::ContentKind pendingOutgoingKind = MessageCrypto::ContentKind::Text;

char inputBuffer[MSG_CHUNK_SIZE];
int bytesRead;
bool messageSentFlag = false;

String user = "User"; //username, nacitane/menene z configu, default "User"
String editContactName = "";
String messageInput = "";
bool isTypingMsg = false;

bool awaitingAck = false;
uint16_t awaitingMsgId = 0;
uint8_t awaitingMac[6] = {0};
unsigned long sendTimestamp = 0;
bool pendingOutgoingReady = false;
String pendingOutgoingContact = "";
String pendingOutgoingText = "";
int messageScroll = 0;
bool discoveryEnabled = false;
bool meshEnabled = false;
Discovery::State nearby;
Mesh::State meshState;
unsigned long nextAliveBroadcast = 0;

constexpr unsigned long IDLE_LOCK_TIMEOUT_MS = 5UL * 60UL * 1000UL;
unsigned long lastActivityMs = 0;

PeerAuth::Pending pendingExchange;
PeerAuth::Budget inboundBudget;
PeerAuth::Budget handshakeBudget;
String pairingContact;
unsigned long pairingStartedMs = 0;
String verificationSnapshot;
bool verificationConfirm = false;

void clearPendingExchange() {
    pendingExchange.clear();
}

bool pairingAllowed(const String& contact) {
    return pairingContact == contact && pairingContact.length() != 0 &&
           millis() - pairingStartedMs < PeerAuth::PAIRING_WINDOW_MS;
}

bool armPeerPairing(const String& contact) {
    if (!contacts.containsKey(contact) || pendingExchange.active || awaitingAck) return false;
    pairingContact = contact;
    pairingStartedMs = millis();
    return true;
}

/*

NETWORKING

*/

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

bool selectContactPeer(const char* contactMac);

bool sendBroadcastFrame(const uint8_t* wire, size_t length) {
    return addOrRefreshPeer(Mesh::BROADCAST) && esp_now_send(Mesh::BROADCAST, wire, length) == ESP_OK;
}

bool sendApplicationPacket(const uint8_t* destination, const uint8_t* wire, size_t length) {
    if (!meshEnabled) return esp_now_send(destination, wire, length) == ESP_OK;
    Mesh::Frame frame;
    if (!deserializePacket(wire, static_cast<int>(length), frame.packet)) return false;
    memcpy(frame.origin, frame.packet.from, 6);
    memcpy(frame.destination, destination, 6);
    esp_fill_random(frame.nonce, sizeof(frame.nonce));
    uint8_t envelope[Mesh::MAX_WIRE_LEN];
    const size_t envelopeLength = Mesh::encode(frame, envelope);
    return envelopeLength != 0 && sendBroadcastFrame(envelope, envelopeLength);
}

void loadNetworkPreferences() {
    discoveryEnabled = config["discovery_enabled"] | false;
    meshEnabled = config["mesh_enabled"] | false;
    nearby = Discovery::State{};
    meshState = Mesh::State{};
    nextAliveBroadcast = millis();
}

bool setNetworkPreference(bool discovery, bool enabled) {
    DynamicJsonDocument transaction(config.capacity());
    if (!transaction.set(config)) return false;
    transaction[discovery ? "discovery_enabled" : "mesh_enabled"] = enabled;
    if (transaction.overflowed() || !saveConfig(transaction, "/m5pager/config.json")) return false;
    config = std::move(transaction);
    if (discovery) {
        discoveryEnabled = enabled;
        nearby = Discovery::State{};
        nextAliveBroadcast = millis();
    } else {
        meshEnabled = enabled;
        meshState = Mesh::State{};
    }
    return true;
}

bool enrollNearby(size_t selected) {
    const auto* peer = nearby.at(selected);
    if (peer == nullptr || millis() - peer->lastSeen > Discovery::EXPIRY_MS) return false;
    const String address = macToString(peer->mac);
    String contactKey = findContactKeyByMac(contacts, address);
    if (contactKey.length() == 0) {
        DynamicJsonDocument transaction(contacts.capacity());
        if (!transaction.set(contacts)) return false;
        JsonObject contact = transaction.createNestedObject(address);
        contact["username"] = peer->name;
        contact.createNestedArray("messages");
        contact.createNestedObject("keys")["status"] = "none";
        if (transaction.overflowed() || !saveContacts(transaction, "/m5pager/contacts.json")) return false;
        contacts = std::move(transaction);
        contactKey = address;
    }
    if (!selectContactPeer(contactKey.c_str())) return false;
    selectedContact = contactKey;
    messageScroll = 0;
    return true;
}

void tickDiscovery() {
    if (!discoveryEnabled || !Security::hasDevicePrivateKey()) return;
    const size_t before = nearby.count();
    nearby.expire(millis());
    if (currentMenu == MENU_NEARBY && before != nearby.count()) drawNearbyMenu();
    if (static_cast<int32_t>(millis() - nextAliveBroadcast) < 0) return;
    nextAliveBroadcast = millis() + Discovery::INTERVAL_MS + (esp_random() % 1000);
    MessageStruct beacon{};
    beacon.type = P_BOARD_ONLINE;
    esp_read_mac(beacon.from, ESP_MAC_WIFI_STA);
    beacon.split_size = 1;
    String name = user.substring(0, Discovery::NAME_LEN);
    if (name.length() == 0) name = "User";
    for (size_t index = 0; index < name.length(); index++) if (name[index] < 32 || name[index] > 126) name[index] = '_';
    const String payload = String(Discovery::PREFIX) + name;
    beacon.data_len = payload.length();
    memcpy(beacon.msg, payload.c_str(), beacon.data_len);
    uint8_t wire[PACKET_MAX_LEN];
    const size_t length = serializePacket(beacon, wire);
    if (length != 0) sendBroadcastFrame(wire, length);
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

    return sendApplicationPacket(targetMac, wire, wireLen);
}

/// @brief Odošle ACK správu cez ESP-NOW.
/// @param targetMac MAC adresa cieľa
/// @param messageId ID správy, ktorú ACKuje
void sendMessageAck(const uint8_t* targetMac, uint16_t messageId, const String& receipt) {
    if (targetMac == nullptr) return;
    addOrRefreshPeer(targetMac);

    MessageStruct ack{};
    ack.type = P_MSG_ACK;
    esp_read_mac(ack.from, ESP_MAC_WIFI_STA);
    ack.message_id = messageId;
    ack.split_size = 1;
    ack.split_index = 0;
    if (receipt.length() != MessageCrypto::DELIVERY_RECEIPT_LEN * 2) return;
    ack.data_len = receipt.length();
    memcpy(ack.msg, receipt.c_str(), ack.data_len);

    uint8_t wire[PACKET_MAX_LEN];
    size_t wireLen = serializePacket(ack, wire);
    if (wireLen == 0) return;

    sendApplicationPacket(targetMac, wire, wireLen);
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
bool sendPeerBytes(PacketType type, const uint8_t* destination, uint16_t identifier,
                   const uint8_t* payload, size_t length) {
    if (length > MSG_CHUNK_SIZE || !addOrRefreshPeer(destination)) return false;
    MessageStruct packet{};
    packet.type = type;
    esp_read_mac(packet.from, ESP_MAC_WIFI_STA);
    packet.message_id = identifier;
    packet.split_size = 1;
    packet.data_len = static_cast<uint8_t>(length);
    memcpy(packet.msg, payload, length);
    uint8_t wire[PACKET_MAX_LEN];
    const size_t encoded = serializePacket(packet, wire);
    return encoded != 0 && sendApplicationPacket(destination, wire, encoded);
}

bool commitPeerExchange(const PeerAuth::Frame& peerFrame, bool initiator) {
    DynamicJsonDocument transaction(contacts.capacity());
    if (!transaction.set(contacts) ||
        !MessageCrypto::completeHandshake(transaction, pendingExchange.contact,
            MessageCrypto::bytesToHex(peerFrame.publicKey(), 32),
            MessageCrypto::bytesToHex(peerFrame.ephemeral(), 32),
            pendingExchange.ephemeralPrivate, initiator)) return false;
    transaction[pendingExchange.contact].remove("receipts");
    transaction[pendingExchange.contact]["keys"]["last_handshake_nonce"] =
        MessageCrypto::bytesToHex(pendingExchange.offer.bytes + 67, 16);
    if (transaction.overflowed() || !saveContacts(transaction, "/m5pager/contacts.json")) return false;
    contacts = std::move(transaction);
    Security::secureZero(pendingExchange.ephemeralPrivate, sizeof(pendingExchange.ephemeralPrivate));
    pendingExchange.completed = true;
    pendingExchange.attempts = 0;
    pendingExchange.lastSent = millis();
    pairingContact = "";
    for (auto& assembly : assemblies) {
        if (memcmp(assembly.from, pendingExchange.peer, 6) == 0) resetAssembly(assembly);
    }
    return true;
}

bool sendPeerConfirmation() {
    pendingExchange.lastSent = millis();
    pendingExchange.attempts++;
    uint8_t own[6];
    uint8_t tag[32]{};
    esp_read_mac(own, ESP_MAC_WIFI_STA);
    const bool valid = PeerAuth::computeTag(pendingExchange.reply, pendingExchange.reply.publicKey(),
        own, pendingExchange.peer, pendingExchange.identifier, P_EXCH_OK, &pendingExchange.offer, tag) &&
        sendPeerBytes(P_EXCH_OK, pendingExchange.peer, pendingExchange.identifier, tag, sizeof(tag));
    Security::secureZero(tag, sizeof(tag));
    return valid;
}

bool requestKeyExchange(const char* contactMac) {
    if (contactMac == nullptr || pendingExchange.active || awaitingAck || groupTransferBusy()) return false;
    uint8_t peer[6];
    if (!parseMacAddress(contactMac, peer) || !Mesh::unicast(peer)) return false;
    const String contact = findContactKeyByMac(contacts, String(contactMac));
    if (contact.length() == 0) return false;
    uint8_t own[6];
    esp_read_mac(own, ESP_MAC_WIFI_STA);
    if (memcmp(own, peer, 6) == 0) return false;
    clearPendingExchange();
    pendingExchange.contact = contact;
    pendingExchange.identifier = nextControlMessageId();
    pendingExchange.initiator = true;
    pendingExchange.started = millis();
    pendingExchange.lastSent = millis();
    pendingExchange.attempts = 1;
    memcpy(pendingExchange.peer, peer, 6);
    bool valid = PeerAuth::create(pendingExchange.offer, pendingExchange.ephemeralPrivate);
    const String expected = MessageCrypto::expectedPeerIdentity(contacts, contact);
    if (valid && expected.length() != 0) {
        uint8_t peerPublic[32]{};
        valid = MessageCrypto::hexToBytes(expected, peerPublic, sizeof(peerPublic)) &&
            PeerAuth::sign(pendingExchange.offer, peerPublic, own, peer, pendingExchange.identifier, P_INIT_EXCH);
    }
    if (!valid) { clearPendingExchange(); return false; }
    pendingExchange.active = true;
    if (!sendPeerBytes(P_INIT_EXCH, peer, pendingExchange.identifier, pendingExchange.offer.bytes, PeerAuth::FRAME_LEN)) {
        clearPendingExchange();
        return false;
    }
    return true;
}

bool verifyPeerIdentity(const String& contact, const String& displayedFingerprint) {
    if (!MessageCrypto::hasReadySession(contacts, contact) ||
        (pendingExchange.active && !pendingExchange.completed) ||
        (contacts[contact]["keys"]["handshake_version"] | 0) != 5 ||
        displayedFingerprint.length() != MessageCrypto::FINGERPRINT_BYTES * 2 ||
        MessageCrypto::getSessionFingerprint(contacts, contact) != displayedFingerprint) return false;
    uint8_t own[32]{};
    uint8_t peer[32]{};
    const String peerHex = contacts[contact]["keys"]["x25519_peer_pub"] | "";
    if (!MessageCrypto::getOwnPublicKey(own) || !MessageCrypto::hexToBytes(peerHex, peer, sizeof(peer)) ||
        MessageCrypto::pairFingerprint(own, peer) != displayedFingerprint ||
        !MessageCrypto::acceptsPeerIdentity(contacts, contact, peerHex)) return false;
    DynamicJsonDocument transaction(contacts.capacity());
    if (!transaction.set(contacts)) return false;
    transaction[contact]["keys"]["verified_peer_pub"] = MessageCrypto::bytesToHex(peer, sizeof(peer));
    transaction[contact]["keys"]["verified_own_pub"] = MessageCrypto::bytesToHex(own, sizeof(own));
    if (transaction.overflowed() || !saveContacts(transaction, "/m5pager/contacts.json")) return false;
    contacts = std::move(transaction);
    return true;
}

void handleKeyExchangePacket(const uint8_t* source, const MessageStruct& packet) {
    if (pendingExchange.active && millis() - pendingExchange.started >= PeerAuth::TIMEOUT_MS) clearPendingExchange();
    if (awaitingAck) return;
    const String contact = findContactKeyByMac(contacts, macToString(source));
    if (contact.length() == 0 || packet.split_size != 1 || packet.split_index != 0 ||
        (packet.message_id & MESSAGE_ID_CONTROL_FLAG) == 0 || !handshakeBudget.allow(millis(), 2)) return;
    uint8_t own[6];
    esp_read_mac(own, ESP_MAC_WIFI_STA);
    if (memcmp(source, own, 6) == 0) return;
    const bool matchesPending = pendingExchange.active && pendingExchange.contact == contact &&
        pendingExchange.identifier == packet.message_id && memcmp(pendingExchange.peer, source, 6) == 0;

    if (packet.type == P_EXCH_OK) {
        if (!matchesPending || pendingExchange.initiator || pendingExchange.completed || packet.data_len != 32) return;
        uint8_t expected[32]{};
        const bool valid = PeerAuth::computeTag(pendingExchange.reply, pendingExchange.offer.publicKey(),
            source, own, packet.message_id, P_EXCH_OK, &pendingExchange.offer, expected) &&
            MessageCrypto::equalBytes(expected, reinterpret_cast<const uint8_t*>(packet.msg), sizeof(expected));
        Security::secureZero(expected, sizeof(expected));
        if (valid) commitPeerExchange(pendingExchange.offer, false);
    } else {
        PeerAuth::Frame frame;
        if (!PeerAuth::parse(packet, frame) ||
            !MessageCrypto::acceptsPeerIdentity(contacts, contact, MessageCrypto::bytesToHex(frame.publicKey(), 32))) return;
        if (packet.type == P_ACK_EXCH) {
            if (!matchesPending || !pendingExchange.initiator) return;
            if (pendingExchange.completed) {
                if (MessageCrypto::equalBytes(frame.bytes, pendingExchange.reply.bytes, PeerAuth::FRAME_LEN)) sendPeerConfirmation();
                return;
            }
            if (!PeerAuth::verify(frame, source, own, packet.message_id, P_ACK_EXCH, &pendingExchange.offer)) return;
            pendingExchange.reply = frame;
            if (commitPeerExchange(frame, true)) sendPeerConfirmation();
        } else if (packet.type == P_INIT_EXCH) {
            if (pendingExchange.active) {
                if (matchesPending && !pendingExchange.initiator &&
                    MessageCrypto::equalBytes(frame.bytes, pendingExchange.offer.bytes, PeerAuth::FRAME_LEN)) {
                    sendPeerBytes(P_ACK_EXCH, source, packet.message_id, pendingExchange.reply.bytes, PeerAuth::FRAME_LEN);
                }
                return;
            }
            const bool verified = MessageCrypto::hasVerifiedSession(contacts, contact);
            const String knownIdentity = MessageCrypto::expectedPeerIdentity(contacts, contact);
            if (!verified && !pairingAllowed(contact)) return;
            if (knownIdentity.length() != 0 || frame.bytes[2] == PeerAuth::AUTHENTICATED) {
                if (!PeerAuth::verify(frame, source, own, packet.message_id, P_INIT_EXCH)) return;
            } else if (!MessageCrypto::isAllZero(frame.tag(), 32)) return;
            const String previousNonce = contacts[contact]["keys"]["last_handshake_nonce"] | "";
            if (previousNonce == MessageCrypto::bytesToHex(frame.bytes + 67, 16)) return;
            clearPendingExchange();
            pendingExchange.contact = contact;
            pendingExchange.identifier = packet.message_id;
            pendingExchange.started = millis();
            pendingExchange.lastSent = millis();
            pendingExchange.attempts = 1;
            pendingExchange.offer = frame;
            memcpy(pendingExchange.peer, source, 6);
            if (!PeerAuth::create(pendingExchange.reply, pendingExchange.ephemeralPrivate) ||
                !PeerAuth::sign(pendingExchange.reply, frame.publicKey(), own, source,
                                packet.message_id, P_ACK_EXCH, &pendingExchange.offer)) {
                clearPendingExchange();
                return;
            }
            pendingExchange.active = true;
            if (!sendPeerBytes(P_ACK_EXCH, source, packet.message_id, pendingExchange.reply.bytes, PeerAuth::FRAME_LEN)) {
                clearPendingExchange();
            }
        }
    }
    if (selectedContact.equalsIgnoreCase(contact)) {
        if (currentMenu == MENU_MESSAGE) drawMessageMenu();
        if (currentMenu == MENU_VERIFY_PEER) drawPeerVerification();
    }
}
uint16_t beginApplicationDelivery(const uint8_t* destination, const String& contact, const String& text, MessageCrypto::ContentKind kind) {
    static uint16_t messageCounter = 0;
    if (awaitingAck || destination == nullptr || text.length() == 0 ||
        text.length() > MessageCrypto::MAX_APPLICATION_PAYLOAD ||
        (kind == MessageCrypto::ContentKind::Text && text.length() > MAX_MESSAGE_TEXT_LEN) ||
        (pendingExchange.active && !pendingExchange.completed) ||
        !MessageCrypto::hasVerifiedSession(contacts, contact) || !addOrRefreshPeer(destination)) return 0;
    uint8_t expected[6];
    if (!parseMacAddress(contact.c_str(), expected) || memcmp(expected, destination, 6) != 0) return 0;
    DynamicJsonDocument transaction(contacts.capacity());
    if (!transaction.set(contacts)) return 0;
    Delivery::Pending prepared;
    uint16_t messageId = (messageCounter + 1) & MESSAGE_ID_VALUE_MASK;
    if (messageId == 0) messageId = 1;
    if (!MessageCrypto::encryptPayload(transaction, contact, text, prepared.payload, prepared.receipt, messageId, kind) ||
        prepared.payload.length() == 0 || prepared.payload.length() > MAX_MESSAGE_PARTS * MSG_CHUNK_SIZE ||
        prepared.receipt.length() != MessageCrypto::DELIVERY_RECEIPT_LEN * 2 ||
        transaction.overflowed() || !saveContacts(transaction, "/m5pager/contacts.json")) return 0;
    contacts = std::move(transaction);
    messageCounter = messageId;
    awaitingMsgId = messageId;
    memcpy(awaitingMac, destination, 6);
    pendingOutgoingReady = true;
    pendingOutgoingContact = contact;
    pendingOutgoingText = text;
    pendingOutgoingKind = kind;
    pendingDelivery = std::move(prepared);
    awaitingAck = true;
    transmitPendingDelivery();
    return messageId;
}

bool submitRadioPacket(const uint8_t* destination, const uint8_t* wire, size_t length) {
    return sendApplicationPacket(destination, wire, length);
}

bool transmitPendingDelivery() {
    uint8_t source[6];
    esp_read_mac(source, ESP_MAC_WIFI_STA);
    pendingDelivery.attempts++;
    sendTimestamp = millis();
    return Delivery::transmit(awaitingMac, source, awaitingMsgId, pendingDelivery.payload, submitRadioPacket);
}

#include "groups_runtime.h"

void onDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
    Serial.print("[+] Last packet send status: ");
    Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}

/// @brief Handler pre prijaté ESP-NOW pakety. Spracuje prijaté pakety, zloží ich z častí, dešifruje a uloží do histórie zpráv. ACK a refresh
/// @param mac_addr MAC adresa odosielateľa
/// @param data Prijaté dáta
/// @param data_len Dĺžka prijatých dát
void onDataRecv(const uint8_t *mac_addr, const uint8_t *data, int data_len) {
    if (mac_addr == nullptr || data == nullptr || data_len < PACKET_HEADER_LEN || data_len > MAX_RADIO_FRAME_LEN) return;

    uint8_t next = (rxQueueTail + 1) % RX_QUEUE_SIZE;
    if (next == rxQueueHead) return;

    RxQueueItem& item = rxQueue[rxQueueTail];
    memcpy(item.mac, mac_addr, 6);
    item.length = static_cast<uint16_t>(data_len);
    memcpy(item.data, data, item.length);

    rxQueueTail = next;
}

/// @brief Spracuje jeden prijatý paket. Volá sa výhradne z loop(), nikdy z callbacku.
/// @param mac_addr MAC adresa odosielateľa
/// @param pkt Paket (už overený deserializePacket)
void processInboundPacket(const uint8_t *mac_addr, const MessageStruct& pkt) {
    if (memcmp(mac_addr, pkt.from, 6) != 0) return;
    if (pkt.type == P_BOARD_ONLINE) {
        if (discoveryEnabled && nearby.observe(mac_addr, pkt, millis()) && currentMenu == MENU_NEARBY) drawNearbyMenu();
        return;
    }
    if (pkt.type == P_MSG_ACK) {
        const String contact = findContactKeyByMac(contacts, macToString(mac_addr));
        if (!MessageCrypto::hasVerifiedSession(contacts, contact)) return;
        if (awaitingAck && memcmp(mac_addr, awaitingMac, 6) == 0 && pkt.message_id == awaitingMsgId &&
            pkt.split_size == 1 && pkt.split_index == 0 &&
            pkt.data_len == MessageCrypto::DELIVERY_RECEIPT_LEN * 2 &&
            packetPayloadToString(pkt) == pendingDelivery.receipt) {
            if (pendingOutgoingReady) {
                String contactKey = pendingOutgoingContact;
                if (pendingOutgoingKind == MessageCrypto::ContentKind::Text) {
                    DynamicJsonDocument transaction(contacts.capacity());
                    if (!transaction.set(contacts) ||
                        !appendMessage(transaction, contactKey, "out", pendingOutgoingText.c_str())) return;
                    contacts = std::move(transaction);
                } else if (!finishGroupTransfer(true)) return;
                pendingOutgoingKind = MessageCrypto::ContentKind::Text;
                awaitingAck = false;
                pendingDelivery = Delivery::Pending{};

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

    bool isLastPart = (pkt.split_index + 1 == pkt.split_size);
    if (!isLastPart && pkt.data_len != MSG_CHUNK_SIZE) return;
    if (isLastPart && pkt.data_len == 0) return;

    const String senderMac = macToString(mac_addr);
    const String contactKey = findContactKeyByMac(contacts, senderMac);
    if (contactKey.length() == 0 || !MessageCrypto::hasVerifiedSession(contacts, contactKey)) return;
    unsigned long now = millis();
    IncomingAssembly* selected = Delivery::selectAssembly(assemblies, mac_addr, pkt, now);
    if (selected == nullptr) return;
    IncomingAssembly& assembly = *selected;
    assembly.lastPacketMs = now;

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

    size_t totalLen = 0;
    for (uint8_t i = 0; i < assembly.expected_parts; i++) {
        totalLen += assembly.partLen[i];
    }

    String payload;
    payload.reserve(totalLen);
    for (size_t i = 0; i < totalLen; i++) {
        payload += assembly.data[i];
    }
    resetAssembly(assembly);

    uint8_t digest[32];
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                   reinterpret_cast<const uint8_t*>(payload.c_str()), payload.length(), digest) != 0) return;
    const String payloadHash = MessageCrypto::bytesToHex(digest, sizeof(digest));
    JsonArray receipts = contacts[contactKey]["receipts"].as<JsonArray>();
    for (JsonObject accepted : receipts) {
        if (accepted["id"].as<uint16_t>() == pkt.message_id && accepted["hash"].as<String>() == payloadHash) {
            sendMessageAck(mac_addr, pkt.message_id, accepted["receipt"].as<String>());
            return;
        }
    }

    DynamicJsonDocument transaction(contacts.capacity());
    if (!transaction.set(contacts)) return;
    String plaintext;
    String receipt;
    MessageCrypto::ContentKind kind;
    if (!MessageCrypto::decryptPayload(transaction, contactKey, payload, plaintext, receipt, pkt.message_id, &kind)) return;
    if (kind == MessageCrypto::ContentKind::Text && plaintext.length() > MAX_MESSAGE_TEXT_LEN) return;
    JsonArray savedReceipts = transaction[contactKey]["receipts"].as<JsonArray>();
    if (savedReceipts.isNull()) savedReceipts = transaction[contactKey].createNestedArray("receipts");
    while (savedReceipts.size() >= Delivery::RECEIPT_CACHE_SIZE) savedReceipts.remove(0);
    JsonObject accepted = savedReceipts.createNestedObject();
    accepted["id"] = pkt.message_id;
    accepted["hash"] = payloadHash;
    accepted["receipt"] = receipt;
    if (transaction.overflowed()) return;
    if (kind == MessageCrypto::ContentKind::Text) {
        if (!appendMessage(transaction, contactKey, "in", plaintext.c_str())) return;
    } else {
        String affected;
        const String source = macToString(mac_addr);
        const bool applied = kind == MessageCrypto::ContentKind::GroupControl
            ? Groups::applyControl(groups, contacts, source, plaintext, affected)
            : Groups::applyMessage(groups, contacts, source, plaintext, affected);
        if (!applied) return;
        refreshGroupsUi();
        if (!saveContacts(transaction, "/m5pager/contacts.json")) return;
    }
    contacts = std::move(transaction);
    sendMessageAck(mac_addr, pkt.message_id, receipt);

    if (currentMenu == MENU_MESSAGE && senderMac.equalsIgnoreCase(selectedContact)) {
        drawMessageMenu();
    }
}

/*

ZAMYKANIE

*/

/// @brief Zamkne zariadenie - vymaže kľúče aj všetky dešifrované dáta z pamäte.
void lockDevice() {
    while (groupTransferBusy()) if (!finishGroupTransfer(false)) break;
    clearGroupTransient();
    groups.clear();
    pendingOutgoingKind = MessageCrypto::ContentKind::Text;
    Security::lockRuntimeKeys();
    nearby = Discovery::State{};
    meshState = Mesh::State{};
    discoveryEnabled = false;
    meshEnabled = false;

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

    for (auto& slot : assemblies) resetAssembly(slot);
    pendingDelivery = Delivery::Pending{};
    rxQueueHead = rxQueueTail;
    clearPendingExchange();
    pairingContact = "";
    pairingStartedMs = 0;
    verificationSnapshot = "";
    verificationConfirm = false;
    verificationReturnMenu = MENU_MESSAGE;

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
    if (!Groups::load(groups)) { groups.clear(); return false; }

    user = config["username"] | "User";
    loadNetworkPreferences();

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
void processRadioFrame(const uint8_t* previousHop, const uint8_t* wire, size_t length) {
    if (!Security::hasDevicePrivateKey() || !Mesh::unicast(previousHop)) return;
    if (!inboundBudget.allow(millis(), 48)) { meshState.limited++; return; }
    if (!Mesh::matches(wire, length)) {
        MessageStruct packet{};
        if (deserializePacket(wire, static_cast<int>(length), packet)) processInboundPacket(previousHop, packet);
        return;
    }
    if (!meshEnabled) return;
    if (!meshState.allow(millis())) { meshState.limited++; return; }
    Mesh::Frame frame;
    if (!Mesh::unicast(previousHop) || !Mesh::decode(wire, length, frame)) { meshState.rejected++; return; }
    uint8_t own[6];
    esp_read_mac(own, ESP_MAC_WIFI_STA);
    if (memcmp(frame.origin, own, 6) == 0) return;
    const auto admission = meshState.remember(wire, length, millis());
    if (admission == Mesh::Admission::Duplicate) { meshState.duplicates++; return; }
    if (admission != Mesh::Admission::Fresh) { meshState.limited++; return; }
    if (memcmp(frame.destination, own, 6) == 0) {
        meshState.delivered++;
        processInboundPacket(frame.origin, frame.packet);
        return;
    }
    if (frame.remaining <= 1) { meshState.expired++; return; }
    frame.remaining--;
    uint8_t forwarded[Mesh::MAX_WIRE_LEN];
    const size_t forwardedLength = Mesh::encode(frame, forwarded);
    if (forwardedLength != 0 && sendBroadcastFrame(forwarded, forwardedLength)) meshState.forwarded++;
}

void drainRxQueue() {
    for (uint8_t processed = 0; processed < 2 && rxQueueHead != rxQueueTail; processed++) {
        RxQueueItem& item = rxQueue[rxQueueHead];
        processRadioFrame(item.mac, item.data, item.length);
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
  M5Cardputer.Display.println("[*] Key ID: " + MessageCrypto::getOwnPublicKeyFingerprint());

  spi.begin(SD_CLK, SD_MISO, SD_MOSI, SD_CS);

  if (!SD.begin(SD_CS, spi)) {
	  M5Cardputer.Display.println("[-] SD Card Mount Failed");
	  return;
  }

  M5Cardputer.Display.println("[+] SD Card initialized.");

  if (!loadConfig(config, "/m5pager/config.json")) {
      M5Cardputer.Display.println("[-] FATAL: Failed to load config.");
      return;
  }
  M5Cardputer.Display.println("[+] Config loaded.");
  loadNetworkPreferences();

  wifiSsid = config["wifi_ssid"] | DEFAULT_WIFI_SSID;
  wifiPass = config["wifi_pass"] | "";

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

  if (!Groups::load(groups)) {
      groups.clear();
      lockDevice();
      M5Cardputer.Display.println("[-] Group storage invalid. Reboot to recover.");
      while (true) delay(1000);
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
  drainRxQueue();
  tickGroupTransfer();
  tickDiscovery();

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

  if (pendingExchange.active && millis() - pendingExchange.started > PeerAuth::TIMEOUT_MS) {
      clearPendingExchange();
  }
  if (pairingContact.length() != 0 && millis() - pairingStartedMs >= PeerAuth::PAIRING_WINDOW_MS) {
      pairingContact = "";
      if (currentMenu == MENU_VERIFY_PEER) drawPeerVerification();
  }
  if (pendingExchange.active && pendingExchange.attempts < 4 &&
      millis() - pendingExchange.lastSent >= 2000) {
      if (pendingExchange.initiator && pendingExchange.completed) {
          sendPeerConfirmation();
      } else if (!pendingExchange.completed) {
          pendingExchange.lastSent = millis();
          pendingExchange.attempts++;
          const auto& frame = pendingExchange.initiator ? pendingExchange.offer : pendingExchange.reply;
          sendPeerBytes(pendingExchange.initiator ? P_INIT_EXCH : P_ACK_EXCH, pendingExchange.peer,
                        pendingExchange.identifier, frame.bytes, PeerAuth::FRAME_LEN);
      }
  }


    //Ak nie je ACKed
    if (awaitingAck && millis() - sendTimestamp > Delivery::RETRY_INTERVAL_MS) {
        if (pendingDelivery.attempts < Delivery::MAX_ATTEMPTS) {
            transmitPendingDelivery();
            return;
        }
        if (pendingOutgoingKind != MessageCrypto::ContentKind::Text) {
            if (!finishGroupTransfer(false)) groupBatch = GroupBatch{};
        }
        pendingOutgoingKind = MessageCrypto::ContentKind::Text;
        pendingDelivery = Delivery::Pending{};
        awaitingAck = false;
        pendingOutgoingReady = false;
        pendingOutgoingContact = "";
        pendingOutgoingText = "";
        showErrorToast("Delivery unconfirmed");
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
