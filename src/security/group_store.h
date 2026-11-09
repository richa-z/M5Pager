#pragma once

#include <utility>
#include <cstddef>
#include <cstdlib>
#include "json_management.h"
#include "security/message_crypto.h"
#include "util/network_util.h"

namespace Groups {

static_assert(ARDUINOJSON_VERSION_MAJOR == 7, "Group storage requires ArduinoJson 7");

constexpr size_t MAX_GROUPS = 4;
constexpr size_t MAX_MEMBERS = 4;
constexpr size_t MAX_TEXT = 120;
constexpr size_t MAX_HISTORY = 12;
constexpr size_t MAX_SEEN = 24;
constexpr size_t MAX_REVOCATIONS = 8;
constexpr size_t MAX_MEMBER_EVENTS = 12;
constexpr uint8_t FORMAT_VERSION = 2;
constexpr size_t STORE_CAPACITY = 65536;
constexpr char STORE_PATH[] = "/m5pager/groups.json";
constexpr size_t JSON_ALLOCATION_BUDGET = 128 * 1024;

inline size_t& allocatedBytes() {
    static size_t allocated = 0;
    return allocated;
}

struct alignas(std::max_align_t) AllocationHeader { size_t bytes; };

class JsonAllocator {
public:
    void* allocate(size_t bytes) {
        if (bytes == 0 || bytes > JSON_ALLOCATION_BUDGET - sizeof(AllocationHeader) ||
            allocatedBytes() > JSON_ALLOCATION_BUDGET - bytes - sizeof(AllocationHeader)) return nullptr;
        auto* allocation = static_cast<AllocationHeader*>(malloc(sizeof(AllocationHeader) + bytes));
        if (allocation == nullptr) return nullptr;
        allocation->bytes = bytes;
        allocatedBytes() += sizeof(AllocationHeader) + bytes;
        return allocation + 1;
    }

    void deallocate(void* pointer) {
        if (pointer == nullptr) return;
        auto* allocation = static_cast<AllocationHeader*>(pointer) - 1;
        allocatedBytes() -= sizeof(AllocationHeader) + allocation->bytes;
        free(allocation);
    }

    void* reallocate(void* pointer, size_t bytes) {
        if (pointer == nullptr) return allocate(bytes);
        if (bytes == 0) { deallocate(pointer); return nullptr; }
        auto* previous = static_cast<AllocationHeader*>(pointer) - 1;
        const size_t retained = allocatedBytes() - previous->bytes;
        if (bytes > JSON_ALLOCATION_BUDGET || retained > JSON_ALLOCATION_BUDGET - bytes) return nullptr;
        const size_t previousBytes = previous->bytes;
        auto* resized = static_cast<AllocationHeader*>(realloc(previous, sizeof(AllocationHeader) + bytes));
        if (resized == nullptr) return nullptr;
        resized->bytes = bytes;
        allocatedBytes() = allocatedBytes() - previousBytes + bytes;
        return resized + 1;
    }
};

using Document = BasicJsonDocument<JsonAllocator>;

inline String macString(const uint8_t address[6]) {
    char encoded[18];
    snprintf(encoded, sizeof(encoded), "%02X:%02X:%02X:%02X:%02X:%02X", address[0], address[1], address[2], address[3], address[4], address[5]);
    return String(encoded);
}

inline String ownMac() {
    uint8_t own[6];
    esp_read_mac(own, ESP_MAC_WIFI_STA);
    return macString(own);
}

inline String ownPublic() {
    String result;
    if (!MessageCrypto::getOwnPublicKeyHex(result)) return "";
    return result;
}

inline bool canonicalMac(const String& address) {
    uint8_t parsed[6]{};
    if (!parseMacAddress(address.c_str(), parsed) || (parsed[0] & 1) != 0 ||
        MessageCrypto::isAllZero(parsed, sizeof(parsed))) return false;
    return macString(parsed) == address;
}

inline bool validHex(const String& value, size_t bytes) {
    uint8_t decoded[32]{};
    return bytes <= sizeof(decoded) && MessageCrypto::hexToBytes(value, decoded, bytes) &&
           !MessageCrypto::isAllZero(decoded, bytes) && MessageCrypto::bytesToHex(decoded, bytes) == value;
}

inline String randomHex(size_t bytes) {
    if (bytes > 32) return "";
    uint8_t random[32]{};
    esp_fill_random(random, bytes);
    String encoded = MessageCrypto::isAllZero(random, bytes) ? String("") : MessageCrypto::bytesToHex(random, bytes);
    Security::secureZero(random, sizeof(random));
    return encoded;
}

inline bool printable(const String& value, size_t limit) {
    if (value.length() == 0 || value.length() > limit) return false;
    for (size_t index = 0; index < value.length(); index++) if (value[index] < 32 || value[index] > 126) return false;
    return true;
}

inline String contactFor(DynamicJsonDocument& contacts, const String& mac) {
    for (JsonPair contact : contacts.as<JsonObject>()) if (mac.equalsIgnoreCase(contact.key().c_str())) return String(contact.key().c_str());
    return "";
}

inline String verifiedPublic(DynamicJsonDocument& contacts, const String& mac) {
    const String contact = contactFor(contacts, mac);
    if (contact.length() == 0 || !MessageCrypto::hasVerifiedSession(contacts, contact)) return "";
    return contacts[contact]["keys"]["verified_peer_pub"] | "";
}

inline String memberPublic(JsonObject record, const String& mac) {
    for (JsonObject member : record["members"].as<JsonArray>()) if (member["mac"].as<String>() == mac) return member["pub"] | "";
    return "";
}

inline bool rosterValid(JsonObject record, const String& localMac, const String& localPublic) {
    JsonArray members = record["members"].as<JsonArray>();
    if (members.size() == 0 || members.size() > MAX_MEMBERS) return false;
    for (size_t index = 0; index < members.size(); index++) {
        const String mac = members[index]["mac"] | "";
        const String key = members[index]["pub"] | "";
        if (!canonicalMac(mac) || !validHex(key, 32)) return false;
        for (size_t earlier = 0; earlier < index; earlier++) {
            if (members[earlier]["mac"].as<String>() == mac ||
                MessageCrypto::samePublicKey(members[earlier]["pub"].as<String>(), key)) return false;
        }
    }
    return memberPublic(record, record["owner"].as<String>()) == record["owner_pub"].as<String>() &&
           MessageCrypto::samePublicKey(memberPublic(record, localMac), localPublic);
}

inline bool save(JsonDocument& store) {
    if (store.overflowed() || measureJsonPretty(store) > STORE_CAPACITY) return false;
    return saveJsonEncrypted(store, STORE_PATH, "groups");
}

inline void cancelOutbox(JsonObject record) {
    const String logical = record["outbox"]["id"] | "";
    for (JsonObject message : record["history"].as<JsonArray>()) {
        if (message["from"].as<String>() != ownMac() || message["id"].as<String>() != logical) continue;
        message["status"] = "unconfirmed";
        for (JsonPair delivery : message["delivery"].as<JsonObject>())
            if (delivery.value().as<String>() == "pending") delivery.value().set("unconfirmed");
    }
    record.remove("outbox");
}

inline void prepareRoster(JsonObject record) {
    cancelOutbox(record);
    record.remove("sync");
    record.createNestedObject("sync");
    record.remove("membership");
    record.createNestedObject("membership");
    record.remove("seen");
    record.createNestedArray("seen");
    record.remove("rx_sequence");
    record.createNestedObject("rx_sequence");
    record["tx_sequence"] = 0UL;
    if (record["state"].as<String>() != "active") return;
    for (JsonObject member : record["members"].as<JsonArray>()) {
        const String mac = member["mac"] | "";
        if (mac == ownMac()) continue;
        record["sync"][mac]["epoch"] = record["epoch"];
        record["sync"][mac]["state"] = "pending";
        record["membership"][mac] = "invited";
    }
}

inline bool queueResponse(JsonObject record, const String& action) {
    if (record["owner"].as<String>() == ownMac()) return false;
    const uint32_t epoch = record["epoch"] | 0UL;
    if (record["response"]["action"].as<String>() != action ||
        record["response"]["epoch"].as<uint32_t>() != epoch) {
        const String identifier = randomHex(16);
        if (identifier.length() == 0) return false;
        record.remove("response");
        record["response"]["id"] = identifier;
        record["response"]["action"] = action;
        record["response"]["epoch"] = epoch;
    }
    record["response"]["state"] = "pending";
    return true;
}

inline bool queueRevocation(JsonObject record, const String& mac, const String& key) {
    JsonObject revocations = record["revocations"].as<JsonObject>();
    if (revocations.isNull()) revocations = record.createNestedObject("revocations");
    if (!revocations.containsKey(mac) && revocations.size() >= MAX_REVOCATIONS) return false;
    revocations[mac]["pub"] = key;
    revocations[mac]["epoch"] = record["epoch"];
    revocations[mac]["state"] = "pending";
    return true;
}

inline bool migrateRecord(JsonObject record) {
    if (record.containsKey("format")) return record["format"].is<uint8_t>() && record["format"].as<uint8_t>() == FORMAT_VERSION;
    record["format"] = FORMAT_VERSION;
    record.createNestedObject("revocations");
    record.createNestedArray("member_events");
    const String state = record["state"] | "";
    if (record["owner"].as<String>() == ownMac() && (state == "active" || state == "closed")) {
        const uint32_t epoch = record["epoch"] | 0UL;
        const String key = randomHex(32);
        if (epoch == UINT32_MAX || key.length() == 0) return false;
        record["epoch"] = epoch + 1;
        if (state == "active") record["key"] = key;
        else {
            for (JsonObject member : record["members"].as<JsonArray>()) {
                const String mac = member["mac"] | "";
                if (mac != ownMac() && !queueRevocation(record, mac, member["pub"].as<String>())) return false;
            }
        }
    } else if (state == "active" || state == "invited") record["needs_sync"] = true;
    prepareRoster(record);
    return true;
}

inline bool deliveryState(const String& state) {
    return state == "pending" || state == "delivered" || state == "unconfirmed";
}

inline bool load(JsonDocument& store) {
    File stored = SD.open(STORE_PATH, FILE_READ);
    if (stored) {
        const bool bounded = static_cast<size_t>(stored.size()) <= STORE_CAPACITY + ENC_FILE_HEADER_LEN;
        stored.close();
        if (!bounded) return false;
    }
    if (!loadJsonEncryptedAware(store, STORE_PATH, "groups", "{}") || store.overflowed() ||
        !store.is<JsonObject>() || store.size() > MAX_GROUPS) return false;
    bool recovered = false;
    for (JsonPair entry : store.as<JsonObject>()) {
        JsonObject record = entry.value().as<JsonObject>();
        const bool legacy = !record.containsKey("format");
        if (!migrateRecord(record)) return false;
        recovered = recovered || legacy;
        const String state = record["state"] | "";
        if (!validHex(String(entry.key().c_str()), 16) || !record["epoch"].is<uint32_t>() ||
            record["epoch"].as<uint32_t>() == 0 || !printable(record["name"].as<String>(), 20) ||
            !canonicalMac(record["owner"].as<String>()) || !validHex(record["owner_pub"].as<String>(), 32) ||
            record["members"].size() > MAX_MEMBERS || record["history"].size() > MAX_HISTORY || record["seen"].size() > MAX_SEEN ||
            (state != "active" && state != "invited" && state != "left" && state != "removed" && state != "closed")) return false;
        if (!record["members"].is<JsonArray>() || !record["history"].is<JsonArray>() ||
            !record["seen"].is<JsonArray>() || !record["sync"].is<JsonObject>() || record["sync"].size() >= MAX_MEMBERS ||
            !record["revocations"].is<JsonObject>() || record["revocations"].size() > MAX_REVOCATIONS ||
            !record["membership"].is<JsonObject>() || record["membership"].size() > MAX_MEMBERS ||
            !record["rx_sequence"].is<JsonObject>() || record["rx_sequence"].size() > MAX_MEMBERS ||
            !record["tx_sequence"].is<uint32_t>() || !record["member_events"].is<JsonArray>() ||
            record["member_events"].size() > MAX_MEMBER_EVENTS) return false;
        if ((state == "active" || state == "invited") && (!validHex(record["key"].as<String>(), 32) ||
            !rosterValid(record, ownMac(), ownPublic()))) return false;
        if (record["owner"].as<String>() == ownMac() && !MessageCrypto::samePublicKey(record["owner_pub"].as<String>(), ownPublic())) return false;
        for (JsonPair member : record["membership"].as<JsonObject>()) {
            const String status = member.value().as<String>();
            if (memberPublic(record, member.key().c_str()).length() == 0 ||
                (status != "invited" && status != "accepted")) return false;
        }
        for (JsonPair sender : record["rx_sequence"].as<JsonObject>()) {
            if (memberPublic(record, sender.key().c_str()).length() == 0 ||
                !sender.value().is<uint32_t>() || sender.value().as<uint32_t>() == 0) return false;
        }
        for (JsonObject event : record["member_events"].as<JsonArray>()) {
            if (!canonicalMac(event["from"].as<String>()) || !validHex(event["id"].as<String>(), 16) ||
                !validHex(event["pub"].as<String>(), 32) || !validHex(event["hash"].as<String>(), 32)) return false;
        }
        for (JsonPair job : record["sync"].as<JsonObject>()) {
            if (memberPublic(record, job.key().c_str()).length() == 0 ||
                job.value()["epoch"].as<uint32_t>() != record["epoch"].as<uint32_t>() ||
                !deliveryState(job.value()["state"].as<String>())) return false;
        }
        for (JsonPair job : record["revocations"].as<JsonObject>()) {
            if (!canonicalMac(job.key().c_str()) || !validHex(job.value()["pub"].as<String>(), 32) ||
                !deliveryState(job.value()["state"].as<String>()) ||
                !job.value()["epoch"].is<uint32_t>() || job.value()["epoch"].as<uint32_t>() == 0 ||
                job.value()["epoch"].as<uint32_t>() > record["epoch"].as<uint32_t>()) return false;
        }
        if (record["outbox"].is<JsonObject>()) {
            JsonObject outgoing = record["outbox"].as<JsonObject>();
            if (!validHex(outgoing["id"].as<String>(), 16) || !outgoing["epoch"].is<uint32_t>() ||
                outgoing["epoch"].as<uint32_t>() != record["epoch"].as<uint32_t>() ||
                outgoing["payload"].as<String>().length() > MessageCrypto::MAX_APPLICATION_PAYLOAD ||
                !outgoing["targets"].is<JsonObject>() || outgoing["targets"].size() == 0 ||
                outgoing["targets"].size() >= MAX_MEMBERS) return false;
            Document wire(2048);
            const String outgoingPayload = outgoing["payload"].as<String>();
            if (state != "active" || deserializeJson(wire, outgoingPayload.c_str(), outgoingPayload.length(), DeserializationOption::NestingLimit(4)) != DeserializationError::Ok ||
                wire["gver"].as<int>() != FORMAT_VERSION || wire["id"].as<String>() != entry.key().c_str() ||
                wire["sender"].as<String>() != ownMac() || wire["mid"].as<String>() != outgoing["id"].as<String>() ||
                wire["epoch"].as<uint32_t>() != record["epoch"].as<uint32_t>() ||
                !wire["seq"].is<uint32_t>() || wire["seq"].as<uint32_t>() == 0 ||
                wire["seq"].as<uint32_t>() != record["tx_sequence"].as<uint32_t>() ||
                wire["body"].as<String>().length() == 0 || wire["body"].as<String>().length() > 256) return false;
            for (JsonPair target : outgoing["targets"].as<JsonObject>()) {
                if (!canonicalMac(target.key().c_str()) || String(target.key().c_str()) == ownMac() ||
                    !MessageCrypto::samePublicKey(target.value()["pub"].as<String>(), memberPublic(record, target.key().c_str())) ||
                    !deliveryState(target.value()["state"].as<String>())) return false;
                if (target.value()["state"].as<String>() == "pending") {
                    target.value()["state"] = "unconfirmed";
                    recovered = true;
                }
            }
        }
        if (record["response"].is<JsonObject>()) {
            const String action = record["response"]["action"] | "";
            if (!validHex(record["response"]["id"].as<String>(), 16) || !record["response"]["epoch"].is<uint32_t>() ||
                record["response"]["epoch"].as<uint32_t>() != record["epoch"].as<uint32_t>() ||
                !deliveryState(record["response"]["state"].as<String>()) ||
                (action != "join" && action != "leave" && action != "decline" && action != "sync")) return false;
        }
        for (JsonObject message : record["history"].as<JsonArray>()) {
            const String status = message["status"] | "";
            if (!canonicalMac(message["from"].as<String>()) || !validHex(message["id"].as<String>(), 16) ||
                !printable(message["text"].as<String>(), MAX_TEXT) || !message["delivery"].is<JsonObject>() ||
                message["delivery"].size() > MAX_MEMBERS ||
                (status != "pending" && status != "delivered" && status != "unconfirmed" && status != "received")) return false;
            if (status == "pending") { message["status"] = "unconfirmed"; recovered = true; }
            for (JsonPair delivery : message["delivery"].as<JsonObject>()) {
                if (!canonicalMac(String(delivery.key().c_str()))) return false;
                const String deliveryState = delivery.value().as<String>();
                if (deliveryState == "pending") { delivery.value().set("unconfirmed"); recovered = true; }
                else if (deliveryState != "delivered" && deliveryState != "unconfirmed") return false;
            }
        }
        for (JsonObject seen : record["seen"].as<JsonArray>()) {
            if (!canonicalMac(seen["from"].as<String>()) || !validHex(seen["id"].as<String>(), 16) ||
                !validHex(seen["hash"].as<String>(), 32)) return false;
        }
    }
    return !recovered || save(store);
}

inline String digest(const String& text) {
    uint8_t hash[32]{};
    if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), reinterpret_cast<const uint8_t*>(text.c_str()), text.length(), hash) != 0) return "";
    return MessageCrypto::bytesToHex(hash, sizeof(hash));
}

inline bool commit(JsonDocument& store, JsonDocument& transaction) {
    if (!save(transaction)) return false;
    store = std::move(transaction);
    return true;
}

inline bool create(JsonDocument& store, const String& name, String& id) {
    if (store.size() >= MAX_GROUPS || !printable(name, 20)) return false;
    id = randomHex(16);
    const String key = randomHex(32);
    const String ownKey = ownPublic();
    if (id.length() == 0 || key.length() == 0 || ownKey.length() == 0 || store.containsKey(id)) return false;
    Document transaction(STORE_CAPACITY);
    if (!transaction.set(store)) return false;
    JsonObject record = transaction.createNestedObject(id);
    record["format"] = FORMAT_VERSION;
    record["name"] = name;
    record["owner"] = ownMac();
    record["owner_pub"] = ownKey;
    record["epoch"] = 1UL;
    record["key"] = key;
    record["state"] = "active";
    JsonObject owner = record.createNestedArray("members").createNestedObject();
    owner["mac"] = ownMac();
    owner["pub"] = ownKey;
    record.createNestedArray("history");
    record.createNestedArray("seen");
    record.createNestedObject("sync");
    record.createNestedObject("revocations");
    record.createNestedArray("member_events");
    prepareRoster(record);
    return commit(store, transaction);
}

inline bool allPeersVerified(JsonObject record, DynamicJsonDocument& contacts) {
    if (record["state"].as<String>() != "active" || (record["needs_sync"] | false) ||
        !rosterValid(record, ownMac(), ownPublic())) return false;
    for (JsonObject member : record["members"].as<JsonArray>()) {
        const String mac = member["mac"] | "";
        if (mac != ownMac() && !MessageCrypto::samePublicKey(member["pub"].as<String>(), verifiedPublic(contacts, mac))) return false;
    }
    return true;
}

inline bool snapshot(JsonObject record, const String& id, String& output) {
    Document wire(4096);
    wire["gver"] = FORMAT_VERSION;
    wire["op"] = "snapshot";
    wire["id"] = id;
    wire["name"] = record["name"];
    wire["owner"] = record["owner"];
    wire["owner_pub"] = record["owner_pub"];
    wire["epoch"] = record["epoch"];
    wire["key"] = record["key"];
    wire["members"].set(record["members"]);
    return !wire.overflowed() && serializeJson(wire, output) != 0 && output.length() <= MessageCrypto::MAX_APPLICATION_PAYLOAD;
}

inline String messageAad(const String& id, uint32_t epoch, const String& sender, const String& logical, uint32_t sequence) {
    return String("M5PAGER_GROUP_V2|") + id + "|" + String(epoch) + "|" + sender + "|" + logical + "|" + String(sequence);
}

inline bool appendHistory(JsonObject record, const String& sender, const String& logical,
                          const String& text, const char* status) {
    JsonArray history = record["history"].as<JsonArray>();
    if (history.isNull()) history = record.createNestedArray("history");
    while (history.size() >= MAX_HISTORY) {
        const String protectedId = record["outbox"]["id"] | "";
        size_t removeIndex = 0;
        if (protectedId.length() != 0 && history[0]["id"].as<String>() == protectedId &&
            history[0]["from"].as<String>() == ownMac()) removeIndex = 1;
        history.remove(removeIndex);
    }
    JsonObject message = history.createNestedObject();
    message["from"] = sender;
    message["id"] = logical;
    message["text"] = text;
    message["status"] = status;
    message.createNestedObject("delivery");
    return !message.isNull();
}

inline bool ownerCanEdit(JsonObject record) {
    return record["state"].as<String>() == "active" && record["owner"].as<String>() == ownMac() &&
           MessageCrypto::samePublicKey(record["owner_pub"].as<String>(), ownPublic());
}

inline bool rotateRoster(JsonDocument& transaction, const String& id, DynamicJsonDocument& contacts,
                         const String& memberMac, bool adding, bool closing) {
    JsonObject record = transaction[id].as<JsonObject>();
    if (!ownerCanEdit(record) || !rosterValid(record, ownMac(), ownPublic())) return false;
    const uint32_t epoch = record["epoch"] | 0UL;
    if (epoch == 0 || epoch == UINT32_MAX || memberMac == ownMac()) return false;
    JsonArray members = record["members"].as<JsonArray>();
    if (adding) {
        const String key = verifiedPublic(contacts, memberMac);
        if (!canonicalMac(memberMac) || key.length() == 0 || members.size() >= MAX_MEMBERS ||
            memberPublic(record, memberMac).length() != 0 ||
            record["revocations"].size() - (record["revocations"].containsKey(memberMac) ? 1 : 0) >= MAX_REVOCATIONS - MAX_MEMBERS) return false;
        record["revocations"].remove(memberMac);
        JsonObject member = members.createNestedObject();
        member["mac"] = memberMac;
        member["pub"] = key;
        if (!rosterValid(record, ownMac(), ownPublic())) return false;
    }
    record["epoch"] = epoch + 1;
    for (JsonPair revoked : record["revocations"].as<JsonObject>()) {
        revoked.value()["epoch"] = epoch + 1;
        revoked.value()["state"] = "pending";
    }
    if (closing) {
        for (JsonObject member : members) {
            const String mac = member["mac"] | "";
            if (mac != ownMac() && !queueRevocation(record, mac, member["pub"].as<String>())) return false;
        }
        record["state"] = "closed";
        record.remove("key");
    } else {
        if (!adding && memberMac.length() != 0) {
            bool found = false;
            for (size_t index = 0; index < members.size(); index++) {
                if (members[index]["mac"].as<String>() != memberMac) continue;
                if (!queueRevocation(record, memberMac, members[index]["pub"].as<String>())) return false;
                members.remove(index);
                found = true;
                break;
            }
            if (!found) return false;
        }
        const String nextKey = randomHex(32);
        if (nextKey.length() == 0) return false;
        record["key"] = nextKey;
    }
    record.remove("needs_sync");
    prepareRoster(record);
    return !transaction.overflowed();
}

inline bool applyMemberResponse(JsonDocument& store, DynamicJsonDocument& contacts,
                                const String& source, JsonObject wire, const String& payload, String& affected) {
    const String id = wire["id"] | "";
    const String token = wire["event"] | "";
    const String key = wire["member_pub"] | "";
    const String action = wire["action"] | "";
    JsonObject current = store[id].as<JsonObject>();
    if (current.isNull() || current["owner"].as<String>() != ownMac() ||
        !MessageCrypto::samePublicKey(current["owner_pub"].as<String>(), ownPublic()) ||
        !MessageCrypto::samePublicKey(key, verifiedPublic(contacts, source)) ||
        !validHex(token, 16) || !wire["epoch"].is<uint32_t>() || wire["epoch"].as<uint32_t>() == 0 ||
        (action != "join" && action != "decline" && action != "leave" && action != "sync")) return false;
    const String hash = digest(payload);
    if (hash.length() == 0) return false;
    for (JsonObject event : current["member_events"].as<JsonArray>()) {
        if (event["from"].as<String>() == source && event["id"].as<String>() == token) {
            affected = id;
            return event["hash"].as<String>() == hash && MessageCrypto::samePublicKey(event["pub"].as<String>(), key);
        }
    }
    const uint32_t epoch = wire["epoch"].as<uint32_t>();
    const bool member = MessageCrypto::samePublicKey(memberPublic(current, source), key);
    const bool revoked = MessageCrypto::samePublicKey(current["revocations"][source]["pub"].as<String>(), key);
    if (epoch > current["epoch"].as<uint32_t>() ||
        (action == "sync" ? (!member && !revoked) : (!member || epoch != current["epoch"].as<uint32_t>() ||
            current["state"].as<String>() != "active"))) return false;
    Document transaction(STORE_CAPACITY);
    if (!transaction.set(store)) return false;
    JsonObject record = transaction[id].as<JsonObject>();
    if (action == "join") record["membership"][source] = "accepted";
    else if (action == "sync") {
        if (revoked) record["revocations"][source]["state"] = "pending";
        else record["sync"][source]["state"] = "pending";
    } else if (!rotateRoster(transaction, id, contacts, source, false, false)) return false;
    JsonArray events = record["member_events"].as<JsonArray>();
    while (events.size() >= MAX_MEMBER_EVENTS) events.remove(0);
    JsonObject event = events.createNestedObject();
    event["from"] = source;
    event["id"] = token;
    event["pub"] = key;
    event["hash"] = hash;
    if (!commit(store, transaction)) return false;
    affected = id;
    return true;
}

inline bool applyControl(JsonDocument& store, DynamicJsonDocument& contacts,
                         const String& source, const String& payload, String& affected) {
    if (payload.length() > MessageCrypto::MAX_APPLICATION_PAYLOAD || !canonicalMac(source) || source == ownMac()) return false;
    Document wire(4096);
    if (deserializeJson(wire, payload.c_str(), payload.length(), DeserializationOption::NestingLimit(6)) != DeserializationError::Ok ||
        !wire["gver"].is<uint8_t>() || wire["gver"].as<uint8_t>() != FORMAT_VERSION) return false;
    const String operation = wire["op"] | "";
    const String id = wire["id"] | "";
    if (!validHex(id, 16)) return false;
    if (operation == "member") return applyMemberResponse(store, contacts, source, wire.as<JsonObject>(), payload, affected);
    const String ownerKey = wire["owner_pub"] | "";
    if ((operation != "snapshot" && operation != "revoke") ||
        wire["owner"].as<String>() != source || !wire["epoch"].is<uint32_t>() ||
        !MessageCrypto::samePublicKey(ownerKey, verifiedPublic(contacts, source))) return false;
    const uint32_t epoch = wire["epoch"].as<uint32_t>();
    if (epoch == 0) return false;
    JsonObject current = store[id].as<JsonObject>();
    const String hash = digest(payload);
    if (hash.length() == 0) return false;
    if (!current.isNull()) {
        if (current["owner"].as<String>() != source || !MessageCrypto::samePublicKey(current["owner_pub"].as<String>(), ownerKey)) return false;
        const uint32_t previous = current["epoch"] | 0UL;
        if (epoch <= previous) {
            affected = id;
            return epoch == previous && current["control_hash"].as<String>() == hash;
        }
    } else if (operation != "snapshot" || store.size() >= MAX_GROUPS) return false;
    if (operation == "snapshot" && (!printable(wire["name"].as<String>(), 20) || !validHex(wire["key"].as<String>(), 32) ||
        !rosterValid(wire.as<JsonObject>(), ownMac(), ownPublic()))) return false;
    Document transaction(STORE_CAPACITY);
    if (!transaction.set(store)) return false;
    JsonObject record = transaction[id].as<JsonObject>();
    if (record.isNull()) {
        record = transaction.createNestedObject(id);
        record["format"] = FORMAT_VERSION;
        record.createNestedArray("history");
        record.createNestedObject("revocations");
        record.createNestedArray("member_events");
    }
    const String previousState = record["state"] | "";
    cancelOutbox(record);
    record["owner"] = source;
    record["owner_pub"] = ownerKey;
    record["epoch"] = epoch;
    record["control_hash"] = hash;
    record.remove("needs_sync");
    record.remove("response");
    record.remove("seen");
    record.createNestedArray("seen");
    record.remove("rx_sequence");
    record.createNestedObject("rx_sequence");
    record["tx_sequence"] = 0UL;
    record.remove("sync");
    record.createNestedObject("sync");
    record.remove("membership");
    record.createNestedObject("membership");
    if (operation == "revoke") {
        record["state"] = "removed";
        record.remove("key");
    } else {
        record["name"] = wire["name"];
        record["members"].set(wire["members"]);
        if (previousState == "left") {
            record["state"] = "left";
            record.remove("key");
            if (!queueResponse(record, "leave")) return false;
        } else {
            record["key"] = wire["key"];
            record["state"] = previousState == "active" ? "active" : "invited";
            if (previousState == "active" && !queueResponse(record, "join")) return false;
        }
    }
    if (!commit(store, transaction)) return false;
    affected = id;
    return true;
}

inline bool applyMessage(JsonDocument& store, DynamicJsonDocument& contacts,
                         const String& source, const String& payload, String& affected) {
    if (payload.length() > MessageCrypto::MAX_APPLICATION_PAYLOAD) return false;
    Document wire(2048);
    if (deserializeJson(wire, payload.c_str(), payload.length(), DeserializationOption::NestingLimit(4)) != DeserializationError::Ok) return false;
    const String id = wire["id"] | "";
    const String logical = wire["mid"] | "";
    if (!wire["gver"].is<uint8_t>() || wire["gver"].as<uint8_t>() != FORMAT_VERSION || !validHex(id, 16) || !validHex(logical, 16) ||
        source == ownMac() || wire["sender"].as<String>() != source || !wire["epoch"].is<uint32_t>() ||
        !wire["seq"].is<uint32_t>() || wire["seq"].as<uint32_t>() == 0) return false;
    JsonObject record = store[id].as<JsonObject>();
    if (record.isNull() || record["state"].as<String>() != "active" || (record["needs_sync"] | false) ||
        wire["epoch"].as<uint32_t>() != record["epoch"].as<uint32_t>() ||
        !MessageCrypto::samePublicKey(memberPublic(record, source), verifiedPublic(contacts, source)) ||
        !MessageCrypto::samePublicKey(memberPublic(record, ownMac()), ownPublic())) return false;
    if (record["owner"].as<String>() == ownMac() && record["membership"][source].as<String>() != "accepted") return false;
    const String hash = digest(payload);
    if (hash.length() == 0) return false;
    for (JsonObject seen : record["seen"].as<JsonArray>()) {
        if (seen["from"].as<String>() == source && seen["id"].as<String>() == logical) return seen["hash"].as<String>() == hash;
    }
    if (wire["seq"].as<uint32_t>() <= record["rx_sequence"][source].as<uint32_t>()) return false;
    uint8_t key[32]{};
    uint8_t* blob = nullptr;
    size_t length = 0;
    const String encoded = wire["body"] | "";
    if (encoded.length() > 256 || !MessageCrypto::base64Decode(encoded, blob, length)) return false;
    const size_t overhead = Security::GCM_IV_LEN + Security::GCM_TAG_LEN;
    uint8_t plaintext[MAX_TEXT + 1]{};
    const String aad = messageAad(id, wire["epoch"].as<uint32_t>(), source, logical, wire["seq"].as<uint32_t>());
    bool valid = length > overhead && length <= overhead + MAX_TEXT &&
        MessageCrypto::hexToBytes(record["key"].as<String>(), key, sizeof(key)) &&
        Security::aesGcmDecrypt(key, blob + overhead, length - overhead, reinterpret_cast<const uint8_t*>(aad.c_str()),
            aad.length(), blob, blob + Security::GCM_IV_LEN, plaintext);
    const String text = valid ? String(reinterpret_cast<const char*>(plaintext)) : String("");
    valid = valid && text.length() == length - overhead && printable(text, MAX_TEXT);
    Security::secureZero(key, sizeof(key));
    Security::secureZero(plaintext, sizeof(plaintext));
    if (blob != nullptr) { Security::secureZero(blob, length); free(blob); }
    if (!valid) return false;
    Document transaction(STORE_CAPACITY);
    if (!transaction.set(store)) return false;
    JsonObject updated = transaction[id].as<JsonObject>();
    JsonArray seen = updated["seen"].as<JsonArray>();
    if (seen.isNull()) seen = updated.createNestedArray("seen");
    while (seen.size() >= MAX_SEEN) seen.remove(0);
    JsonObject entry = seen.createNestedObject();
    entry["from"] = source;
    entry["id"] = logical;
    entry["hash"] = hash;
    updated["rx_sequence"][source] = wire["seq"];
    if (!appendHistory(updated, source, logical, text, "received")) return false;
    JsonArray history = updated["history"].as<JsonArray>();
    history[history.size() - 1]["epoch"] = wire["epoch"];
    history[history.size() - 1]["sequence"] = wire["seq"];
    history[history.size() - 1]["sender_pub"] = memberPublic(updated, source);
    if (!commit(store, transaction)) return false;
    affected = id;
    return true;
}

inline bool encodeMessage(JsonObject record, const String& id, const String& text, String& logical, String& output) {
    if (!printable(text, MAX_TEXT) || record["tx_sequence"].as<uint32_t>() == UINT32_MAX) return false;
    const uint32_t sequence = record["tx_sequence"].as<uint32_t>() + 1;
    logical = randomHex(16);
    uint8_t key[32]{};
    uint8_t blob[Security::GCM_IV_LEN + Security::GCM_TAG_LEN + MAX_TEXT]{};
    const String aad = messageAad(id, record["epoch"].as<uint32_t>(), ownMac(), logical, sequence);
    bool valid = logical.length() != 0 && MessageCrypto::hexToBytes(record["key"].as<String>(), key, sizeof(key)) &&
        Security::aesGcmEncrypt(key, reinterpret_cast<const uint8_t*>(text.c_str()), text.length(),
            reinterpret_cast<const uint8_t*>(aad.c_str()), aad.length(), blob,
            blob + Security::GCM_IV_LEN + Security::GCM_TAG_LEN, blob + Security::GCM_IV_LEN);
    String encrypted;
    if (valid) valid = MessageCrypto::base64Encode(blob, Security::GCM_IV_LEN + Security::GCM_TAG_LEN + text.length(), encrypted);
    Security::secureZero(key, sizeof(key));
    Security::secureZero(blob, sizeof(blob));
    if (!valid) return false;
    Document wire(1536);
    wire["id"] = id;
    wire["epoch"] = record["epoch"];
    wire["sender"] = ownMac();
    wire["gver"] = FORMAT_VERSION;
    wire["seq"] = sequence;
    wire["mid"] = logical;
    wire["body"] = encrypted;
    return !wire.overflowed() && serializeJson(wire, output) != 0 && output.length() <= MessageCrypto::MAX_APPLICATION_PAYLOAD;
}

}
