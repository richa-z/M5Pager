#pragma once

#include "security/group_store.h"

struct GroupTarget {
    String mac;
    String expectedPublic;
    String payload;
};

struct GroupBatch {
    bool active = false;
    String id;
    String logical;
    String task;
    uint32_t epoch = 0;
    uint32_t taskEpoch = 0;
    MessageCrypto::ContentKind kind = MessageCrypto::ContentKind::GroupControl;
    GroupTarget targets[Groups::MAX_MEMBERS];
    size_t count = 0;
    size_t next = 0;
};

GroupBatch groupBatch;
unsigned long nextGroupDispatchMs = 0;
bool groupStorageFault = false;

bool commitGroupTransaction(JsonDocument& transaction) {
    const bool saved = Groups::commit(groups, transaction);
    groupStorageFault = !saved;
    return saved;
}

bool groupTransferBusy() { return groupBatch.active; }

void resetGroupDelivery() {
    if (groupBatch.active && pendingOutgoingKind != MessageCrypto::ContentKind::Text) {
        awaitingAck = false;
        pendingOutgoingReady = false;
        pendingOutgoingText = "";
        pendingOutgoingContact = "";
        pendingDelivery = Delivery::Pending{};
        pendingOutgoingKind = MessageCrypto::ContentKind::Text;
    }
    groupBatch = GroupBatch{};
}

void updateGroupMessageStatus(JsonObject record, const String& logical) {
    JsonObject outgoing = record["outbox"].as<JsonObject>();
    bool pending = false;
    bool failed = false;
    for (JsonPair target : outgoing["targets"].as<JsonObject>()) {
        pending = pending || target.value()["state"].as<String>() == "pending";
        failed = failed || target.value()["state"].as<String>() != "delivered";
    }
    for (JsonObject message : record["history"].as<JsonArray>()) {
        if (message["id"].as<String>() != logical || message["from"].as<String>() != Groups::ownMac()) continue;
        for (JsonPair target : outgoing["targets"].as<JsonObject>())
            message["delivery"][target.key().c_str()] = target.value()["state"];
        message["status"] = pending ? "pending" : (failed ? "unconfirmed" : "delivered");
    }
    if (!failed) record.remove("outbox");
}

bool finishGroupTransfer(bool delivered) {
    if (!groupBatch.active || groupBatch.next >= groupBatch.count) return false;
    Groups::Document transaction(Groups::STORE_CAPACITY);
    if (!transaction.set(groups)) { groupStorageFault = true; return false; }
    JsonObject record = transaction[groupBatch.id].as<JsonObject>();
    const String mac = groupBatch.targets[groupBatch.next].mac;
    const char* state = delivered ? "delivered" : "unconfirmed";
    bool changed = false;
    if (!record.isNull() && record["epoch"].as<uint32_t>() == groupBatch.epoch) {
        if (groupBatch.kind == MessageCrypto::ContentKind::GroupMessage && record["outbox"]["id"].as<String>() == groupBatch.logical) {
            record["outbox"]["targets"][mac]["state"] = state;
            updateGroupMessageStatus(record, groupBatch.logical);
            changed = true;
        } else if (groupBatch.task == "revoke" && record["revocations"][mac]["epoch"].as<uint32_t>() == groupBatch.taskEpoch) {
            if (delivered) record["revocations"].remove(mac);
            else record["revocations"][mac]["state"] = state;
            changed = true;
        } else if (groupBatch.task == "snapshot") {
            record["sync"][mac]["state"] = state;
            changed = true;
        } else if (groupBatch.task == "response" && record["response"]["id"].as<String>() == groupBatch.logical) {
            record["response"]["state"] = state;
            changed = true;
        }
    }
    if (changed && !commitGroupTransaction(transaction)) return false;
    groupBatch.next++;
    if (groupBatch.next == groupBatch.count) groupBatch = GroupBatch{};
    nextGroupDispatchMs = millis() + 250;
    refreshGroupsUi();
    return true;
}

bool addGroupTarget(GroupBatch& batch, const String& mac, const String& payload, const String& expectedPublic) {
    if (mac == Groups::ownMac()) return true;
    if (batch.count >= Groups::MAX_MEMBERS || payload.length() == 0 ||
        payload.length() > MessageCrypto::MAX_APPLICATION_PAYLOAD || !Groups::canonicalMac(mac) ||
        !Groups::validHex(expectedPublic, 32)) return false;
    batch.targets[batch.count].mac = mac;
    batch.targets[batch.count].expectedPublic = expectedPublic;
    batch.targets[batch.count].payload = payload;
    batch.count++;
    batch.active = true;
    return true;
}

bool groupMutationBusy() {
    return groupTransferBusy() || awaitingAck || (pendingExchange.active && !pendingExchange.completed);
}

bool editGroupMember(const String& id, const String& mac, bool adding, bool closing) {
    if (groupMutationBusy()) return false;
    Groups::Document transaction(Groups::STORE_CAPACITY);
    return transaction.set(groups) && Groups::rotateRoster(transaction, id, contacts, mac, adding, closing) &&
        commitGroupTransaction(transaction);
}

bool renameGroup(const String& id, const String& name) {
    if (groupMutationBusy() || !Groups::printable(name, 20)) return false;
    Groups::Document transaction(Groups::STORE_CAPACITY);
    if (!transaction.set(groups) || !Groups::rotateRoster(transaction, id, contacts, "", false, false)) return false;
    transaction[id]["name"] = name;
    return commitGroupTransaction(transaction);
}

bool syncGroup(const String& id) {
    if (groupMutationBusy()) return false;
    Groups::Document transaction(Groups::STORE_CAPACITY);
    if (!transaction.set(groups)) return false;
    JsonObject record = transaction[id].as<JsonObject>();
    if (record.isNull()) return false;
    if (record["owner"].as<String>() == Groups::ownMac()) {
        if (!MessageCrypto::samePublicKey(record["owner_pub"].as<String>(), Groups::ownPublic())) return false;
        for (JsonPair job : record["revocations"].as<JsonObject>()) job.value()["state"] = "pending";
        if (record["state"].as<String>() == "active")
            for (JsonPair job : record["sync"].as<JsonObject>()) job.value()["state"] = "pending";
    } else {
        const String state = record["state"] | "";
        const String action = state == "left" ? "leave" : (state == "active" && !(record["needs_sync"] | false) ? "join" : "sync");
        if (!Groups::queueResponse(record, action)) return false;
    }
    return commitGroupTransaction(transaction);
}

bool acceptGroup(const String& id, bool accept) {
    if (groupMutationBusy()) return false;
    JsonObject record = groups[id].as<JsonObject>();
    if (record["state"].as<String>() != "invited" || (record["needs_sync"] | false)) return false;
    const String owner = record["owner"] | "";
    if (accept && (!MessageCrypto::samePublicKey(record["owner_pub"].as<String>(), Groups::verifiedPublic(contacts, owner)) ||
        !Groups::rosterValid(record, Groups::ownMac(), Groups::ownPublic()))) return false;
    Groups::Document transaction(Groups::STORE_CAPACITY);
    if (!transaction.set(groups)) return false;
    JsonObject updated = transaction[id].as<JsonObject>();
    updated["state"] = accept ? "active" : "left";
    if (!accept) updated.remove("key");
    if (!Groups::queueResponse(updated, accept ? "join" : "decline")) return false;
    return commitGroupTransaction(transaction);
}

bool leaveGroup(const String& id) {
    if (groupMutationBusy()) return false;
    JsonObject record = groups[id].as<JsonObject>();
    if (record["owner"].as<String>() == Groups::ownMac() || record["state"].as<String>() != "active") return false;
    Groups::Document transaction(Groups::STORE_CAPACITY);
    if (!transaction.set(groups)) return false;
    JsonObject updated = transaction[id].as<JsonObject>();
    Groups::cancelOutbox(updated);
    updated["state"] = "left";
    updated.remove("key");
    if (!Groups::queueResponse(updated, "leave")) return false;
    return commitGroupTransaction(transaction);
}

bool ownerGroupReady(JsonObject record) {
    if (record["owner"].as<String>() != Groups::ownMac()) return true;
    for (JsonObject member : record["members"].as<JsonArray>()) {
        const String mac = member["mac"] | "";
        if (mac == Groups::ownMac()) continue;
        if (record["sync"][mac]["epoch"].as<uint32_t>() != record["epoch"].as<uint32_t>() ||
            record["sync"][mac]["state"].as<String>() != "delivered" ||
            record["membership"][mac].as<String>() != "accepted") return false;
    }
    return true;
}

bool sendGroupText(const String& id, const String& text) {
    if (groupMutationBusy()) return false;
    JsonObject record = groups[id].as<JsonObject>();
    if (record.containsKey("outbox") || record["members"].size() < 2 ||
        !Groups::allPeersVerified(record, contacts) || !ownerGroupReady(record)) return false;
    String logical, payload;
    if (!Groups::encodeMessage(record, id, text, logical, payload)) return false;
    Groups::Document transaction(Groups::STORE_CAPACITY);
    if (!transaction.set(groups)) return false;
    JsonObject updated = transaction[id].as<JsonObject>();
    if (!Groups::appendHistory(updated, Groups::ownMac(), logical, text, "pending")) return false;
    const uint32_t sequence = updated["tx_sequence"].as<uint32_t>() + 1;
    updated["tx_sequence"] = sequence;
    JsonArray history = updated["history"].as<JsonArray>();
    JsonObject message = history[history.size() - 1];
    message["epoch"] = updated["epoch"];
    message["sequence"] = sequence;
    message["sender_pub"] = Groups::ownPublic();
    JsonObject outgoing = updated.createNestedObject("outbox");
    outgoing["id"] = logical;
    outgoing["epoch"] = updated["epoch"];
    outgoing["payload"] = payload;
    for (JsonObject member : updated["members"].as<JsonArray>()) {
        const String mac = member["mac"] | "";
        if (mac == Groups::ownMac()) continue;
        outgoing["targets"][mac]["pub"] = member["pub"];
        outgoing["targets"][mac]["state"] = "pending";
        message["delivery"][mac] = "pending";
    }
    return commitGroupTransaction(transaction);
}

bool retryGroupMessage(const String& id) {
    if (groupMutationBusy()) return false;
    JsonObject record = groups[id].as<JsonObject>();
    if (!record["outbox"].is<JsonObject>() || !Groups::allPeersVerified(record, contacts) || !ownerGroupReady(record)) return false;
    Groups::Document transaction(Groups::STORE_CAPACITY);
    if (!transaction.set(groups)) return false;
    JsonObject updated = transaction[id].as<JsonObject>();
    for (JsonPair target : updated["outbox"]["targets"].as<JsonObject>())
        if (target.value()["state"].as<String>() != "delivered") target.value()["state"] = "pending";
    updateGroupMessageStatus(updated, updated["outbox"]["id"].as<String>());
    return commitGroupTransaction(transaction);
}

bool pauseGroup(const String& id, bool discard) {
    Groups::Document transaction(Groups::STORE_CAPACITY);
    if (!transaction.set(groups)) return false;
    JsonObject record = transaction[id].as<JsonObject>();
    if (record.isNull()) return false;
    for (JsonPair target : record["outbox"]["targets"].as<JsonObject>())
        if (target.value()["state"].as<String>() == "pending") target.value()["state"] = "unconfirmed";
    if (record["outbox"].is<JsonObject>()) updateGroupMessageStatus(record, record["outbox"]["id"].as<String>());
    for (JsonPair job : record["sync"].as<JsonObject>())
        if (job.value()["state"].as<String>() == "pending") job.value()["state"] = "unconfirmed";
    for (JsonPair job : record["revocations"].as<JsonObject>())
        if (job.value()["state"].as<String>() == "pending") job.value()["state"] = "unconfirmed";
    if (record["response"]["state"].as<String>() == "pending") record["response"]["state"] = "unconfirmed";
    if (discard) Groups::cancelOutbox(record);
    if (!commitGroupTransaction(transaction)) return false;
    if (groupBatch.active && groupBatch.id == id) resetGroupDelivery();
    return true;
}

bool clearGroupHistory(const String& id) {
    if (groupMutationBusy() || !groups.containsKey(id) || groups[id].containsKey("outbox")) return false;
    Groups::Document transaction(Groups::STORE_CAPACITY);
    if (!transaction.set(groups)) return false;
    transaction[id].remove("history");
    transaction[id].createNestedArray("history");
    return commitGroupTransaction(transaction);
}

bool forgetGroup(const String& id, bool abandon) {
    if (groupMutationBusy()) return false;
    JsonObject record = groups[id].as<JsonObject>();
    const String state = record["state"] | "";
    if (state != "closed" && state != "left" && state != "removed") return false;
    const String response = record["response"]["state"] | "delivered";
    if (!abandon && (record["revocations"].size() != 0 || response != "delivered")) return false;
    Groups::Document transaction(Groups::STORE_CAPACITY);
    if (!transaction.set(groups)) return false;
    transaction.remove(id);
    return commitGroupTransaction(transaction);
}

bool prepareNextGroupJob() {
    for (JsonPair pair : groups.as<JsonObject>()) {
        JsonObject record = pair.value().as<JsonObject>();
        GroupBatch prepared;
        prepared.id = pair.key().c_str();
        prepared.epoch = record["epoch"].as<uint32_t>();
        Groups::Document wire(1024);
        String payload;
        if (record["owner"].as<String>() == Groups::ownMac()) {
            for (JsonPair job : record["revocations"].as<JsonObject>()) {
                if (job.value()["state"].as<String>() != "pending") continue;
                prepared.task = "revoke";
                prepared.taskEpoch = job.value()["epoch"].as<uint32_t>();
                wire["gver"] = Groups::FORMAT_VERSION;
                wire["op"] = "revoke";
                wire["id"] = prepared.id;
                wire["owner"] = record["owner"];
                wire["owner_pub"] = record["owner_pub"];
                wire["epoch"] = prepared.taskEpoch;
                if (wire.overflowed() || serializeJson(wire, payload) == 0 ||
                    !addGroupTarget(prepared, job.key().c_str(), payload, job.value()["pub"].as<String>())) { groupStorageFault = true; return false; }
                groupBatch = std::move(prepared);
                return true;
            }
            if (record["state"].as<String>() == "active") {
                for (JsonObject member : record["members"].as<JsonArray>()) {
                    const String mac = member["mac"] | "";
                    if (mac == Groups::ownMac() || record["sync"][mac]["state"].as<String>() != "pending") continue;
                    prepared.task = "snapshot";
                    if (!Groups::snapshot(record, prepared.id, payload) ||
                        !addGroupTarget(prepared, mac, payload, member["pub"].as<String>())) { groupStorageFault = true; return false; }
                    groupBatch = std::move(prepared);
                    return true;
                }
            }
        } else if (record["response"]["state"].as<String>() == "pending") {
            prepared.task = "response";
            prepared.logical = record["response"]["id"].as<String>();
            wire["gver"] = Groups::FORMAT_VERSION;
            wire["op"] = "member";
            wire["id"] = prepared.id;
            wire["event"] = prepared.logical;
            wire["epoch"] = record["response"]["epoch"];
            wire["action"] = record["response"]["action"];
            wire["member_pub"] = Groups::ownPublic();
            if (wire.overflowed() || serializeJson(wire, payload) == 0 ||
                !addGroupTarget(prepared, record["owner"].as<String>(), payload, record["owner_pub"].as<String>())) { groupStorageFault = true; return false; }
            groupBatch = std::move(prepared);
            return true;
        }
        JsonObject outgoing = record["outbox"].as<JsonObject>();
        if (record["state"].as<String>() != "active" || outgoing.isNull()) continue;
        prepared.kind = MessageCrypto::ContentKind::GroupMessage;
        prepared.logical = outgoing["id"].as<String>();
        for (JsonPair target : outgoing["targets"].as<JsonObject>()) {
            if (target.value()["state"].as<String>() != "pending") continue;
            if (!addGroupTarget(prepared, target.key().c_str(), outgoing["payload"].as<String>(), target.value()["pub"].as<String>())) { groupStorageFault = true; return false; }
        }
        if (prepared.active) { groupBatch = std::move(prepared); return true; }
    }
    return false;
}

void clearGroupTransient() {
    groupBatch = GroupBatch{};
    isTypingGroup = false;
    groupInput = "";
    groupConfirm = "";
    selectedGroup = "";
    groupActionMac = "";
    groupActionEpoch = 0;
    groupComposeEpoch = 0;
    groupReviewRequired = false;
    groupScroll = 0;
    nextGroupDispatchMs = 0;
    groupStorageFault = false;
}

void tickGroupTransfer() {
    if (!Security::hasDevicePrivateKey()) return;
    if (groupBatch.active) {
        JsonObject record = groups[groupBatch.id].as<JsonObject>();
        if (record.isNull() || record["epoch"].as<uint32_t>() != groupBatch.epoch ||
            (groupBatch.kind == MessageCrypto::ContentKind::GroupMessage &&
                (record["state"].as<String>() != "active" || record["outbox"]["id"].as<String>() != groupBatch.logical))) {
            resetGroupDelivery();
            refreshGroupsUi();
            return;
        }
    }
    if (groupStorageFault || awaitingAck || (pendingExchange.active && !pendingExchange.completed) ||
        static_cast<int32_t>(millis() - nextGroupDispatchMs) < 0) return;
    if (!groupBatch.active && !prepareNextGroupJob()) return;
    const GroupTarget& target = groupBatch.targets[groupBatch.next];
    const String contact = Groups::contactFor(contacts, target.mac);
    uint8_t destination[6];
    if (!MessageCrypto::samePublicKey(target.expectedPublic, Groups::verifiedPublic(contacts, target.mac)) ||
        !parseMacAddress(target.mac.c_str(), destination) ||
        beginApplicationDelivery(destination, contact, target.payload, groupBatch.kind) == 0) {
        if (!finishGroupTransfer(false)) {
            resetGroupDelivery();
            nextGroupDispatchMs = millis() + 30000;
        }
    }
}
