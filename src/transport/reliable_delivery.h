#pragma once

#include "types.h"

namespace Delivery {

constexpr uint8_t MAX_ATTEMPTS = 4;
constexpr unsigned long RETRY_INTERVAL_MS = 2000;
constexpr uint8_t REASSEMBLY_SLOTS = 4;
constexpr uint8_t RECEIPT_CACHE_SIZE = 8;
using PacketSender = bool (*)(const uint8_t*, const uint8_t*, size_t);

struct Pending {
    String payload;
    String receipt;
    uint8_t attempts = 0;
};

inline bool transmit(const uint8_t* destination, const uint8_t* source,
                     uint16_t messageId, const String& payload, PacketSender sender) {
    const size_t totalLength = payload.length();
    const size_t partCount = (totalLength + MSG_CHUNK_SIZE - 1) / MSG_CHUNK_SIZE;
    if (destination == nullptr || source == nullptr || sender == nullptr ||
        partCount == 0 || partCount > MAX_MESSAGE_PARTS) return false;
    bool submitted = true;
    for (size_t partIndex = 0; partIndex < partCount; partIndex++) {
        MessageStruct packet{};
        packet.type = P_MSG;
        memcpy(packet.from, source, 6);
        packet.message_id = messageId;
        packet.split_size = static_cast<uint8_t>(partCount);
        packet.split_index = static_cast<uint8_t>(partIndex);
        const size_t offset = partIndex * MSG_CHUNK_SIZE;
        const size_t remaining = totalLength - offset;
        packet.data_len = static_cast<uint8_t>(remaining < MSG_CHUNK_SIZE ? remaining : MSG_CHUNK_SIZE);
        memcpy(packet.msg, payload.c_str() + offset, packet.data_len);
        uint8_t wire[PACKET_MAX_LEN];
        const size_t wireLength = serializePacket(packet, wire);
        if (wireLength == 0 || !sender(destination, wire, wireLength)) submitted = false;
    }
    return submitted;
}

inline IncomingAssembly* selectAssembly(IncomingAssembly* slots, const uint8_t* source,
                                        const MessageStruct& packet, unsigned long now) {
    IncomingAssembly* available = nullptr;
    for (uint8_t slotIndex = 0; slotIndex < REASSEMBLY_SLOTS; slotIndex++) {
        IncomingAssembly& candidate = slots[slotIndex];
        if (candidate.active && now - candidate.lastPacketMs > ASSEMBLY_TIMEOUT_MS) resetAssembly(candidate);
        if (candidate.active && memcmp(candidate.from, source, 6) == 0 &&
            candidate.message_id == packet.message_id) {
            return candidate.expected_parts == packet.split_size ? &candidate : nullptr;
        }
        if (!candidate.active && available == nullptr) available = &candidate;
    }
    if (available == nullptr) return nullptr;
    resetAssembly(*available);
    available->active = true;
    memcpy(available->from, source, 6);
    available->message_id = packet.message_id;
    available->expected_parts = packet.split_size;
    available->lastPacketMs = now;
    return available;
}

}
