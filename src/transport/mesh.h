#pragma once

#include "types.h"
#include <mbedtls/md.h>

namespace Mesh {

constexpr uint8_t MAGIC[4] = {'M', '5', 'R', '1'};
constexpr uint8_t BROADCAST[6] = {255, 255, 255, 255, 255, 255};
constexpr size_t HEADER_LEN = 26;
constexpr size_t MAX_WIRE_LEN = HEADER_LEN + PACKET_MAX_LEN;
constexpr uint8_t MAX_HOPS = 4;
constexpr size_t CACHE_SIZE = 64;
constexpr unsigned long CACHE_LIFETIME_MS = 15000;
constexpr uint8_t FRAMES_PER_SECOND = 32;

inline bool unicast(const uint8_t* address) {
    if (address == nullptr || (address[0] & 1) != 0) return false;
    uint8_t combined = 0;
    for (size_t index = 0; index < 6; index++) combined |= address[index];
    return combined != 0;
}

inline bool supported(PacketType type) {
    return type == P_MSG || type == P_MSG_ACK || type == P_INIT_EXCH || type == P_ACK_EXCH || type == P_EXCH_OK;
}

inline bool validPacketShape(const MessageStruct& packet) {
    if (packet.message_id == 0 || packet.split_size == 0 || packet.split_index >= packet.split_size) return false;
    if (packet.type == P_MSG) {
        return (packet.message_id & MESSAGE_ID_CONTROL_FLAG) == 0 && packet.split_size <= MAX_MESSAGE_PARTS &&
               packet.data_len != 0 && (packet.split_index + 1 == packet.split_size || packet.data_len == MSG_CHUNK_SIZE);
    }
    if (packet.split_size != 1 || packet.split_index != 0) return false;
    if (packet.type == P_MSG_ACK) return (packet.message_id & MESSAGE_ID_CONTROL_FLAG) == 0 && packet.data_len == 64;
    if ((packet.message_id & MESSAGE_ID_CONTROL_FLAG) == 0) return false;
    if (packet.type == P_EXCH_OK) return packet.data_len == 32;
    return (packet.type == P_INIT_EXCH || packet.type == P_ACK_EXCH) &&
           packet.data_len == PEER_HANDSHAKE_FRAME_LEN && packet.msg[0] == 'K' && packet.msg[1] == '5';
}

struct Frame {
    uint8_t remaining = MAX_HOPS;
    uint8_t nonce[8]{};
    uint8_t origin[6]{};
    uint8_t destination[6]{};
    MessageStruct packet{};
};

inline bool matches(const uint8_t* wire, size_t length) {
    return wire != nullptr && length >= sizeof(MAGIC) && memcmp(wire, MAGIC, sizeof(MAGIC)) == 0;
}

inline size_t encode(const Frame& frame, uint8_t* wire) {
    if (wire == nullptr || frame.remaining == 0 || frame.remaining > MAX_HOPS ||
        !unicast(frame.origin) || !unicast(frame.destination) ||
        memcmp(frame.origin, frame.destination, 6) == 0 || !validPacketShape(frame.packet) ||
        memcmp(frame.origin, frame.packet.from, 6) != 0 || !supported(frame.packet.type)) return 0;
    const size_t innerLength = serializePacket(frame.packet, wire + HEADER_LEN);
    if (innerLength == 0) return 0;
    memcpy(wire, MAGIC, sizeof(MAGIC));
    wire[4] = frame.remaining;
    memcpy(wire + 5, frame.nonce, 8);
    memcpy(wire + 13, frame.origin, 6);
    memcpy(wire + 19, frame.destination, 6);
    wire[25] = static_cast<uint8_t>(innerLength);
    return HEADER_LEN + innerLength;
}

inline bool decode(const uint8_t* wire, size_t length, Frame& frame) {
    if (!matches(wire, length) || length < HEADER_LEN + PACKET_HEADER_LEN || length > MAX_WIRE_LEN ||
        wire[4] == 0 || wire[4] > MAX_HOPS || wire[25] != length - HEADER_LEN) return false;
    frame.remaining = wire[4];
    memcpy(frame.nonce, wire + 5, 8);
    memcpy(frame.origin, wire + 13, 6);
    memcpy(frame.destination, wire + 19, 6);
    return unicast(frame.origin) && unicast(frame.destination) &&
           memcmp(frame.origin, frame.destination, 6) != 0 &&
           deserializePacket(wire + HEADER_LEN, static_cast<int>(length - HEADER_LEN), frame.packet) &&
           memcmp(frame.origin, frame.packet.from, 6) == 0 && supported(frame.packet.type) && validPacketShape(frame.packet);
}

struct Seen {
    bool active = false;
    uint8_t digest[32]{};
    unsigned long received = 0;
};

enum class Admission { Fresh, Duplicate, Full, Invalid };

struct State {
    Seen seen[CACHE_SIZE]{};
    unsigned long rateWindow = 0;
    uint8_t windowCount = 0;
    uint32_t forwarded = 0;
    uint32_t delivered = 0;
    uint32_t duplicates = 0;
    uint32_t expired = 0;
    uint32_t rejected = 0;
    uint32_t limited = 0;

    Admission remember(const uint8_t* wire, size_t length, unsigned long now) {
        if (wire == nullptr || length > MAX_WIRE_LEN || length < HEADER_LEN) return Admission::Invalid;
        uint8_t normalized[MAX_WIRE_LEN];
        memcpy(normalized, wire, length);
        normalized[4] = 0;
        uint8_t digest[32];
        if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), normalized, length, digest) != 0) return Admission::Invalid;
        Seen* available = nullptr;
        for (auto& entry : seen) {
            if (entry.active && now - entry.received > CACHE_LIFETIME_MS) entry.active = false;
            if (entry.active && memcmp(entry.digest, digest, sizeof(digest)) == 0) return Admission::Duplicate;
            if (!entry.active && available == nullptr) available = &entry;
        }
        if (available == nullptr) return Admission::Full;
        available->active = true;
        available->received = now;
        memcpy(available->digest, digest, sizeof(digest));
        return Admission::Fresh;
    }

    bool allow(unsigned long now) {
        if (now - rateWindow >= 1000) { rateWindow = now; windowCount = 0; }
        if (windowCount >= FRAMES_PER_SECOND) return false;
        windowCount++;
        return true;
    }
};

}
