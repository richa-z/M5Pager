#pragma once

#include "transport/mesh.h"

namespace Discovery {

constexpr size_t MAX_NEARBY = 8;
constexpr size_t NAME_LEN = 20;
constexpr unsigned long EXPIRY_MS = 30000;
constexpr unsigned long INTERVAL_MS = 8000;
constexpr char PREFIX[] = "M5D1:";

struct Peer {
    bool active = false;
    uint8_t mac[6]{};
    char name[NAME_LEN + 1]{};
    unsigned long lastSeen = 0;
};

struct State {
    Peer peers[MAX_NEARBY]{};

    void expire(unsigned long now) {
        for (auto& peer : peers) if (peer.active && now - peer.lastSeen > EXPIRY_MS) peer = Peer{};
    }

    size_t count() const {
        size_t total = 0;
        for (const auto& peer : peers) if (peer.active) total++;
        return total;
    }

    const Peer* at(size_t selected) const {
        for (const auto& peer : peers) {
            if (!peer.active) continue;
            if (selected == 0) return &peer;
            selected--;
        }
        return nullptr;
    }

    bool observe(const uint8_t* source, const MessageStruct& packet, unsigned long now) {
        constexpr size_t prefixLength = sizeof(PREFIX) - 1;
        if (!Mesh::unicast(source) || packet.type != P_BOARD_ONLINE || packet.split_size != 1 || packet.split_index != 0 ||
            packet.data_len <= prefixLength || packet.data_len > prefixLength + NAME_LEN ||
            memcmp(packet.msg, PREFIX, prefixLength) != 0) return false;
        for (size_t index = prefixLength; index < packet.data_len; index++) {
            if (packet.msg[index] < 32 || packet.msg[index] > 126) return false;
        }
        expire(now);
        Peer* selected = nullptr;
        for (auto& peer : peers) {
            if (peer.active && memcmp(peer.mac, source, 6) == 0) { selected = &peer; break; }
            if (!peer.active && selected == nullptr) selected = &peer;
        }
        if (selected == nullptr) return false;
        selected->active = true;
        memcpy(selected->mac, source, 6);
        memset(selected->name, 0, sizeof(selected->name));
        memcpy(selected->name, packet.msg + prefixLength, packet.data_len - prefixLength);
        selected->lastSeen = now;
        return true;
    }
};

}
