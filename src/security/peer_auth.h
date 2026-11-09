#pragma once

#include "security/message_crypto.h"
#include "types.h"

namespace PeerAuth {

constexpr size_t BODY_LEN = 83;
constexpr size_t FRAME_LEN = PEER_HANDSHAKE_FRAME_LEN;
static_assert(FRAME_LEN == BODY_LEN + 32 && FRAME_LEN <= MSG_CHUNK_SIZE, "Handshake frame size mismatch");
constexpr unsigned long TIMEOUT_MS = 30000;
constexpr unsigned long PAIRING_WINDOW_MS = 60000;
constexpr uint8_t AUTHENTICATED = 1;
constexpr char AUTH_CONTEXT[] = "M5PAGER_PEER_AUTH_V5";

struct Frame {
    uint8_t bytes[FRAME_LEN]{};
    uint8_t* publicKey() { return bytes + 3; }
    const uint8_t* publicKey() const { return bytes + 3; }
    const uint8_t* ephemeral() const { return bytes + 35; }
    const uint8_t* tag() const { return bytes + BODY_LEN; }
};

inline bool create(Frame& frame, uint8_t privateKey[32]) {
    frame = Frame{};
    frame.bytes[0] = 'K';
    frame.bytes[1] = '5';
    esp_fill_random(frame.bytes + 67, 16);
    return MessageCrypto::getOwnPublicKey(frame.publicKey()) &&
           MessageCrypto::generateEphemeralKeypair(privateKey, frame.bytes + 35) &&
           !MessageCrypto::isAllZero(frame.bytes + 67, 16);
}

inline bool parse(const MessageStruct& packet, Frame& frame) {
    if (packet.data_len != FRAME_LEN || packet.split_size != 1 || packet.split_index != 0 ||
        (packet.message_id & MESSAGE_ID_CONTROL_FLAG) == 0) return false;
    memcpy(frame.bytes, packet.msg, FRAME_LEN);
    return frame.bytes[0] == 'K' && frame.bytes[1] == '5' && frame.bytes[2] <= AUTHENTICATED &&
           !MessageCrypto::isAllZero(frame.publicKey(), 32) &&
           !MessageCrypto::isAllZero(frame.ephemeral(), 32) &&
           !MessageCrypto::isAllZero(frame.bytes + 67, 16);
}

inline bool computeTag(const Frame& frame, const uint8_t peerPublic[32],
                       const uint8_t source[6], const uint8_t destination[6], uint16_t identifier,
                       PacketType type, const Frame* offer, uint8_t output[32]) {
    uint8_t shared[32]{};
    uint8_t key[32]{};
    uint8_t transcript[6 + 6 + 2 + 1 + BODY_LEN + FRAME_LEN]{};
    size_t length = 0;
    memcpy(transcript + length, source, 6); length += 6;
    memcpy(transcript + length, destination, 6); length += 6;
    transcript[length++] = static_cast<uint8_t>(identifier);
    transcript[length++] = static_cast<uint8_t>(identifier >> 8);
    transcript[length++] = static_cast<uint8_t>(type);
    memcpy(transcript + length, frame.bytes, BODY_LEN); length += BODY_LEN;
    if (offer != nullptr) { memcpy(transcript + length, offer->bytes, FRAME_LEN); length += FRAME_LEN; }
    bool valid = MessageCrypto::computeSharedSecret(peerPublic, shared) &&
                 MessageCrypto::hmacSha256(reinterpret_cast<const uint8_t*>(AUTH_CONTEXT),
                                          sizeof(AUTH_CONTEXT) - 1, shared, sizeof(shared), key) &&
                 MessageCrypto::hmacSha256(key, sizeof(key), transcript, length, output);
    Security::secureZero(shared, sizeof(shared));
    Security::secureZero(key, sizeof(key));
    return valid;
}

inline bool sign(Frame& frame, const uint8_t peerPublic[32], const uint8_t source[6],
                 const uint8_t destination[6], uint16_t identifier, PacketType type, const Frame* offer = nullptr) {
    frame.bytes[2] = AUTHENTICATED;
    return computeTag(frame, peerPublic, source, destination, identifier, type, offer, frame.bytes + BODY_LEN);
}

inline bool verify(const Frame& frame, const uint8_t source[6], const uint8_t destination[6],
                   uint16_t identifier, PacketType type, const Frame* offer = nullptr) {
    if (frame.bytes[2] != AUTHENTICATED) return false;
    uint8_t expected[32]{};
    const bool valid = computeTag(frame, frame.publicKey(), source, destination, identifier, type, offer, expected) &&
                       MessageCrypto::equalBytes(expected, frame.tag(), sizeof(expected));
    Security::secureZero(expected, sizeof(expected));
    return valid;
}

struct Pending {
    bool active = false;
    bool initiator = false;
    bool completed = false;
    uint16_t identifier = 0;
    uint8_t peer[6]{};
    uint8_t ephemeralPrivate[32]{};
    String contact;
    Frame offer;
    Frame reply;
    unsigned long started = 0;
    unsigned long lastSent = 0;
    uint8_t attempts = 0;

    void clear() {
        Security::secureZero(ephemeralPrivate, sizeof(ephemeralPrivate));
        active = false;
        initiator = false;
        completed = false;
        identifier = 0;
        memset(peer, 0, sizeof(peer));
        contact = "";
        offer = Frame{};
        reply = Frame{};
        started = 0;
        lastSent = 0;
        attempts = 0;
    }
};

struct Budget {
    unsigned long window = 0;
    uint8_t count = 0;

    bool allow(unsigned long now, uint8_t limit) {
        if (now - window >= 1000) { window = now; count = 0; }
        if (count >= limit) return false;
        count++;
        return true;
    }
};

}
