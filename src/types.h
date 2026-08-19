#pragma once

#define MSG_CHUNK_SIZE 180

#include <stdint.h>
#include <string.h>
#include <String.h>
#include "enums/packet_types.h"

#define PROTO_VERSION 3

#define PACKET_HEADER_LEN 13
#define PACKET_MAX_LEN (PACKET_HEADER_LEN + MSG_CHUNK_SIZE)

typedef struct MessageStruct {
  PacketType type;

  uint8_t from[6];

  uint16_t message_id;
  uint8_t split_size;
  uint8_t split_index;

  uint8_t data_len;
  char msg[MSG_CHUNK_SIZE];
} MessageStruct;

/// @brief Serializuje paket do bajtového poľa v pevne danom formáte.
/// @param pkt Paket na serializáciu
/// @param out Výstupné pole, musí mať aspoň PACKET_MAX_LEN bajtov
/// @return Počet zapísaných bajtov, alebo 0 pri neplatnom pakete
inline size_t serializePacket(const MessageStruct& pkt, uint8_t* out) {
    if (out == nullptr || pkt.data_len > MSG_CHUNK_SIZE) return 0;

    out[0] = PROTO_VERSION;
    out[1] = static_cast<uint8_t>(pkt.type);
    memcpy(out + 2, pkt.from, 6);
    out[8] = static_cast<uint8_t>(pkt.message_id & 0xFF);
    out[9] = static_cast<uint8_t>((pkt.message_id >> 8) & 0xFF);
    out[10] = pkt.split_size;
    out[11] = pkt.split_index;
    out[12] = pkt.data_len;

    if (pkt.data_len > 0) {
        memcpy(out + PACKET_HEADER_LEN, pkt.msg, pkt.data_len);
    }
    return PACKET_HEADER_LEN + pkt.data_len;
}

/// @brief Rozloží prijaté bajty na paket a overí, že sú vnútorne konzistentné.
/// @param data Prijaté bajty
/// @param len Dĺžka prijatých bajtov
/// @param out Výstupný paket
/// @return TRUE, ak bol paket platný a rozložený, inak FALSE
inline bool deserializePacket(const uint8_t* data, int len, MessageStruct& out) {
    if (data == nullptr) return false;
    if (len < PACKET_HEADER_LEN || len > PACKET_MAX_LEN) return false;
    if (data[0] != PROTO_VERSION) return false;

    memset(&out, 0, sizeof(out));
    out.type = static_cast<PacketType>(data[1]);
    memcpy(out.from, data + 2, 6);
    out.message_id = static_cast<uint16_t>(data[8]) |
                     (static_cast<uint16_t>(data[9]) << 8);
    out.split_size = data[10];
    out.split_index = data[11];
    out.data_len = data[12];

    if (out.data_len > MSG_CHUNK_SIZE) return false;
    if (static_cast<int>(out.data_len) > len - PACKET_HEADER_LEN) return false;

    if (out.data_len > 0) {
        memcpy(out.msg, data + PACKET_HEADER_LEN, out.data_len);
    }
    return true;
}

#define MAX_MESSAGE_PARTS 8

#define MAX_MESSAGE_TEXT_LEN 180

#define ASSEMBLY_TIMEOUT_MS 5000

#define MESSAGE_ID_CONTROL_FLAG 0x8000
#define MESSAGE_ID_VALUE_MASK   0x7FFF

typedef struct IncomingAssembly {
    bool active;
    uint8_t from[6];
    uint16_t message_id;
    uint8_t expected_parts;
    bool received[MAX_MESSAGE_PARTS];

    uint8_t partLen[MAX_MESSAGE_PARTS];
    char data[MAX_MESSAGE_PARTS * MSG_CHUNK_SIZE];

    unsigned long lastPacketMs;
} IncomingAssembly;

/// @brief Vynuluje stav zostavovania správy.
/// @param assembly Stav zostavovania
inline void resetAssembly(IncomingAssembly& assembly) {
    memset(&assembly, 0, sizeof(assembly));
}

typedef struct RxQueueItem {
    uint8_t mac[6];
    MessageStruct pkt;
} RxQueueItem;