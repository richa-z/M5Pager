#pragma once

#define MSG_CHUNK_SIZE 180

#include <stdint.h>
#include <String.h>
#include "enums/packet_types.h"

typedef struct MessageStruct {
  PacketType type;
  uint8_t from[6];

  uint16_t message_id;
  uint8_t split_size;
  uint8_t split_index;

  uint8_t data_len;
  char msg[MSG_CHUNK_SIZE];
} MessageStruct;

typedef struct IncomingAssembly {
    uint16_t message_id;
    uint8_t expected_parts;
    bool received[32];
    String data;
} IncomingAssembly;