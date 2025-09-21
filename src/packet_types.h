#include <stdint.h>
#pragma once

enum PacketType : uint8_t {
    P_BOARD_ONLINE,
    P_MSG_ACK,
    P_MSG,
    P_KEY_EXCHANGE,
    P_ACK_KEY_EXCHANGE,
    P_AES_KEY
};