#include <stdint.h>
#pragma once

enum PacketType : uint8_t {
    P_BOARD_ONLINE,
    P_MSG_ACK,
    P_MSG,
    P_MSG_FWD,
    P_INIT_EXCH,
    P_ACK_EXCH,
    P_AES_EXCH,
    P_EXCH_OK
};