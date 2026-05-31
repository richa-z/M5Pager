#include <stdint.h>
#pragma once

enum PacketType : uint8_t {
    P_BOARD_ONLINE, //do buducna
    P_MSG_ACK, //ACK pre správy
    P_MSG, //správa, rozdelená na viac paketov ak je dlhšia než MSG_CHUNK_SIZE
    P_MSG_FWD, //do buducna
    P_INIT_EXCH, //key exchange init
    P_ACK_EXCH, //key exchange ACK
    P_EXCH_OK //key exchange dokončený
};