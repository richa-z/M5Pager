#pragma once
#include <M5Cardputer.h>
#include <String.h>

/// @brief Spracuje vstup textu z klávesnice.
/// @param key Stlačený kľúč
/// @param target Premenna, do ktorej sa bude ukladať text
/// @param maxLen Maximálna dĺžka reťazca
/// @return TRUE, ak bol vstup spracovaný, inak FALSE
inline bool handleTextInput(int key, String& target, size_t maxLen = 0) {
    if (key == KEY_BACKSPACE) {
        if (target.length() > 0) {
            target.remove(target.length() - 1);
            return true;
        }
        return false;
    }

    //len ASCII
    if (key < 32 || key > 126) {
        return false;
    }

    if (maxLen > 0 && target.length() >= maxLen) {
        return false;
    }

    target += (char)key;
    return true;
}