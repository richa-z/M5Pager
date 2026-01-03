#pragma once

#include <Arduino.h>
#include <M5Cardputer.h>
#include <String.h>

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