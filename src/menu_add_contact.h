#pragma once

#include "menus.h"
#include "gui_handlers.h"
#include "json_management.h"
#include <M5Cardputer.h>
#include <ArduinoJson.h>

extern MenuState currentMenu;

void drawAddContact() {
    //Add
}

void handleAddContactInput(int key) {
    if (key == KEY_BACKSPACE) {
        currentMenu = MENU_CONTACTS;
    }
}