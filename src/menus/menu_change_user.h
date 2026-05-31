#pragma once

#include "menus.h"
#include "gui_handlers.h"
#include <M5Cardputer.h>
#include <ArduinoJson.h>
#include <json_management.h>
#include "util/text_input.h"

extern MenuState currentMenu;
extern DynamicJsonDocument config;
extern int menuIndex;
extern const char* user;
String newUsername = "";

void drawChangeUsername() {
    changeUsername(newUsername);
}

void handleChangeUsernameInput(int key) {
    if (key == '`') {
        menuIndex = 0;
        newUsername = "";
        currentMenu = MENU_SETTINGS;
        return;
    } else if (key == KEY_ENTER) {
        if (newUsername.length() == 0) {
            return;
        }

        config["username"] = newUsername.c_str();
        if (!saveConfig(config, "/m5pager/config.json")) {
            drawChangeUsername();
            showErrorToast("Failed to save config");
            return;
        } else {
            drawChangeUsername();
            showSuccessToast("Username saved", 700);
        }
        menuIndex = 0;
        user = newUsername.c_str();
        newUsername = "";
        currentMenu = MENU_SETTINGS;
        return;
    }

    if (handleTextInput(key, newUsername, 20)) {
        drawChangeUsername();
    }
}
