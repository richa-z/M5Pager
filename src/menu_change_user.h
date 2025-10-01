#pragma once

#include "menus.h"
#include "gui_handlers.h"
#include <M5Cardputer.h>
#include <ArduinoJson.h>
#include <json_management.h>

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
        currentMenu = MENU_SETTINGS;
        return;
    } else if (key == KEY_BACKSPACE) {
        if (newUsername.length() > 0) {
            newUsername.remove(newUsername.length() - 1);
        }
        drawChangeUsername();
    } else if (key == KEY_ENTER) {
        if (newUsername.length() == 0) {
            //do nothing
            return;
        }
        //save new username to config
        config["username"] = newUsername.c_str();
        if (!saveConfig(config, "/m5pager/config.json")) {
            M5Cardputer.Display.println("[-] Failed to save config.");
        } else {
            M5Cardputer.Display.println("[+] Config saved.");
        }
        menuIndex = 0;
        user = newUsername.c_str();
        newUsername = "";
        currentMenu = MENU_SETTINGS;
        return;
    } else if (newUsername.length() < 20) { 
        newUsername += (char)key;
        drawChangeUsername();
    } 

    
}