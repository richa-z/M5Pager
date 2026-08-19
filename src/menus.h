#pragma once

enum MenuState {
    MENU_MAIN,
    MENU_CONTACTS,
    MENU_MESSAGE,
    MENU_SETTINGS,
    MENU_CHANGE_USERNAME,
    MENU_ADD_CONTACT,
    MENU_CONTACT_OPTIONS,
    MENU_EDIT_CONTACT,
    MENU_CHANGE_SSID,
    MENU_CHANGE_SSID_PASS
};


typedef void (*DrawFunc)();
typedef void (*InputFunc)(int key);
struct MenuHandler {
    DrawFunc draw;
    InputFunc handleInput;
};

extern MenuState currentMenu;