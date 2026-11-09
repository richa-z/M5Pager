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
    MENU_CHANGE_SSID_PASS,
    MENU_NETWORK,
    MENU_NEARBY,
    MENU_VERIFY_PEER,
    MENU_GROUPS,
    MENU_GROUP_CREATE,
    MENU_GROUP_CHAT,
    MENU_GROUP_MANAGE,
    MENU_GROUP_ADD,
    MENU_GROUP_ACTIONS,
    MENU_GROUP_DELIVERY,
    MENU_GROUP_RENAME,
    MENU_GROUP_INFO,
    MENU_GROUP_MEMBER
};


typedef void (*DrawFunc)();
typedef void (*InputFunc)(int key);
struct MenuHandler {
    DrawFunc draw;
    InputFunc handleInput;
};

extern MenuState currentMenu;
