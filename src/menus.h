#pragma once

//used for menu navigation states -> so input isnt dumb and can be expanded later
enum MenuState {
    MENU_MAIN,
    MENU_CONTACTS,
    MENU_MESSAGE,
    MENU_SETTINGS,
    MENU_CHANGE_USERNAME,
    MENU_ADD_CONTACT,
    MENU_CONTACT_OPTIONS,
    MENU_EDIT_CONTACT
};


//function for drawLogic and inputLogic pointers
typedef void (*DrawFunc)();
typedef void (*InputFunc)(int key);
struct MenuHandler {
    DrawFunc draw;
    InputFunc handleInput;
};

extern MenuState currentMenu;