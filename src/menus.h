#pragma once

//Used for menu navigation states -> so input isnt dumb and can be expanded later
enum MenuState {
    MENU_MAIN,
    MENU_CONTACTS,
    MENU_MESSAGE,
    MENU_NETWORK,
    MENU_SETTINGS
};


//function for drawLogic and inputLogic pointers
typedef void (*DrawFunc)();
typedef void (*InputFunc)(int key);
struct MenuHandler {
    DrawFunc draw;
    InputFunc handleInput;
};

extern MenuState currentMenu;