#pragma once

//slúži na označenie stavov navigácie v ponuke -> takže vstup nie je obmedzený a dá sa neskôr rozšíriť
//POZOR: poradie musí presne sedieť s poľom menus[] v m5pager.ino
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


//definícia menu handleru, ktorý obsahuje funkciu pre vykreslenie menu a funkciu pre spracovanie vstupu v danom menu
typedef void (*DrawFunc)();
typedef void (*InputFunc)(int key);
struct MenuHandler {
    DrawFunc draw;
    InputFunc handleInput;
};

extern MenuState currentMenu;