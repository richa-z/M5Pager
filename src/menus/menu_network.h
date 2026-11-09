#pragma once

#include "gui_handlers.h"
#include "transport/discovery.h"

extern bool discoveryEnabled;
extern bool meshEnabled;
extern Discovery::State nearby;
extern int menuIndex;
bool setNetworkPreference(bool discovery, bool enabled);
bool enrollNearby(size_t selected);

void drawNetworkMenu() {
    beginScreenFrame();
    drawSectionTitle("NETWORK / PRIVACY");
    drawCardRow(String("Discovery: ") + (discoveryEnabled ? "ON" : "OFF"), 0, menuIndex == 0);
    drawCardRow(String("Mesh / relay: ") + (meshEnabled ? "ON" : "OFF"), 1, menuIndex == 1);
    drawCardRow("Nearby pagers (unverified)", 2, menuIndex == 2);
    drawCardRow("Back", 3, menuIndex == 3);
    drawHintLine("Beacons are public. Verify peers.", 121);
}

void drawNearbyMenu() {
    beginScreenFrame();
    drawSectionTitle("NEARBY / UNVERIFIED");
    const size_t total = nearby.count();
    if (total == 0) {
        menuIndex = 0;
        drawHintLine(discoveryEnabled ? "Listening for one-hop beacons..." : "Enable Discovery in Network first", 42);
    } else {
        if (menuIndex >= static_cast<int>(total)) menuIndex = 0;
        const size_t first = static_cast<size_t>(menuIndex / 2) * 2;
        for (size_t offset = 0; offset < 2 && first + offset < total; offset++) {
            const auto* peer = nearby.at(first + offset);
            const int top = UI_CONTENT_TOP_Y + 14 + static_cast<int>(offset) * 38;
            drawCardRow(String(peer->name), 0, static_cast<int>(first + offset) == menuIndex, top);
            drawHintLine(macToString(peer->mac), top + 20);
        }
    }
    drawHintLine("Enter: add peer | Backspace: back", 121);
}

void handleNetworkInput(int key) {
    if (key == KEY_BACKSPACE) { menuIndex = 0; currentMenu = MENU_MAIN; return; }
    if (key == ';') menuIndex = (menuIndex + 3) % 4;
    else if (key == '.') menuIndex = (menuIndex + 1) % 4;
    else if (key == KEY_ENTER) {
        if (menuIndex < 2) {
            const bool discovery = menuIndex == 0;
            if (!setNetworkPreference(discovery, !(discovery ? discoveryEnabled : meshEnabled))) showErrorToast("Could not save network setting");
        } else {
            currentMenu = menuIndex == 2 ? MENU_NEARBY : MENU_MAIN;
            menuIndex = 0;
            return;
        }
    }
    drawNetworkMenu();
}

void handleNearbyInput(int key) {
    if (key == KEY_BACKSPACE) { menuIndex = 0; currentMenu = MENU_NETWORK; return; }
    const int total = static_cast<int>(nearby.count());
    if (total == 0) return;
    if (key == ';') menuIndex = (menuIndex + total - 1) % total;
    else if (key == '.') menuIndex = (menuIndex + 1) % total;
    else if (key == KEY_ENTER) {
        if (enrollNearby(static_cast<size_t>(menuIndex))) { menuIndex = 0; currentMenu = MENU_MESSAGE; return; }
        showErrorToast("Could not save discovered peer");
    }
    drawNearbyMenu();
}
