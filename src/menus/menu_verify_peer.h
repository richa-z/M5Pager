#pragma once

#include "gui_handlers.h"
#include "security/message_crypto.h"

extern DynamicJsonDocument contacts;
extern String selectedContact;
extern String verificationSnapshot;
extern bool verificationConfirm;
extern MenuState verificationReturnMenu;
bool armPeerPairing(const String& contact);
bool pairingAllowed(const String& contact);
bool requestKeyExchange(const char* contactMac);
bool verifyPeerIdentity(const String& contact, const String& displayedFingerprint);

void drawPeerVerification() {
    beginScreenFrame();
    drawSectionTitle("VERIFY PEER OUTSIDE MESH");
    const String fingerprint = MessageCrypto::getSessionFingerprint(contacts, selectedContact);
    if (verificationSnapshot != fingerprint) {
        verificationSnapshot = fingerprint;
        verificationConfirm = false;
    }
    const bool modern = (contacts[selectedContact]["keys"]["handshake_version"] | 0) == 5;
    if (fingerprint.length() == MessageCrypto::FINGERPRINT_BYTES * 2 && modern) {
        drawHintLine(fingerprint.substring(0, 16), 34, uiTextPrimaryColor());
        drawHintLine(fingerprint.substring(16), 47, uiTextPrimaryColor());
        drawHintLine("Compare BOTH lines in person or", 65);
        drawHintLine("over an independently trusted call.", 77);
        drawHintLine(MessageCrypto::hasVerifiedSession(contacts, selectedContact) ? "Identity pinned / verified" :
            (verificationConfirm ? "Enter: confirm BOTH lines match" : "Y: I compared BOTH lines"), 94);
    } else {
        drawHintLine("No v5 fingerprint. Do NOT send yet.", 38);
        drawHintLine("On the OTHER pager, press P here.", 56);
        drawHintLine("Then press E here to exchange keys.", 71);
    }
    drawHintLine(pairingAllowed(selectedContact) ? "Incoming pairing allowed for 60s" : "P: allow incoming | E: exchange", 109);
    drawHintLine("Backspace: back. Mismatch? STOP.", 122);
}

void handlePeerVerification(int key) {
    if (key == KEY_BACKSPACE) {
        verificationConfirm = false;
        verificationSnapshot = "";
        currentMenu = verificationReturnMenu;
        verificationReturnMenu = MENU_MESSAGE;
        return;
    }
    if (key == 'p' || key == 'P') {
        verificationConfirm = false;
        if (!armPeerPairing(selectedContact)) showErrorToast("An exchange or send is pending");
    } else if (key == 'e' || key == 'E') {
        verificationConfirm = false;
        if (!requestKeyExchange(selectedContact.c_str())) showErrorToast("Exchange busy or could not start");
    } else if (key == 'y' || key == 'Y') {
        if (verificationSnapshot.length() == MessageCrypto::FINGERPRINT_BYTES * 2 &&
            (contacts[selectedContact]["keys"]["handshake_version"] | 0) == 5) verificationConfirm = true;
    } else if (key == KEY_ENTER && verificationConfirm) {
        verificationConfirm = false;
        if (!verifyPeerIdentity(selectedContact, verificationSnapshot)) {
            showErrorToast("Identity not saved; compare again");
        } else {
            showSuccessToast("Peer identity pinned", 1000);
            currentMenu = verificationReturnMenu;
            verificationReturnMenu = MENU_MESSAGE;
            return;
        }
    }
    drawPeerVerification();
}
