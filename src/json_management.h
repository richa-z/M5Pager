#pragma once

#include <SD.h>
#include <ArduinoJson.h>
#include <M5Cardputer.h>

#include "util/util.h"

bool loadContacts(DynamicJsonDocument &contacts, const char* filename) {
    M5Cardputer.Display.println("[*] Loading contacts...");

    if (!fileExists("/m5pager")) SD.mkdir("/m5pager");

    if (!fileExists(filename)) {
        M5Cardputer.Display.println("[*] Contacts file not found. Creating empty file...");
        File file = SD.open(filename, FILE_WRITE);
        if (file) {
            file.print("{}");
            file.close();
        }
        return false;
    }
    M5Cardputer.Display.println("[*] Contacts file found. Reading...");

    File file = SD.open(filename, FILE_READ);
    if (!file) {
        M5Cardputer.Display.println("[-] Failed to open contacts file.");
        return false;
    }

    if (file.size() == 0) {
        file.close();
        M5Cardputer.Display.println("[*] Contacts file empty.");
        return true;
    }

    DeserializationError error = deserializeJson(contacts, file);
    file.close();
    if (error) {
        M5Cardputer.Display.print("[-] JSON parse error: ");
        M5Cardputer.Display.println(error.c_str());
        return false;
    }
    return true;
}


bool saveContacts(const DynamicJsonDocument &contacts, const char* filename) {
    File file = SD.open(filename, FILE_WRITE);
    if (!file) {
        M5Cardputer.Display.println("[-] Failed to open contacts file for writing.");
        return false;
    }

    if (serializeJsonPretty(contacts, file) == 0) {
        M5Cardputer.Display.println("[-] Failed to write to contacts file.");
        file.close();
        return false;
    }

    file.close();
    return true;
}

bool loadConfig(DynamicJsonDocument &config, const char* filename) {
    M5Cardputer.Display.println("[*] Loading config...");

    if (!fileExists("/m5pager")) SD.mkdir("/m5pager");

    if (!fileExists(filename)) {
        M5Cardputer.Display.println("[*] Config file not found. Creating default file...");
        File file = SD.open(filename, FILE_WRITE);
        if (file) {
            file.print("{\"username\":\"User\"}");
            file.close();
        }

        DeserializationError error = deserializeJson(config, file);
        if (error) {
            M5Cardputer.Display.print("[-] JSON parse error: ");
            M5Cardputer.Display.println(error.c_str());
            return false;
        }
        return true;
    }
    M5Cardputer.Display.println("[*] Config file found. Reading...");

    File file = SD.open(filename, FILE_READ);
    if (!file) {
        M5Cardputer.Display.println("[-] Failed to open config file.");
        return false;
    }

    if (file.size() == 0) {
        file.close();
        M5Cardputer.Display.println("[*] Config file empty.");
        return true;
    }

    DeserializationError error = deserializeJson(config, file);
    file.close();
    if (error) {
        M5Cardputer.Display.print("[-] JSON parse error: ");
        M5Cardputer.Display.println(error.c_str());
        return false;
    }
    return true;
}

bool saveConfig(const DynamicJsonDocument &config, const char* filename) {
    File file = SD.open(filename, FILE_WRITE);
    if (!file) {
        M5Cardputer.Display.println("[-] Failed to open config file for writing.");
        return false;
    }

    if (serializeJsonPretty(config, file) == 0) {
        M5Cardputer.Display.println("[-] Failed to write to config file.");
        file.close();
        return false;
    }

    file.close();
    return true;
}

//TODO: add functions to add, remove, edit contacts in the DynamicJsonDocument
//TODO: add function to load message history from file (also unload to save memory on leave)
