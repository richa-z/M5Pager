#pragma once

#include "gui_handlers.h"
#include "menus.h"
#include "security/group_store.h"
#include "util/text_input.h"

extern Groups::Document groups;
extern DynamicJsonDocument contacts;
extern String selectedGroup, groupInput, groupConfirm, groupActionMac, selectedContact;
extern uint32_t groupActionEpoch, groupComposeEpoch;
extern bool groupReviewRequired;
extern bool isTypingGroup, awaitingAck, groupStorageFault;
extern int groupScroll, menuIndex;
extern MenuState verificationReturnMenu;

bool groupTransferBusy();
bool groupMutationBusy();
bool ownerGroupReady(JsonObject);
bool editGroupMember(const String&, const String&, bool, bool);
bool renameGroup(const String&, const String&);
bool syncGroup(const String&);
bool acceptGroup(const String&, bool);
bool leaveGroup(const String&);
bool sendGroupText(const String&, const String&);
bool retryGroupMessage(const String&);
bool pauseGroup(const String&, bool);
bool clearGroupHistory(const String&);
bool forgetGroup(const String&, bool);
void drawGroupActions();

String groupIdAt(int selected) {
    int index = 0;
    for (JsonPair entry : groups.as<JsonObject>()) if (index++ == selected) return entry.key().c_str();
    return "";
}

String groupContactName(const String& mac) {
    if (mac == Groups::ownMac()) return "You";
    const String contact = Groups::contactFor(contacts, mac);
    const String name = contacts[contact]["username"] | "";
    return name.length() == 0 ? mac : name;
}

String groupCandidateAt(int selected) {
    int index = 0;
    JsonObject record = groups[selectedGroup].as<JsonObject>();
    for (JsonPair entry : contacts.as<JsonObject>()) {
        uint8_t address[6];
        if (!parseMacAddress(entry.key().c_str(), address)) continue;
        const String mac = Groups::macString(address);
        if (mac == Groups::ownMac() || Groups::memberPublic(record, mac).length() != 0 ||
            Groups::verifiedPublic(contacts, mac).length() == 0) continue;
        if (index++ == selected) return mac;
    }
    return "";
}

int groupCandidateCount() {
    int count = 0;
    while (groupCandidateAt(count).length() != 0) count++;
    return count;
}

String groupSendProblem(JsonObject record) {
    if (groupStorageFault) return "Storage failure: S sync to retry";
    if (groupMutationBusy()) return "Delivery busy; O actions to pause";
    if (record.containsKey("outbox")) return "T retry / O discard queued message";
    if (record["needs_sync"] | false) return "S request owner's current epoch";
    if (record["members"].size() < 2) return "M then A: add verified members";
    if (!Groups::allPeersVerified(record, contacts)) return "M then V: verify every member";
    if (!ownerGroupReady(record)) return "Waiting for joins; M shows status";
    return "Invalid text or storage save failed";
}

void confirmGroupAction(const String& action, const String& mac = "") {
    groupConfirm = action;
    groupActionMac = mac;
    groupActionEpoch = groups[selectedGroup]["epoch"].as<uint32_t>();
    currentMenu = MENU_GROUP_ACTIONS;
}

void drawGroupsMenu() {
    beginScreenFrame();
    drawSectionTitle("GROUPS / ENCRYPTED");
    const int count = static_cast<int>(groups.size());
    if (count == 0) drawHintLine("No groups. N: create one", 55);
    else {
        if (menuIndex >= count) menuIndex = 0;
        const int first = (menuIndex / 3) * 3;
        for (int index = first; index < count && index < first + 3; index++) {
            JsonObject record = groups[groupIdAt(index)].as<JsonObject>();
            drawCardRow(record["name"].as<String>() + " / " + record["state"].as<String>(), index - first, index == menuIndex);
        }
    }
    drawHintLine("Enter open | N new | Back return", 121);
}

void handleGroupsInput(int key) {
    const int count = static_cast<int>(groups.size());
    if (key == KEY_BACKSPACE) { currentMenu = MENU_MAIN; menuIndex = 0; return; }
    if (key == 'n' || key == 'N') { groupInput = ""; currentMenu = MENU_GROUP_CREATE; return; }
    if (count == 0) return;
    if (key == ';') menuIndex = (menuIndex + count - 1) % count;
    else if (key == '.') menuIndex = (menuIndex + 1) % count;
    else if (key == KEY_ENTER) {
        selectedGroup = groupIdAt(menuIndex);
        groupScroll = 0; isTypingGroup = false; groupConfirm = ""; groupReviewRequired = false;
        currentMenu = MENU_GROUP_CHAT; menuIndex = 0;
        return;
    }
    drawGroupsMenu();
}

void drawGroupCreate() {
    beginScreenFrame();
    drawSectionTitle("CREATE GROUP");
    drawInputCard("Group name (20 chars)", groupInput, "name", 42, 32);
    drawHintLine("Enter create | ` cancel", 121);
}

void handleGroupCreate(int key) {
    if (key == '`') { groupInput = ""; currentMenu = MENU_GROUPS; return; }
    if (key == KEY_ENTER) {
        if (groupMutationBusy() || !Groups::create(groups, groupInput, selectedGroup)) showErrorToast("Busy, invalid name or group limit");
        else {
            groupInput = ""; groupConfirm = ""; menuIndex = 0;
            currentMenu = MENU_GROUP_MANAGE;
            return;
        }
    } else handleTextInput(key, groupInput, 20);
    drawGroupCreate();
}

void refreshGroupDraftState() {
    if (isTypingGroup && (groups[selectedGroup]["epoch"].as<uint32_t>() != groupComposeEpoch ||
        groups[selectedGroup]["state"].as<String>() != "active")) {
        isTypingGroup = false;
        groupInput = "";
        groupReviewRequired = true;
    }
}

void drawGroupChat() {
    refreshGroupDraftState();
    beginScreenFrame();
    JsonObject record = groups[selectedGroup].as<JsonObject>();
    drawSectionTitle(record["name"].as<String>());
    const String state = record["state"] | "";
    drawHintLine(state + " / E" + String(record["epoch"].as<uint32_t>()) +
        (groupStorageFault ? " / SAVE ERROR" : (record.containsKey("outbox") ? " / queued" : "")), 31);

    if (groupReviewRequired) {
        drawHintLine("Membership changed while typing.", 52);
        drawHintLine("Draft discarded. Inspect the roster.", 69);
        drawHintLine("Enter review members | Back", 121);
        return;
    }
    if (state == "invited") {
        drawHintLine("Invitation from:", 52);
        drawHintLine(groupContactName(record["owner"].as<String>()), 65);
        drawHintLine(record["owner"].as<String>(), 78);
        drawHintLine("M inspect roster | O actions", 100);
        drawHintLine("Y accept | N decline | Back", 121);
        return;
    }
    if (isTypingGroup) {
        drawHintLine(String(static_cast<unsigned int>(groupInput.length())) + "/120 characters", 48);
        for (int row = 0; row < 4; row++) drawHintLine(groupInput.substring(row * 35, (row + 1) * 35), 61 + row * 11);
        drawHintLine("Enter send | ` cancel | BKSP edit", 121);
        return;
    }

    JsonArray history = record["history"].as<JsonArray>();
    const int count = static_cast<int>(history.size());
    if (groupScroll >= count) groupScroll = max(0, count - 1);

    if (count != 0) {
        const int selected = count - 1 - groupScroll;
        JsonObject message = history[selected];
        drawHintLine(groupContactName(message["from"].as<String>()) + " / " + message["status"].as<String>(), 45);
        const String text = message["text"] | "";
        for (int row = 0; row < 4; row++) drawHintLine(text.substring(row * 35, (row + 1) * 35), 59 + row * 11);
        drawHintLine(String(selected + 1) + "/" + String(count) + " | D delivery | T retry", 109);
    } else drawHintLine("No messages. M: manage members", 68);

    drawHintLine("Enter write | M/O | ;/. | Back", 122);
}

void handleGroupChat(int key) {
    refreshGroupDraftState();
    JsonObject record = groups[selectedGroup].as<JsonObject>();

    if (groupReviewRequired) {
        if (key == KEY_ENTER) { groupReviewRequired = false; currentMenu = MENU_GROUP_MANAGE; menuIndex = 0; }
        else if (key == KEY_BACKSPACE) { groupReviewRequired = false; currentMenu = MENU_GROUPS; menuIndex = 0; }
        return;
    }
    if (isTypingGroup) {
        if (key == '`') { isTypingGroup = false; groupInput = ""; }
        else if (key == KEY_ENTER) {
            if (!sendGroupText(selectedGroup, groupInput)) showErrorToast(groupSendProblem(record));
            else { isTypingGroup = false; groupInput = ""; groupScroll = 0; }
        } else handleTextInput(key, groupInput, Groups::MAX_TEXT);
        drawGroupChat();
        return;
    }
    if (key == KEY_BACKSPACE) { currentMenu = MENU_GROUPS; menuIndex = 0; return; }
    if (key == 'm' || key == 'M') { groupConfirm = ""; menuIndex = 0; currentMenu = MENU_GROUP_MANAGE; return; }
    if (key == 'o' || key == 'O') { groupConfirm = ""; menuIndex = 0; currentMenu = MENU_GROUP_ACTIONS; return; }
    if (key == 's' || key == 'S') { if (!syncGroup(selectedGroup)) showErrorToast("Busy or sync state could not save"); }

    else if (record["state"].as<String>() == "invited") {
        if (key == 'y' || key == 'Y') {
             if (!acceptGroup(selectedGroup, true)) showErrorToast("Verify owner / sync / storage busy"); 
        }
        else if (key == 'n' || key == 'N') {
            confirmGroupAction("decline"); return;
        }
    } 
    else if (key == KEY_ENTER && record["state"].as<String>() == "active") {
        if (record.containsKey("outbox") || !Groups::allPeersVerified(record, contacts) || !ownerGroupReady(record)) showErrorToast(groupSendProblem(record));
        else { 
            isTypingGroup = true; groupInput = ""; groupComposeEpoch = record["epoch"].as<uint32_t>(); 
        }
    } 
    else if (key == 't' || key == 'T') {
        if (!retryGroupMessage(selectedGroup)) showErrorToast("No queue / busy / verify peers");
    } 
    else if (key == 'd' || key == 'D') { currentMenu = MENU_GROUP_DELIVERY; return; }
    else if (key == ';') groupScroll = min(groupScroll + 1, max(0, static_cast<int>(record["history"].size()) - 1));
    else if (key == '.') groupScroll = max(0, groupScroll - 1);
    drawGroupChat();
}

void drawGroupManage() {
    beginScreenFrame();
    JsonObject record = groups[selectedGroup].as<JsonObject>();
    drawSectionTitle("GROUP MEMBERS / E" + String(record["epoch"].as<uint32_t>()));
    const int count = static_cast<int>(record["members"].size());

    if (menuIndex >= count) menuIndex = 0;
    const int first = (menuIndex / 2) * 2;
    for (int index = first; index < count && index < first + 2; index++) {
        const String mac = record["members"][index]["mac"] | "";
        const bool owner = mac == record["owner"].as<String>();
        const int top = 29 + (index - first) * 35;
        const bool verified = mac == Groups::ownMac() || MessageCrypto::samePublicKey(Groups::memberPublic(record, mac), Groups::verifiedPublic(contacts, mac));
            
        drawCardRow(groupContactName(mac) + (owner ? " [owner]" : ""), 0, menuIndex == index, top);
        String status = verified ? "verified" : "VERIFY REQUIRED";
        if (record["owner"].as<String>() == Groups::ownMac() && mac != Groups::ownMac())
            status += " / " + record["membership"][mac].as<String>() + " / " + record["sync"][mac]["state"].as<String>();
        drawHintLine(status, top + 21);
    }
    drawHintLine("A add | R remove | I identity", 108);
    drawHintLine("V verify | O actions | ;/. | Back", 122);
}

void handleGroupManage(int key) {
    JsonObject record = groups[selectedGroup].as<JsonObject>();
    const int count = static_cast<int>(record["members"].size());
    if (key == KEY_BACKSPACE) { currentMenu = MENU_GROUP_CHAT; return; }
    if (key == 'o' || key == 'O') { groupConfirm = ""; currentMenu = MENU_GROUP_ACTIONS; menuIndex = 0; return; }
    if (count > 0 && key == ';') menuIndex = (menuIndex + count - 1) % count;
    else if (count > 0 && key == '.') menuIndex = (menuIndex + 1) % count;
    else if (key == 'a' || key == 'A') {
        if (Groups::ownerCanEdit(record)) { currentMenu = MENU_GROUP_ADD; menuIndex = 0; return; }
    } else if ((key == 'r' || key == 'R') && Groups::ownerCanEdit(record) && count > 0) {
        const String mac = record["members"][menuIndex]["mac"] | "";
        if (mac != Groups::ownMac()) { confirmGroupAction("remove", mac); return; }
    } else if (count > 0 && (key == 'i' || key == 'I' || key == 'v' || key == 'V')) {
        groupActionMac = record["members"][menuIndex]["mac"].as<String>();
        if (key == 'i' || key == 'I') { currentMenu = MENU_GROUP_MEMBER; return; }
        selectedContact = Groups::contactFor(contacts, groupActionMac);
        if (groupActionMac == Groups::ownMac() || selectedContact.length() == 0) showErrorToast("Enroll the peer in Contacts first");
        else { verificationReturnMenu = MENU_GROUP_MANAGE; currentMenu = MENU_VERIFY_PEER; return; }
    }
    drawGroupManage();
}

void drawGroupAdd() {
    beginScreenFrame(); drawSectionTitle("ADD VERIFIED MEMBER");
    const int count = groupCandidateCount();
    if (count == 0) drawHintLine("No unused verified contacts", 55);
    else {
        if (menuIndex >= count) menuIndex = 0;
        const int first = (menuIndex / 3) * 3;
        for (int index = first; index < count && index < first + 3; index++)
            drawCardRow(groupContactName(groupCandidateAt(index)), index - first, index == menuIndex);
    }
    drawHintLine("Enter add + rotate | Back cancel", 121);
}

void handleGroupAdd(int key) {
    if (key == KEY_BACKSPACE) { currentMenu = MENU_GROUP_MANAGE; menuIndex = 0; return; }
    const int count = groupCandidateCount();
    if (count == 0) return;
    if (key == ';') menuIndex = (menuIndex + count - 1) % count;
    else if (key == '.') menuIndex = (menuIndex + 1) % count;
    else if (key == KEY_ENTER) {
        if (!editGroupMember(selectedGroup, groupCandidateAt(menuIndex), true, false)) showErrorToast("Busy / member limit / sync removals");
        else { currentMenu = MENU_GROUP_MANAGE; menuIndex = 0; return; }
    }
    drawGroupAdd();
}

const char* groupActionItems[] = {"Sync membership notices", "Retry queued message", "Pause group sends", "Discard queued message",
    "Rotate epoch key (owner)", "Rename group (owner)", "Clear local history", "Close / leave group", "Delete inactive group",
    "Forget incl. unsent notices", "Group information", "Back"};
constexpr int GROUP_ACTION_COUNT = sizeof(groupActionItems) / sizeof(groupActionItems[0]);

void drawGroupActions() {
    beginScreenFrame();
    if (groupConfirm.length() != 0) {
        drawSectionTitle("CONFIRM / " + groupConfirm);
        drawHintLine(groups[selectedGroup]["name"].as<String>(), 34);
        if (groupActionMac.length() != 0) drawHintLine(groupActionMac, 49);
        drawHintLine("Epoch " + String(groupActionEpoch), 64);
        if (groupConfirm == "forget" || groupConfirm == "abandon notices") {
            drawHintLine("Erases local history and tombstone.", 80);
            drawHintLine("Unsent removals will be discarded.", 94);
        } else drawHintLine("This change is saved immediately.", 88);
        drawHintLine("Enter confirm | Back cancel", 122);
        return;
    }
    drawSectionTitle("GROUP ACTIONS");
    if (menuIndex >= GROUP_ACTION_COUNT) menuIndex = 0;
    const int first = (menuIndex / 3) * 3;
    for (int index = first; index < GROUP_ACTION_COUNT && index < first + 3; index++)
        drawCardRow(groupActionItems[index], index - first, index == menuIndex);
    drawHintLine(String(menuIndex + 1) + "/" + String(GROUP_ACTION_COUNT) + " | ;/. | Enter | Back", 122);
}

void handleGroupActions(int key) {
    if (groupConfirm.length() != 0) {
        if (key == KEY_BACKSPACE) { groupConfirm = ""; drawGroupActions(); return; }
        if (key != KEY_ENTER) return;
        if (groups[selectedGroup]["epoch"].as<uint32_t>() != groupActionEpoch) {
            groupConfirm = ""; showErrorToast("Group changed; review action again"); drawGroupActions(); return;
        }
        if (groupConfirm == "forget") { groupConfirm = "abandon notices"; drawGroupActions(); return; }
        bool done = false;
        const String action = groupConfirm;
        if (action == "remove") done = editGroupMember(selectedGroup, groupActionMac, false, false);
        else if (action == "rotate") done = editGroupMember(selectedGroup, "", false, false);
        else if (action == "close") done = editGroupMember(selectedGroup, "", false, true);
        else if (action == "leave") done = leaveGroup(selectedGroup);
        else if (action == "decline") done = acceptGroup(selectedGroup, false);
        else if (action == "discard message") done = pauseGroup(selectedGroup, true);
        else if (action == "clear history") done = clearGroupHistory(selectedGroup);
        else if (action == "delete" || action == "abandon notices") done = forgetGroup(selectedGroup, action == "abandon notices");
        groupConfirm = "";
        if (!done) showErrorToast("Busy / save failed / unsettled notices");
        else if (action == "delete" || action == "abandon notices") {
            selectedGroup = ""; menuIndex = 0; currentMenu = MENU_GROUPS; return;
        } else { currentMenu = MENU_GROUP_CHAT; return; }
        drawGroupActions(); return;
    }
    if (key == KEY_BACKSPACE) { currentMenu = MENU_GROUP_CHAT; return; }
    if (key == ';') menuIndex = (menuIndex + GROUP_ACTION_COUNT - 1) % GROUP_ACTION_COUNT;
    else if (key == '.') menuIndex = (menuIndex + 1) % GROUP_ACTION_COUNT;
    else if (key == KEY_ENTER) {
        JsonObject record = groups[selectedGroup].as<JsonObject>();
        bool done = true;
        switch (menuIndex) {
            case 0: done = syncGroup(selectedGroup); break;
            case 1: done = retryGroupMessage(selectedGroup); break;
            case 2: done = pauseGroup(selectedGroup, false); break;
            case 3: confirmGroupAction("discard message"); break;
            case 4: confirmGroupAction("rotate"); break;
            case 5:
                if (Groups::ownerCanEdit(record)) {
                    groupInput = record["name"].as<String>(); groupActionEpoch = record["epoch"].as<uint32_t>();
                    currentMenu = MENU_GROUP_RENAME; return;
                }
                done = false; break;
            case 6: confirmGroupAction("clear history"); break;
            case 7: confirmGroupAction(record["owner"].as<String>() == Groups::ownMac() ? "close" : "leave"); break;
            case 8: confirmGroupAction("delete"); break;
            case 9: confirmGroupAction("forget"); break;
            case 10: currentMenu = MENU_GROUP_INFO; return;
            case 11: currentMenu = MENU_GROUP_CHAT; return;
        }
        if (!done) showErrorToast("Busy / role / queue / save failed");
    }
    drawGroupActions();
}

void drawGroupDelivery() {
    beginScreenFrame(); drawSectionTitle("MESSAGE DELIVERY");
    JsonArray history = groups[selectedGroup]["history"].as<JsonArray>();
    const int index = static_cast<int>(history.size()) - 1 - groupScroll;
    if (index < 0 || index >= static_cast<int>(history.size())) drawHintLine("No selected message", 50);
    else {
        JsonObject message = history[index];
        drawHintLine("From " + message["from"].as<String>(), 32);
        drawHintLine("E" + String(message["epoch"].as<uint32_t>()) + " / seq " + String(message["sequence"].as<uint32_t>()) + " / " + message["status"].as<String>(), 45);
        int row = 0;
        for (JsonPair delivery : message["delivery"].as<JsonObject>()) {
            drawHintLine(String(delivery.key().c_str()) + " " + delivery.value().as<String>(), 62 + row++ * 15);
        }
        if (row == 0) drawHintLine("Authenticated incoming message", 70);
        drawHintLine(message["id"].as<String>(), 110);
    }
    drawHintLine("T retry queued message | Back", 122);
}

void handleGroupDelivery(int key) {
    if (key == KEY_BACKSPACE) { currentMenu = MENU_GROUP_CHAT; return; }
    if (key == 't' || key == 'T') {
        if (!retryGroupMessage(selectedGroup)) showErrorToast("No queue / busy / verify peers");
    }
    drawGroupDelivery();
}

void drawGroupRename() {
    beginScreenFrame(); drawSectionTitle("RENAME / ROTATE EPOCH");
    drawInputCard("New group name", groupInput, "name", 42, 32);
    drawHintLine("Enter save | ` cancel", 122);
}

void handleGroupRename(int key) {
    if (key == '`') { groupInput = ""; currentMenu = MENU_GROUP_ACTIONS; return; }
    if (key == KEY_ENTER) {
        if (groups[selectedGroup]["epoch"].as<uint32_t>() != groupActionEpoch || !renameGroup(selectedGroup, groupInput))
            showErrorToast("Busy / group changed / save failed");
        else { groupInput = ""; currentMenu = MENU_GROUP_CHAT; return; }
    } else handleTextInput(key, groupInput, 20);
    drawGroupRename();
}

void drawGroupInfo() {
    beginScreenFrame(); drawSectionTitle("GROUP INFORMATION");
    JsonObject record = groups[selectedGroup].as<JsonObject>();
    drawHintLine(selectedGroup, 31);
    drawHintLine("Owner " + record["owner"].as<String>(), 44);
    drawHintLine("Epoch " + String(record["epoch"].as<uint32_t>()) + " / " + record["state"].as<String>(), 57);
    drawHintLine("Removal notices: " + String(static_cast<unsigned int>(record["revocations"].size())), 70);
    drawHintLine("Response: " + record["response"]["state"].as<String>(), 83);
    drawHintLine(record.containsKey("outbox") ? "One message retained for retry" : "No pending message", 96);
    drawHintLine("Back: actions", 122);
}

void handleGroupInfo(int key) { if (key == KEY_BACKSPACE) currentMenu = MENU_GROUP_ACTIONS; }

void drawGroupMember() {
    beginScreenFrame(); drawSectionTitle("PINNED ROSTER IDENTITY");
    const String key = Groups::memberPublic(groups[selectedGroup].as<JsonObject>(), groupActionMac);
    drawHintLine(groupActionMac, 33);
    drawHintLine(key.substring(0, 32), 49);
    drawHintLine(key.substring(32), 62);
    drawHintLine("Full static public key (not secret)", 80);
    drawHintLine("Use V in Members to compare pair FP", 96);
    drawHintLine("Back: members", 122);
}

void handleGroupMember(int key) { if (key == KEY_BACKSPACE) currentMenu = MENU_GROUP_MANAGE; }

void refreshGroupsUi() {
    if (currentMenu == MENU_GROUPS) drawGroupsMenu();
    else if (currentMenu == MENU_GROUP_CHAT) drawGroupChat();
    else if (currentMenu == MENU_GROUP_MANAGE) drawGroupManage();
    else if (currentMenu == MENU_GROUP_ADD) drawGroupAdd();
    else if (currentMenu == MENU_GROUP_ACTIONS) drawGroupActions();
    else if (currentMenu == MENU_GROUP_DELIVERY) drawGroupDelivery();
    else if (currentMenu == MENU_GROUP_INFO) drawGroupInfo();
    else if (currentMenu == MENU_GROUP_MEMBER) drawGroupMember();
}
