#include <unordered_map>
#include <string>
#include "hook.h"

// c++ just for maps, since I need them for my IAT integrity check mechanism

static std::unordered_map<std::string, HookEntry*> hookMap;

extern "C" {
    void InitializeHookMap(void) {
        hookMap.clear();
        for (size_t i = 0; i < HookListSize; i++) {
            //TODO: should you do dll!func instead of just func?
            hookMap[HookList[i].funcName] = &HookList[i];
        }
    }

    HookEntry* FindHookEntry(LPCSTR funcName) {
        auto entry = hookMap.find(funcName);
        // check if map lookup found an entry
        if (entry != hookMap.end()) {
            return entry->second; // entry->first is the key and entry->second is value
        }
        return NULL;
    }
}