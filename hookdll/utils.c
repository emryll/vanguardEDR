#include <windows.h>
#include "hook.h"

void GetTextTelemetryPacket(TELEMETRY* tm, char* moduleName, BOOL result) {
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId();
    tm.header.type = TM_TYPE_TEXT_INTEGRITY;

    tm.data.textCheck.result = result;
    strncpy(tm.data.textCheck.module, moduleName, sizeof(tm.data.textCheck.module));
    return;
}

void GetHookIntegrityTelemetryPacket(TELEMETRY* tm, int* mismatches, int mismatchCount) {
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId;
    tm.header.type = TM_TYPE_HOOK_INTEGRITY;

    tm.data.funcCheck.mismatchCount = mismatchCount;
    for (size_t i = 0; i < mismatchCount; i++) {
        strncpy(tm.data.funcCheck.mismatches[i], 
        HookList[mismatches[i]].funcName,
        sizeof(tm.data.funcCheck.mismatches[i]));
    }
    return;
}

PPEB getPEB() {
    return (PPEB)__readgsqword(0x60);  // For x64
}

// returns array of ints, corresponding to hooked functions with mismatch, value being index to hooklist
// caller must free resulting array
int* CheckHookIntegrity(int* mismatchCount) {
    int *mismatches = NULL;
    size_t count = 0;
    size_t capacity = 0;

    for (size_t i = 0; i < HookListSize; i++) {
        unsigned char* funcHash;
        if (HookList[i].funcAddress == NULL) {
            continue;
        }
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            continue;
        }
        if (EVP_DigestInit_ex(ctx, EVP_sha256, NULL) != 1) {
            EVP_MD_CTX_free(ctx);
            continue;
        }
        if (EVP_DigestUpdate(ctx, (LPCVOID)HookList[i].funcAddress, fixedHashSize) != 1) {
            EVP_MD_CTX_free(ctx);
            continue;
        }
        unsigned int hashLen;
        if (EVP_DigestFinal_ex(ctx, funcHash, &hashLen)) {
            EVP_MD_CTX_free(ctx);
            continue;
        }
        if (memcmp(HookList[i].originalHash, funcHash, hashLen) != 0) {
            if (count >= capacity) {
                // start with 4, after that when you need more space, double it
                size_t newCapacity = (capacity == 0) ? 4 : capacity * 2;
                int* new_arr = realloc(mismatches, newCapacity * sizeof(int));
                if (!new_arr) {
                    fprintf(stderr, "Memory allocation failed\n");
                    mismatchCount = count;
                    return mismatches;
                }
                mismatches = new_arr;
                capacity = newCapacity;
            }
            mismatches[count] = i;
            count++;;
        }
    }
    return count;
}