#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <openssl/evp.h>
#include "MinHook.h"
#include "hook.h"

typedef struct {
    LPCSTR funcName;
    LPCSTR moduleName;
    PVOID funcAddress;
    PVOID originalFunc;
    unsigned char* originalHash;
    PVOID hookFunc;
} HookEntry;

HookEntry HookList[] = {
    { "VirtualProtect", "kernelbase.dll", NULL, NULL, NULL, VirtualProtect_HookHandler },
    { "VirtualAlloc", "kernel32.dll", NULL, NULL, NULL, VirtualAlloc_HookHandler },
    { "CreateProcessA", "kernel32.dll", NULL, NULL, NULL, CreateProcessA_HookHandler },
    { "CreateProcessW", "kernel32.dll", NULL, NULL, NULL, CreateProcessW_HookHandler },
};

const size_t HookListSize = sizeof(HookList) / sizeof(HookEntry);
 
FILE* f;

// returns false if failed
int UninstallFunctionHooks() {
    int failed = 0;
    for (size_t i = 0; i < HookListSize; i++) {
        if (MH_DisableHook(HookList[i].funcAddress) != MH_OK) {
            failed++;
            continue;
        }
    }

    if (MH_Uninitialize() != MH_OK) {
        return -1;
    }

    return failed;
}

// loops through func array and hooks all of them
int InstallFunctionHooks() {
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    if (MH_Initialize() != MH_OK) {
        fprintf(f, "failed to initialize minhook\n");
        fclose(f);
        return -1;
    }
    fprintf(f, "initialized minhook\n");
    fclose(f);

    int failed = 0;
    for (size_t i = 0; i < HookListSize; i++) {
        f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
        unsigned char* p = (unsigned char*)HookList[i].funcAddress;
        fprintf(f, "func first bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n", p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]);
        fclose(f);
        
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery(HookList[i].funcAddress, &mbi, sizeof(mbi));
        f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
        fprintf(f, "%s!%s function base: 0x%p, module base 0x%p, protect 0x%p\n",
        HookList[i].moduleName, HookList[i].funcName, HookList[i].funcAddress, mbi.AllocationBase, mbi.Protect);
        fclose(f);
        f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
        // save first bytes and prepare trampoline
        if (MH_CreateHook(HookList[i].funcAddress, HookList[i].hookFunc, &HookList[i].originalFunc) != MH_OK) {
            fprintf(f, "failed to create hook %d\n", i);
            fclose(f);
            failed++;
            continue;
        }
        fprintf(f, "created hook %d, func address: 0x%p, handler address: 0x%p\n", i, HookList[i].funcAddress, HookList[i].hookFunc);
        fclose(f);

        f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
        // insert actual hook into function
        if (MH_EnableHook(HookList[i].funcAddress) != MH_OK) {
            fprintf(f, "failed to enable hook %d\n", i);
            fclose(f);
            failed++;
            continue;
        }
        fprintf(f, "enabled hook %d\n", i);
        fclose(f);
    }
    return failed;
}

// fully successful call returns 0
int FillFunctionAddresses() {
    HMODULE ntBase = GetModuleHandle("ntdll.dll");
    HMODULE k32Base = GetModuleHandle("kernel32.dll");
    HMODULE kbBase = GetModuleHandle("kernelbase.dll");
    HMODULE u32Base = GetModuleHandle("user32.dll");
    if (k32Base == NULL && ntBase == NULL && kbBase == NULL && u32Base == NULL) {
        return -1;
    }
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    fprintf(f, "ntdll base: 0x%p, kernel32 base: 0x%p, kernelbase base: 0x%p, user32 base: 0x%p\n", ntBase, k32Base, kbBase, u32Base);
    fclose(f);

    int failCount = 0;
    for (size_t i = 0; i < HookListSize; i++) {
        if (strcmp(HookList[i].moduleName, "ntdll.dll") == 0) {
            HookList[i].funcAddress = GetProcAddress(ntBase, HookList[i].funcName);
        }
        if (strcmp(HookList[i].moduleName, "kernel32.dll") == 0) {
            HookList[i].funcAddress = GetProcAddress(k32Base, HookList[i].funcName);
        }
        if (strcmp(HookList[i].moduleName, "kernelbase.dll") == 0) {
            HookList[i].funcAddress = GetProcAddress(kbBase, HookList[i].funcName);
        }
        if (strcmp(HookList[i].moduleName, "user32.dll") == 0) {
            HookList[i].funcAddress = GetProcAddress(u32Base, HookList[i].funcName);
        }
        if (HookList[i].funcAddress == NULL) {
            failCount++;
        }
    }
    return failCount;
}

int main() {
    //TODO: setup hooks

    DWORD wait = WaitForSingleObject(hEvent, INFINITE);
    switch (wait) {
        case WAIT_OBJECT_0:
    //* virtualalloc
    BOOL need2free = FALSE;
    LPVOID pMem = VirtualAlloc(NULL, 420, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pMem == NULL) {
        printf("VirtualAlloc failed, error: %d\n", GetLastError());
    } else {
        need2free = TRUE;
    }
    //* createprocess
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcess(
        NULL, "C:\\Windows\\System32\\calc.exe", NULL, NULL,
        FALSE, 0, NULL, NULL, &si, &pi)) {
            printf("CreateProcess failed, error: %d\n", GetLastError());
        }
    //* virtualprotect
    if (need2free) {
        DWORD oldProtect;
        BOOL ok = VirtualProtect(pMem, 420, PAGE_EXECUTE_READ, &oldProtect);
        VirtualFree(pMem, 420, MEM_RELEASE);
    }
}