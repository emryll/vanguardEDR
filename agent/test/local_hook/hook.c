#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include "MinHook.h"
#include "hook.h"



HookEntry HookList[] = {
    //{ "VirtualQuery", "kernel32.dll", NULL, NULL, NULL, VirtualQuery_HookHandler},
    { "MessageBoxA", "user32.dll", NULL, NULL, NULL, MessageBoxA_HookHandler},
    { "CreateProcessA", "kernel32.dll", NULL, NULL, NULL, CreateProcessA_HookHandler },
    { "CreateProcessW", "kernel32.dll", NULL, NULL, NULL, CreateProcessW_HookHandler },
    //{ "VirtualAlloc", "kernel32.dll", NULL, NULL, NULL, VirtualAlloc_HookHandler },
    //{ "VirtualProtect", "kernelbase.dll", NULL, NULL, NULL, VirtualProtect_HookHandler },
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

LPVOID WINAPI VirtualAlloc_HookHandler(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect) {
    fprintf(f, "inside virtual alloc hook\n");
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_VIRTUAL_ALLOC);

    tm.data.apiCall.args[0].arg.ptrValue = lpAddress;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.dwValue = dwSize;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[2].arg.dwValue = flAllocationType;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[3].arg.dwValue = flProtect;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_DWORD;

    FillEmptyArgs(&tm, 4);

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    if (flProtect != PAGE_EXECUTE_READWRITE) {
        return ((VIRTUALALLOC)HookList[HOOK_VIRTUAL_ALLOC].originalFunc)(lpAddress, dwSize, flAllocationType, flProtect);
    } else {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
}

static __thread bool inHook_vp = false;

BOOL WINAPI VirtualProtect_HookHandler(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect) {
    if (inHook_vp) {
        return ((VIRTUALPROTECT)HookList[HOOK_VIRTUAL_PROTECT].originalFunc)(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    inHook_vp = true;

    BOOL result = ((VIRTUALPROTECT)HookList[HOOK_VIRTUAL_PROTECT].originalFunc)(lpAddress, dwSize, flNewProtect, lpflOldProtect);

    fprintf(f, "inside virtual protect hook\n");
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_VIRTUAL_PROTECT);
    
    tm.data.apiCall.args[0].arg.ptrValue = lpAddress;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.dwValue = dwSize;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[2].arg.dwValue  = flNewProtect;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpflOldProtect;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;

    FillEmptyArgs(&tm, 4);

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    inHook_vp = false;
    return result;
}

static __thread bool inHook_cpa = false;

BOOL WINAPI CreateProcessA_HookHandler(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation) {
    CREATEPROCESSA createProcess = (CREATEPROCESSA)HookList[HOOK_CREATE_PROCESS_A].originalFunc;
    if (inHook_cpa) {
        return createProcess(lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }
    inHook_cpa = true;

    BOOL result = createProcess(lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
    lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    fprintf(f, "inside create process hook\n");
    fclose(f);
    /*TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_CREATE_PROCESS_A);
    
    strncpy(tm.data.apiCall.args[0].arg.astrValue, lpApplicationName, sizeof(tm.data.apiCall.args[0].arg.astrValue));
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_ASTRING;
    
    strncpy(tm.data.apiCall.args[1].arg.astrValue, lpCommandLine, sizeof(tm.data.apiCall.args[1].arg.astrValue));
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_ASTRING;

    tm.data.apiCall.args[2].arg.ptrValue  = lpProcessAttributes;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpThreadAttributes;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[4].arg.boolValue = bInheritHandles;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_BOOL;

    tm.data.apiCall.args[5].arg.dwValue = dwCreationFlags;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[6].arg.ptrValue = lpEnvironment;
    tm.data.apiCall.args[6].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[7].arg.ptrValue = lpCurrentDirectory;
    tm.data.apiCall.args[7].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[8].arg.ptrValue = lpStartupInfo;
    tm.data.apiCall.args[8].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[9].arg.ptrValue = lpProcessInformation;
    tm.data.apiCall.args[9].type         = API_ARG_TYPE_PTR;

    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    fprintf(f, "createprocess before writing to pipe\n");
    fclose(f);

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    fprintf(f, "sent %d bytes to pipe\n", dwBytesWritten);
    fclose(f);*/
    inHook_cpa = false;
    return result;
}

BOOL WINAPI CreateProcessW_HookHandler(
  LPCWSTR                lpApplicationName,
  LPWSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCWSTR                lpCurrentDirectory,
  LPSTARTUPINFOW        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_CREATE_PROCESS_W);
    
    wcsncpy(tm.data.apiCall.args[0].arg.wstrValue, lpApplicationName, sizeof(tm.data.apiCall.args[0].arg.wstrValue) / sizeof(wchar_t) -1);
    tm.data.apiCall.args[0].arg.wstrValue[259] = L'\0';
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_ASTRING;
    
    wcsncpy(tm.data.apiCall.args[1].arg.wstrValue, lpCommandLine, sizeof(tm.data.apiCall.args[1].arg.wstrValue) / sizeof(wchar_t) -1);
    tm.data.apiCall.args[1].arg.wstrValue[259] = L'\0';
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_ASTRING;

    tm.data.apiCall.args[2].arg.ptrValue  = lpProcessAttributes;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpThreadAttributes;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[4].arg.boolValue = bInheritHandles;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_BOOL;

    tm.data.apiCall.args[5].arg.dwValue = dwCreationFlags;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[6].arg.ptrValue = lpEnvironment;
    tm.data.apiCall.args[6].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[7].arg.ptrValue = lpCurrentDirectory;
    tm.data.apiCall.args[7].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[8].arg.ptrValue = lpStartupInfo;
    tm.data.apiCall.args[8].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[9].arg.ptrValue = lpProcessInformation;
    tm.data.apiCall.args[9].type         = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((CREATEPROCESSW)HookList[HOOK_CREATE_PROCESS_W].originalFunc)(lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

int WINAPI MessageBoxA_HookHandler(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    MESSAGEBOXA msgBox = (MESSAGEBOXA)HookList[HOOK_MESSAGE_BOX_A].originalFunc;
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    fprintf(f, "inside messagebox hook\n");
    fclose(f);
    TELEMETRY tm;
    memset(&tm, 0, sizeof(tm));
    GetHookBaseTelemetryPacket(&tm, "user32.dll", HOOK_MESSAGE_BOX_A);

    tm.data.apiCall.args[0].arg.ptrValue = (void *)69;//hWnd;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_PTR;

    strncpy(tm.data.apiCall.args[1].arg.astrValue, lpText, sizeof(tm.data.apiCall.args[1].arg.astrValue)-1);
    tm.data.apiCall.args[1].type = API_ARG_TYPE_ASTRING;

    strncpy(tm.data.apiCall.args[2].arg.astrValue, lpCaption, sizeof(tm.data.apiCall.args[2].arg.astrValue)-1);
    tm.data.apiCall.args[2].type = API_ARG_TYPE_ASTRING;

    tm.data.apiCall.args[3].arg.dwValue = uType;
    tm.data.apiCall.args[3].type = API_ARG_TYPE_DWORD;

    FillEmptyArgs(&tm, 4);

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    fprintf(f, "tid: %d, hwnd: %d, pid: %d, time: %d, sizeof(enum): %d\nwrote %d bytes to pipe, sizeof telemetry struct: %d\n", tm.data.apiCall.tid, tm.data.apiCall.args[0].arg.ptrValue, tm.header.pid, tm.header.timeStamp, sizeof(HOOK_MESSAGE_BOX_A), dwBytesWritten, sizeof(tm));
    fclose(f);
    return msgBox(hWnd, "Hooked!", "Hooked!", uType);
}
/*
SIZE_T WINAPI VirtualQuery_HookHandler(
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength) {
    VIRTUALQUERY virtualQuery = (VIRTUALQUERY)HookList[HOOK_VIRTUAL_QUERY].originalFunc;
    if (inHook) {
        return virtualQuery(lpAddress, lpBuffer, dwLength);
    }
    inHook = true;
    SIZE_T result = virtualQuery(lpAddress, lpBuffer, dwLength);

    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    fprintf(f, "inside virtualquery hook\n");
    fclose(f);
    TELEMETRY tm;
    memset(&tm, 0, sizeof(tm));
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_VIRTUAL_QUERY);

    tm.data.apiCall.args[0].arg.ptrValue = lpAddress;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = lpBuffer;
    tm.data.apiCall.args[1].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.dwValue = dwLength;
    tm.data.apiCall.args[2].type = API_ARG_TYPE_DWORD;

    FillEmptyArgs(&tm, 3);

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    inHook = false;
    return result;
}*/