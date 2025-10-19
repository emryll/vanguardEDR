#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "hook.h"

//TODO: read from a config file, currently kind of a ghetto system for enabling hooks...
//? To enable or disable hooks, add them here and the dll to TrackedModules
//? The function will also need a handler function in handlers.c and also
//?  you need to create a typedef so the function can be called from pointer in the handler,
//?  also you need to add an enum for it in correct spot in hook.h HOOK_INDEX enum.
//? Notice, if you disable a hook by commenting it out in this list, you will also
//?  need to comment out the enum in HOOK_INDEX, or it will mess up every hook after
HookEntry HookList[] = {
    { "MessageBoxA", "user32.dll", NULL, NULL,              (FARPROC)MessageBoxA_Handler, {0} },
    { "VirtualProtect", "kernelbase.dll", NULL, NULL,       (FARPROC)VirtualProtect_Handler, {0} },
    { "VirtualProtectEx", "kernelbase.dll", NULL, NULL,     (FARPROC)VirtualProtectEx_Handler, {0} },
    { "NtProtectVirtualMemory", "ntdll.dll", NULL, NULL,    (FARPROC)NtProtectVM_Handler, {0} },
    { "VirtualAlloc", "kernel32.dll", NULL, NULL,           (FARPROC)VirtualAlloc_Handler, {0} },
    { "VirtualAlloc2", "kernelbase.dll", NULL, NULL,        (FARPROC)VirtualAlloc2_Handler, {0} },
    { "VirtualAllocEx", "kernel32.dll", NULL, NULL,         (FARPROC)VirtualAllocEx_Handler, {0} },
    { "NtAllocateVirtualMemory", "ntdll.dll", NULL, NULL,   (FARPROC)NtAllocateVM_Handler, {0} },
    { "NtAllocateVirtualMemoryEx", "ntdll.dll", NULL, NULL, (FARPROC)NtAllocateVMEx_Handler, {0} },
    { "OpenProcess", "kernel32.dll", NULL, NULL,            (FARPROC)OpenProcess_Handler, {0} },
    { "NtOpenProcess", "ntdll.dll", NULL, NULL,             (FARPROC)NtOpenProcess_Handler, {0} },
    { "CreateProcessA", "kernel32.dll", NULL, NULL,         (FARPROC)CreateProcessA_Handler, {0} },
    { "CreateProcessW", "kernel32.dll", NULL, NULL,         (FARPROC)CreateProcessW_Handler, {0} },
    { "CreateProcessAsUserA", "kernel32.dll", NULL, NULL,   (FARPROC)CreateProcessAsUserA_Handler, {0} },
    { "CreateProcessAsUserW", "kernel32.dll", NULL, NULL,   (FARPROC)CreateProcessAsUserW_Handler, {0} },
    { "NtCreateProcess", "ntdll.dll", NULL, NULL,           (FARPROC)NtCreateProcess_Handler, {0} },
    { "NtCreateProcessEx", "ntdll.dll", NULL, NULL,         (FARPROC)NtCreateProcessEx_Handler, {0} },
    { "NtCreateUserProcess", "ntdll.dll", NULL, NULL,       (FARPROC)NtCreateUserProcess_Handler, {0} },
    { "CreateRemoteThread", "kernel32.dll", NULL, NULL,     (FARPROC)CreateRemoteThread_Handler, {0} },
    { "CreateRemoteThreadEx", "kernel32.dll", NULL, NULL,   (FARPROC)CreateRemoteThreadEx_Handler, {0} },
    { "NtCreateThread", "ntdll.dll", NULL, NULL,            (FARPROC)NtCreateThread_Handler, {0} },
    { "NtCreateThreadEx", "ntdll.dll", NULL, NULL,          (FARPROC)NtCreateThreadEx_Handler, {0} },
};

Module TrackedModules[] = {
    { "kernel32.dll",   NULL, {0} },
    { "kernelbase.dll", NULL, {0} },
    { "ntdll.dll",      NULL, {0} },
    { "user32.dll",     NULL, {0} },
    //{ "advapi.dll", NULL, NULL },
};

const size_t HookListSize = sizeof(HookList) / sizeof(HookEntry); 
const size_t NumTrackedModules = sizeof(TrackedModules) / sizeof(Module); 

void InitializeModuleList() {
    for (size_t i = 0; i < NumTrackedModules; i++) {
        TrackedModules[i].base = GetModuleHandle(TrackedModules[i].name);
        unsigned int hashLen = 0;
        HashTextSection(TrackedModules[i].base, TrackedModules[i].textHash, &hashLen);
    }
}

// fills function addresses and takes hash
int InitializeHookList() {
    fprintf(stderr, "start of InitializeHookList, NumTrackedModules: %d\n", NumTrackedModules);
    // pre-fill base addresses of each tracked module onto a list

    for (size_t i = 0; i < HookListSize; i++) {
        // fill moduleBase from previously loaded list of module addresses
        for (size_t j = 0; j < NumTrackedModules; j++) {
            if (strcmp(HookList[i].moduleName, TrackedModules[j].name) == 0) {
                HookList[i].moduleBase = TrackedModules[j].base;
            }
        }
        HookList[i].originalFunc = GetProcAddress(HookList[i].moduleBase, HookList[i].funcName);
        fprintf(stderr, "function %s\n\tmodulebase: %p\n\taddress: %p\n", HookList[i].funcName, HookList[i].moduleBase, HookList[i].originalFunc);
        FillFunctionHash(HookList[i].funcHash, HookList[i].originalFunc, FUNC_HASH_LENGTH);
    }
    return 0;
}

int InitializeIatHookByName(LPVOID moduleBase, LPCSTR funcToHook, FARPROC handler) {
    //* Parse PE header to find Import Address Table and change function address to point to handler
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != PE_SIGNATURE) {
        return -1;
    }

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)moduleBase);
	LPCSTR libraryName = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL; 
    
    while (importDescriptor->Name != 0) {
        // is it the correct module's IAT?
		libraryName = (LPCSTR)((DWORD_PTR)importDescriptor->Name + (DWORD_PTR)moduleBase);
        if (strcmp(libraryName, "") == 0) {
            break;
        }
        
        PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
        originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->OriginalFirstThunk);
        firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->FirstThunk);
        
        while (originalFirstThunk->u1.AddressOfData != 0) {
            //? do you need to check if originalFirstThunk or firstThunk is NULL?
            functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)moduleBase + originalFirstThunk->u1.AddressOfData);

            // skip null function entry
            if (firstThunk->u1.Function == 0) {
                originalFirstThunk++;
                firstThunk++;
                continue;
            }
           
            // replace address if its the one we want to hook
            if (strcmp(functionName->Name, funcToHook) == 0) {
                DWORD oldProtect;
                VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
                firstThunk->u1.Function = (DWORD_PTR)handler;
                return 0;
            }
            originalFirstThunk++;
            firstThunk++;
        }
        importDescriptor++;
    }
    return 1;
}

//! currently very inefficient. will optimize it later, temporarily doing seperate parsing for each function 
int InitializeIatHooksByHookList() {
    int failed = 0;
    for (size_t i = 0; i < HookListSize; i++) {
        //? the iat is in main module, because youre going through modules imported by main module!
        int result = InitializeIatHookByName((LPVOID)GetModuleHandle(NULL), HookList[i].funcName, HookList[i].handler);
        if (result != 0) {
            // return value 1 is to be expected if the tracked program does not import this function
            fprintf(stderr, "failed to hook %s (return value %d)\n", HookList[i].funcName, result);
            failed++;
        }
    }
    return failed;
}

//TODO: uninstall iat hooks