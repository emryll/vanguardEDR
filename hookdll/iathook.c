#include <windows.h>
#include <winternl.h>

typedef struct {
    LPCSTR funcName;
    LPCSTR moduleName;
    LPVOID moduleBase;
    FARPROC originalFunc;
    FARPROC handler;
    unsigned char funcHash[SHA256_DIGEST_LENGTH];
} HookEntry;

typedef struct {
    LPCSTR name;
    LPVOID base;
    unsigned char* textHash;
} Module;

HookEntry HookList[] = {
    { "MessageBoxA", "user32.dll", NULL, NULL, NULL, MessageBoxA_HookHandler },
//    { "VirtualProtect", "kernelbase.dll", NULL, NULL, NULL, VirtualProtect_HookHandler },
//    { "VirtualAlloc", "kernel32.dll", NULL, NULL, NULL, VirtualAlloc_HookHandler },
//    { "CreateProcessA", "kernel32.dll", NULL, NULL, NULL, CreateProcessA_HookHandler },
//    { "CreateProcessW", "kernel32.dll", NULL, NULL, NULL, CreateProcessW_HookHandler },
};

Module TrackedModules[] = {
    { "kernel32.dll", NULL, NULL },
    { "kernelbase.dll", NULL, NULL },
    { "ntdll.dll", NULL, NULL },
    { "user32.dll", NULL, NULL },
};

const size_t HookListSize = sizeof(HookList) / sizeof(HookEntry); 
const size_t NumTrackedModules = sizeof(TrackedModules) / sizeof(LPCSTR); 

// fills function addresses and takes hash
int InitializeHookList() {
    for (size_t i = 0; i < NumTrackedModules; i++) {
        TrackedModules[i].base = GetModuleHandle(TrackedModules[i].name);
    }

    for (size_t i = 0; i < HookListSize; i++) {
        for (size_t j = 0; j < NumTrackedModules; i++) {
            if (strcmp(HookList[i].moduleName, TrackedModules[j].name) == 0) {
                strcpy(TrackedModules[j].base, HookList[i].moduleBase);
            }
        }
        HookList[i].originalFunc = GetProcAddress(HookList[i].moduleBase, HookList[i].funcName);
        
        //TODO: make func hash function
        getFuncHash((LPVOID)HookList[i].originalFunc, FN_HASH_LENGTH, HookList[i].funcHash);
    }
}

// 
int InitializeIatHookByName(LPVOID moduleBase, LPCSTR funcToHook, FARPROC handler) {
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != PE_SIGNATURE) {
        //setColor(RED);
        //printf("\n[!] Incorrect PE signature!\n");
        //setColor(WHITE);
        return -1;
    }
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)moduleBase);
	LPCSTR libraryName = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL; 
    
    while (importDescriptor->Name != 0) {
		libraryName = (LPCSTR)((DWORD_PTR)importDescriptor->Name + (DWORD_PTR)moduleBase);
        if (strcmp(libraryName, "") == 0) {
            break;
        }
        
        PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
        originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->OriginalFirstThunk);
        firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->FirstThunk);
        
        while (originalFirstThunk->u1.AddressOfData != 0) {
            if (originalFirstThunk == NULL || firstThunk == NULL) {
                //printf("[!] NULL pointer\n");
            }
            
            functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)moduleBase + originalFirstThunk->u1.AddressOfData);

            if (firstThunk->u1.Function == 0) {
                //printf("[i] Skipping null function entry\n");
                originalFirstThunk++;
                firstThunk++;
                continue;
            }
           
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
        int result = InitializeIatHookByName(HookList[i].moduleBase, HookList[i].funcName, HookList[i].handler);
        if (result != 0) {
            failed++;
        }
    }
    return failed;
}