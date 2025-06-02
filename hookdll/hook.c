#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <openssl/evp.h>
#include "MinHook.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

typedef struct {
    LPCSTR funcName;
    PVOID funcAddress;
    unsigned char* originalHash;
    PVOID hookFunc;
} HookEntry;

HookEntry HookList[] = {
    { "CreateRemoteThread",      NULL, NULL, CreateRemoteThread_HookHandler },
    { "CreateRemoteThreadEx",    NULL, NULL, CreateRemoteThreadEx_HookHandler },
    { "VirtualProtect",          NULL, NULL, VirtualProtect_HookHandler },
    { "VirtualAlloc",            NULL, NULL, VirtualAlloc_HookHandler },
    { "VirtualAlloc2",           NULL, NULL, VirtualAlloc2_HookHandler },
    { "VirtualAllocEx",          NULL, NULL, VirtualAllocEx_HookHandler },
    { "NtAllocateVirtualMemory", NULL, NULL, NtAllocateVirtualMemory_HookHandler },
    { "NtCreateThread",          NULL, NULL, NtCreateThread_HookHandler },
    { "NtCreateThreadEx",        NULL, NULL, NtCreateThreadEx_HookHandler },
    //TODO: ....
    { "CreateProcessA",          NULL, NULL, CreateProcessA_HookHandler },
    { "CreateProcessW",          NULL, NULL, CreateProcessW_HookHandler },
    { "NtCreateProcess",         NULL, NULL, NtCreateProcess_HookHandler },
    { "NtCreateProcessEx",       NULL, NULL, NtCreateProcessEx_HookHandler },
    { "NtCreateUserProcess",     NULL, NULL, NtCreateUserProcess_HookHandler },
    { "NtProtectVirtualMemory",  NULL, NULL, NtProtectVirtualMemory_HookHandler },
    { "QueueUserAPC",            NULL, NULL, QueueUserAPC_HookHandler },
    { "NtQueueApcThread",        NULL, NULL, NtQueueApcThread_HookHandler },
    { "HeapAlloc",               NULL, NULL, HeapAlloc_HookHandler },
    { "HeapReAlloc",             NULL, NULL, HeapReAlloc_HookHandler },
    { "NtUnmapViewOfSection",    NULL, NULL, NtUnmapViewOfSection_HookHandler },
    { "NtMapViewOfSection",      NULL, NULL, NtMapViewOfSection_HookHandler },
    { "GetProcAddress",          NULL, NULL, GetProcAddress_HookHandler },
    { "GetModuleHandleA",        NULL, NULL, GetModuleHandleA_HookHandler },
    { "GetModuleHandleW",        NULL, NULL, GetModuleHandleW_HookHandler },
    { "SetWindowsHookExA",       NULL, NULL, SetWindowsHookExA_HookHandler },
    { "SetWindowsHookExW",       NULL, NULL, SetWindowsHookExW_HookHandler },
    { "WinExec",                 NULL, NULL, WinExec_HookHandler },
    { "IsDebuggerPresent",       NULL, NULL, IsDebuggerPresent_HookHandler },
    { "CryptCreateHash",         NULL, NULL, CryptCreateHash_HookHandler },
    { "CryptEncrypt",            NULL, NULL, CryptEncrypt_HookHandler },
    { "EncryptFileA",            NULL, NULL, EncryptFileA_HookHandler },
    { "EncryptFileW",            NULL, NULL, EncryptFileW_HookHandler },
    { "", NULL, NULL, _HookHandler },
};

const size_t HookListSize = sizeof(HookList) / sizeof(HookEntry);
 
// returns false if failed
BOOL UninstallFunctionHooks() {
    //TODO: read original bytes from trampoline, free trampoline mem
    //TODO: write original bytes back over the inline hook
    for (size_t i = 0; i < HookListSize; i++) {

    }

    if (MH_Uninitialize() != MH_OK) {
        return FALSE;
    }
    return TRUE;
}

// loops through func array and hooks all of them
BOOL SetupHooks() {
    if (MH_Initialize() != MH_OK)

    for (size_t i = 0; i < HookListSize; i++) {
        // save first bytes and prepare trampoline
        MH_CreateHook();

        // insert actual hook into function
        MH_EnableHook();
    }
}

// fully successful call returns 0
int FillFunctionAddresses() {
    HMODULE ntBase = GetModuleHandle("ntdll.dll");
    if (ntBase == NULL) {
        return -1;
    }
    int failCount = 0;
    for (size_t i = 0; i < HookListSize; i++) {
        pFunc = GetProcAddress(ntBase, HookList[i].funcName)
        if (pFunc == NULL) {
            failCount++;
        }
        HookList[i].funcName = pFunc;
    }
    return failCount;
}

//@fixedHashSize: how many bytes to hash from start of function address
//TODO: test this function
int FillFunctionHashes(DWORD fixedHashSize) {
    BOOL empty = TRUE;
    for (size_t i = 0; i < HookListSize; i++) {
        if (HookList[i].funcAddress == NULL) {
            continue
        } else {
            empty = FALSE;
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx) {
                return 1;
            }
            if (EVP_DigestInit_ex(ctx, EVP_sha256, NULL) != 1) {
                EVP_MD_CTX_free(ctx);
                return 2;
            }
            if (EVP_DigestUpdate(ctx, (LPCVOID)HookList[i].funcAddress, fixedHashSize) != 1) {
                EVP_MD_CTX_free(ctx);
                return 3;
            }
            unsigned int hashLen;
            if (EVP_DigestFinal_ex(ctx, HookList[i].originalHash, &hashLen)) {
                EVP_MD_CTX_free(ctx);
                return 4;
            }
        }
    }
    if (empty) {
        return -1;
    }
}

HANDLE CreateRemoteThread_HookHandler(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId,
) {
    TELEMETRY tm;
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId();
    tm.header.type = TM_TYPE_API_CALL;

    tm.data.apiCall.tid = GetCurrentThreadId();
    strncpy(tm.data.apiCall.dllName, "kernel32.dll", sizeof(tm.data.apiCall.dllName)-1);
    strncpy(tm.data.apiCall.funcName, "CreateRemoteThread", sizeof(tm.data.apiCall.funcName)-1);
    
    tm.data.apiCall.args[0].arg.ptrValue = hProcess;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.ptrValue = lpThreadAttributes;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.ptrValue = dwStackSize;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpStartAddress;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[4].arg.ptrValue = lpParameter;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[5].arg.dwValue  = dwCreationFlags;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[6].arg.ptrValue = lpThreadId;
    tm.data.apiCall.args[6].type         = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HANDLE CreateRemoteThreadEx_HookHandler(
    HANDLE                       hProcess,
    LPSECURITY_ATTRIBUTES        lpThreadAttributes,
    SIZE_T                       dwStackSize,
    LPTHREAD_START_ROUTINE       lpStartAddress,
    LPVOID                       lpParameter,
    DWORD                        dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD                      lpThreadId,
) {
    TELEMETRY tm;
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId();
    tm.header.type = TM_TYPE_API_CALL;

    tm.data.apiCall.tid = GetCurrentThreadId();
    strncpy(tm.data.apiCall.dllName, "kernel32.dll", sizeof(tm.data.apiCall.dllName)-1);
    strncpy(tm.data.apiCall.funcName, "CreateRemoteThreadEx", sizeof(tm.data.apiCall.funcName)-1);
    
    tm.data.apiCall.args[0].arg.ptrValue = hProcess;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.ptrValue = lpThreadAttributes;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.ptrValue = dwStackSize;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpStartAddress;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[4].arg.ptrValue = lpParameter;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[5].arg.dwValue  = dwCreationFlags;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[6].arg.ptrValue = lpAttributeList;
    tm.data.apiCall.args[6].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[7].arg.ptrValue = lpThreadId;
    tm.data.apiCall.args[7].type         = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);

    return CreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}

LPVOID VirtualAlloc_HookHandler(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect,
) {
    TELEMETRY tm;
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId();
    tm.header.type = TM_TYPE_API_CALL;

    tm.data.apiCall.tid = GetCurrentThreadId();
    strncpy(tm.data.apiCall.dllName, "kernel32.dll", sizeof(tm.data.apiCall.dllName)-1);
    strncpy(tm.data.apiCall.funcName, "VirtualAlloc", sizeof(tm.data.apiCall.funcName)-1);
    
    tm.data.apiCall.args[0].arg.ptrValue = lpAddress;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.ptrValue = dwSize;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.dwValue = flAllocationType;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[3].arg.dwValue = flProtect;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_DWORD;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    if (flProtect != PAGE_EXECUTE_READWRITE) {
        return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    } else {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
}

LPVOID VirtualAlloc2_HookHandler(
    HANDLE                 Process,
    PVOID                  BaseAddress,
    SIZE_T                 Size,
    ULONG                  AllocationType,
    ULONG                  PageProtection,
    MEM_EXTENDED_PARAMETER *ExtendedParameters,
    ULONG                  ParameterCount,
) {
    TELEMETRY tm;
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId();
    tm.header.type = TM_TYPE_API_CALL;

    tm.data.apiCall.tid = GetCurrentThreadId();
    strncpy(tm.data.apiCall.dllName, "kernelbase.dll", sizeof(tm.data.apiCall.dllName)-1);
    strncpy(tm.data.apiCall.funcName, "VirtualAlloc2", sizeof(tm.data.apiCall.funcName)-1);
    
    tm.data.apiCall.args[0].arg.ptrValue = Process;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.ptrValue = BaseAddress;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.ptrValue = Size;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[3].arg.dwValue  = AllocationType;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[4].arg.dwValue  = PageProtection;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[5].arg.ptrValue = ExtendedParameters;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[6].arg.dwValue  = ParameterCount;
    tm.data.apiCall.args[6].type         = API_ARG_TYPE_DWORD;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    if (PageProtection != PAGE_EXECUTE_READWRITE) {
        return VirtualAlloc2(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount);
    } else {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
}

LPVOID VirtualAllocEx_HookHandler(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect,
) {
    TELEMETRY tm;
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId();
    tm.header.type = TM_TYPE_API_CALL;

    tm.data.apiCall.tid = GetCurrentThreadId();
    strncpy(tm.data.apiCall.dllName, "kernel32.dll", sizeof(tm.data.apiCall.dllName)-1);
    strncpy(tm.data.apiCall.funcName, "VirtualAllocEx", sizeof(tm.data.apiCall.funcName)-1);
    
    tm.data.apiCall.args[0].arg.ptrValue = hProcess;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = lpAddress;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[2].arg.ptrValue = dwSize;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[3].arg.dwValue = flAllocationType;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[4].arg.dwValue = flProtect;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_DWORD;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    if (flProtect != PAGE_EXECUTE_READWRITE) {
        return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    } else {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
}

BOOL VirtualProtect_HookHandler(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect,
) {
    TELEMETRY tm;
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId();
    tm.header.type = TM_TYPE_API_CALL;

    tm.data.apiCall.tid = GetCurrentThreadId();
    strncpy(tm.data.apiCall.dllName, "kernel32.dll", sizeof(tm.data.apiCall.dllName)-1);
    strncpy(tm.data.apiCall.funcName, "VirtualProtect", sizeof(tm.data.apiCall.funcName)-1);
    
    tm.data.apiCall.args[0].arg.ptrValue = lpAddress;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.ptrValue = dwSize;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.dwValue  = flNewProtect;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpflOldProtect;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

NTSTATUS NtAllocateVirtualMemory_HookHandler(
    HANDLE    ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect,
) {
    TELEMETRY tm;
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId();
    tm.header.type = TM_TYPE_API_CALL;

    tm.data.apiCall.tid = GetCurrentThreadId();
    strncpy(tm.data.apiCall.dllName, "ntdll.dll", sizeof(tm.data.apiCall.dllName)-1);
    strncpy(tm.data.apiCall.funcName, "NtAllocateVirtualMemory", sizeof(tm.data.apiCall.funcName)-1);
    
    tm.data.apiCall.args[0].arg.ptrValue = ProcessHandle;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = BaseAddress;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[2].arg.ptrValue = ZeroBits;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[3].arg.ptrValue = RegionSize;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[4].arg.dwValue  = AllocationType;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[5].arg.dwValue = Protect;
    tm.data.apiCall.args[5].type        = API_ARG_TYPE_DWORD;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    if (Protect != PAGE_EXECUTE_READWRITE) {
        return NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    } else {
        return STATUS_ACCESS_DENIED;
    }
}

NTSTATUS NtCreateThread_HookHandler(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOL CreateSuspended,
) {
    TELEMETRY tm;
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId();
    tm.header.type = TM_TYPE_API_CALL;

    tm.data.apiCall.tid = GetCurrentThreadId();
    strncpy(tm.data.apiCall.dllName, "ntdll.dll", sizeof(tm.data.apiCall.dllName)-1);
    strncpy(tm.data.apiCall.funcName, "NtCreateThread", sizeof(tm.data.apiCall.funcName)-1);
    
    tm.data.apiCall.args[0].arg.ptrValue = ThreadHandle;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.dwValue  = DesiredAccess;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[2].arg.ptrValue = ObjectAttributes;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[3].arg.ptrValue = ProcessHandle;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[4].arg.ptrValue = ClientId;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[5].arg.ptrValue = ThreadContext;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[6].arg.ptrValue = InitialTeb;
    tm.data.apiCall.args[6].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[7].arg.boolValue = CreateSuspended;
    tm.data.apiCall.args[7].type         = API_ARG_TYPE_BOOL;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

NTSTATUS NtCreateThreadEx_HookHandler(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PUSER_THREAD_START_ROUTINE StartRoutine,
    PVOID Argument,
    ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList,
) {
    TELEMETRY tm;
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId();
    tm.header.type = TM_TYPE_API_CALL;

    tm.data.apiCall.tid = GetCurrentThreadId();
    strncpy(tm.data.apiCall.dllName, "ntdll.dll", sizeof(tm.data.apiCall.dllName)-1);
    strncpy(tm.data.apiCall.funcName, "NtCreateThreadEx", sizeof(tm.data.apiCall.funcName)-1);
    
    tm.data.apiCall.args[0].arg.ptrValue = ThreadHandle;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.dwValue  = DesiredAccess;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[2].arg.ptrValue = ObjectAttributes;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[3].arg.ptrValue = ProcessHandle;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[4].arg.ptrValue = StartRoutine;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[5].arg.ptrValue = Argument;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[6].arg.dwValue = CreateFlags;
    tm.data.apiCall.args[6].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[7].arg.ptrValue = ZeroBits;
    tm.data.apiCall.args[7].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[8].arg.ptrValue = StackSize;
    tm.data.apiCall.args[8].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[9].arg.ptrValue = MaximumStackSize;
    tm.data.apiCall.args[9].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[10].arg.ptrValue = AttributeList;
    tm.data.apiCall.args[10].type         = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}