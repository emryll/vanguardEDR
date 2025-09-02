#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "hook.h"

#define STATUS_ACCESS_DENIED 0xC0000022
//?================================================================================+
//?   These are the functions API hooks point to, for now they are just simply     |
//?   sending the call and args to agent via named pipes. Currently the telemetry  |
//?   packets are very inefficient, however they will be redesigned soon...        |
//?================================================================================+

HANDLE CreateRemoteThread_Handler(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", "CreateRemoteThread");
    
    tm.data.apiCall.args[0].arg.ptrValue = hProcess;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.ptrValue = lpThreadAttributes;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.dwValue = dwStackSize;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpStartAddress;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[4].arg.ptrValue = lpParameter;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[5].arg.dwValue  = dwCreationFlags;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[6].arg.dwValue = *lpThreadId;
    tm.data.apiCall.args[6].type         = API_ARG_TYPE_DWORD;

    FillEmptyArgs(&tm, 7);
    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((CREATEREMOTETHREAD)HookList[HOOK_CREATE_REMOTE_THREAD].originalFunc)(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HANDLE CreateRemoteThreadEx_Handler(
    HANDLE                       hProcess,
    LPSECURITY_ATTRIBUTES        lpThreadAttributes,
    SIZE_T                       dwStackSize,
    LPTHREAD_START_ROUTINE       lpStartAddress,
    LPVOID                       lpParameter,
    DWORD                        dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD                      lpThreadId) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", "CreateRemoteThreadEx");
    
    tm.data.apiCall.args[0].arg.ptrValue = hProcess;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.ptrValue = lpThreadAttributes;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.dwValue = dwStackSize;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpStartAddress;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[4].arg.ptrValue = lpParameter;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[5].arg.dwValue  = dwCreationFlags;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[6].arg.ptrValue = lpAttributeList;
    tm.data.apiCall.args[6].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[7].arg.dwValue = *lpThreadId;
    tm.data.apiCall.args[7].type         = API_ARG_TYPE_DWORD;

    FillEmptyArgs(&tm, 8);
    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);

    return ((CREATEREMOTETHREADEX)HookList[HOOK_CREATE_REMOTE_THREAD_EX].originalFunc)(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}



LPVOID VirtualAlloc_Handler(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", "VirtualAlloc");

    tm.data.apiCall.args[0].arg.ptrValue = lpAddress;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.dwValue = dwSize;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[2].arg.dwValue = flAllocationType;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[3].arg.dwValue = flProtect;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_DWORD;

    fprintf(stderr, "VirtualAlloc hook\n\tHEADER\n\t\tpid: 0x%08X\n\t\ttype: 0x%08X\n\t\ttimestamp: 0x%X\n", tm.header.pid, tm.header.type, tm.header.timeStamp);
    fprintf(stderr, "\tDATA\n\t\ttid: 0x%08X\n\t\tdllName: %s\n\t\tfuncName: %s\n", tm.data.apiCall.tid, tm.data.apiCall.dllName, tm.data.apiCall.funcName);
    fprintf(stderr, "\n\t\tARG 0\n\t\ttype: 0x%08X\n\t\tPTR value: %p\n", tm.data.apiCall.args[0].type, tm.data.apiCall.args[0].arg.ptrValue);
    fprintf(stderr, "\n\t\tARG 1\n\t\ttype: 0x%08X\n\t\tDWORD value: 0x%08X\n", tm.data.apiCall.args[1].type, tm.data.apiCall.args[1].arg.dwValue);
    fprintf(stderr, "\n\t\tARG 2\n\t\ttype: 0x%08X\n\t\tDWORD value: 0x%08X\n", tm.data.apiCall.args[2].type, tm.data.apiCall.args[2].arg.dwValue);
    fprintf(stderr, "\n\t\tARG 3\n\t\ttype: 0x%08X\n\t\tDWORD value: 0x%08X\n", tm.data.apiCall.args[3].type, tm.data.apiCall.args[3].arg.dwValue);


    FillEmptyArgs(&tm, 4);
    DWORD dwBytesWritten;
    BOOL ok = WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    if (!ok) {
        fprintf(stderr, "[virtualalloc] failed to write to telemetry pipe: %d\n", GetLastError());
    } else {
        fprintf(stderr, "size of TELEMETRY: %d\n", sizeof(tm));
    }
    if (flProtect != PAGE_EXECUTE_READWRITE) {
        return ((VIRTUALALLOC)HookList[HOOK_VIRTUAL_ALLOC].originalFunc)(lpAddress, dwSize, flAllocationType, flProtect);
    } else {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
}

LPVOID VirtualAlloc2_Handler(
    HANDLE                 Process,
    PVOID                  BaseAddress,
    SIZE_T                 Size,
    ULONG                  AllocationType,
    ULONG                  PageProtection,
    MEM_EXTENDED_PARAMETER *ExtendedParameters,
    ULONG                  ParameterCount) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernelbase.dll", "VirtualAlloc2");
    FillEmptyArgs(&tm, 7);
    
    tm.data.apiCall.args[0].arg.ptrValue = Process;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.ptrValue = BaseAddress;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.dwValue = Size;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;
    
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
        return ((VIRTUALALLOC2)HookList[HOOK_VIRTUAL_ALLOC2].originalFunc)(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount);
    } else {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
}

LPVOID VirtualAllocEx_Handler(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", "VirtualAllocEx");
    FillEmptyArgs(&tm, 5);
    
    tm.data.apiCall.args[0].arg.ptrValue = hProcess;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = lpAddress;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[2].arg.dwValue = dwSize;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[3].arg.dwValue = flAllocationType;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[4].arg.dwValue = flProtect;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_DWORD;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    if (flProtect != PAGE_EXECUTE_READWRITE) {
        return ((VIRTUALALLOCEX)HookList[HOOK_VIRTUAL_ALLOC_EX].originalFunc)(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    } else {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
}

BOOL VirtualProtect_Handler(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", "VirtualProtect");
    FillEmptyArgs(&tm, 4);
    
    tm.data.apiCall.args[0].arg.ptrValue = lpAddress;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[1].arg.dwValue = dwSize;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[2].arg.dwValue  = flNewProtect;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpflOldProtect;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((VIRTUALPROTECT)HookList[HOOK_VIRTUAL_PROTECT].originalFunc)(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL VirtualProtectEx_Handler(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", "VirtualProtectEx");
    FillEmptyArgs(&tm, 5);
    
    tm.data.apiCall.args[0].arg.ptrValue = hProcess;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = lpAddress;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[2].arg.dwValue = dwSize;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[3].arg.dwValue  = flNewProtect;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[4].arg.ptrValue = lpflOldProtect;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((VIRTUALPROTECTEX)HookList[HOOK_VIRTUAL_PROTECT_EX].originalFunc)(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

NTSTATUS NtProtectVM_Handler(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "ntdll.dll", "NtProtectVirtualMemory");
    FillEmptyArgs(&tm, 5);

    tm.data.apiCall.args[0].arg.ptrValue = ProcessHandle;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = *BaseAddress;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[2].arg.dwValue = *RegionSize;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[3].arg.dwValue = NewProtection;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[4].arg.dwValue  = *OldProtection;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_DWORD;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((NTPROTECTVM)HookList[HOOK_NT_PROTECT_VM].originalFunc)(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);
}

NTSTATUS NtAllocateVM_Handler(
    HANDLE    ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "ntdll.dll", "NtAllocateVirtualMemory");
    FillEmptyArgs(&tm, 6);

    tm.data.apiCall.args[0].arg.ptrValue = ProcessHandle;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = BaseAddress;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[2].arg.ptrValue = (PVOID)ZeroBits;
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
        return ((NTALLOCVM)HookList[HOOK_NT_ALLOC_VM].originalFunc)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    } else {
        return STATUS_ACCESS_DENIED;
    }
}

NTSTATUS NtAllocateVMEx_Handler(
    HANDLE    ProcessHandle,
    PVOID     *BaseAddress,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "ntdll.dll", "NtAllocateVirtualMemoryEx");
    FillEmptyArgs(&tm, 7);

    tm.data.apiCall.args[0].arg.ptrValue = ProcessHandle;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = BaseAddress;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[2].arg.ptrValue = RegionSize;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[3].arg.dwValue  = AllocationType;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[4].arg.dwValue = Protect;
    tm.data.apiCall.args[4].type        = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[5].arg.ptrValue = ExtendedParameters;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[6].arg.dwValue = ExtendedParameterCount;
    tm.data.apiCall.args[6].type        = API_ARG_TYPE_DWORD;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    if (Protect != PAGE_EXECUTE_READWRITE) {
        return ((NTALLOCVMEX)HookList[HOOK_NT_ALLOC_VM_EX].originalFunc)(ProcessHandle, BaseAddress, RegionSize, AllocationType, Protect, ExtendedParameters, ExtendedParameterCount);
    } else {
        return STATUS_ACCESS_DENIED;
    }
}

NTSTATUS NtCreateThread_Handler(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    void* InitialTeb, //PINITIAL_TEB
    BOOL CreateSuspended) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "ntdll.dll", "NtCreateThread");
    FillEmptyArgs(&tm, 8);
    
    tm.data.apiCall.args[0].arg.ptrValue = ThreadHandle;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.dwValue  = DesiredAccess;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[2].arg.ptrValue = (PVOID)ObjectAttributes;
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
    return ((NTCREATETHREAD)HookList[HOOK_NT_CREATE_THREAD].originalFunc)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

NTSTATUS NtCreateThreadEx_Handler(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    void* StartRoutine, //PUSER_THREAD_START_ROUTINE
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    void* AttributeList) { // PPS_ATTRIBUTE_LIST
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "ntdll.dll", "NtCreateThreadEx");
    
    tm.data.apiCall.args[0].arg.ptrValue = ThreadHandle;
    tm.data.apiCall.args[0].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.dwValue  = DesiredAccess;
    tm.data.apiCall.args[1].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[2].arg.ptrValue = (PVOID)ObjectAttributes;
    tm.data.apiCall.args[2].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[3].arg.ptrValue = ProcessHandle;
    tm.data.apiCall.args[3].type         = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[4].arg.ptrValue = StartRoutine;
    tm.data.apiCall.args[4].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[5].arg.ptrValue = Argument;
    tm.data.apiCall.args[5].type         = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[6].arg.dwValue = CreateFlags;
    tm.data.apiCall.args[6].type         = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[7].arg.dwValue = ZeroBits;
    tm.data.apiCall.args[7].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[8].arg.dwValue = StackSize;
    tm.data.apiCall.args[8].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[9].arg.dwValue = MaximumStackSize;
    tm.data.apiCall.args[9].type         = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[10].arg.ptrValue = AttributeList;
    tm.data.apiCall.args[10].type         = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((NTCREATETHREADEX)HookList[HOOK_NT_CREATE_THREAD_EX].originalFunc)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}
/*
DWORD QueueUserAPC_Handler(PAPCFUNC arg0, HANDLE arg1, ULONG_PTR arg2) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_QUEUE_USER_APC);
    FillEmptyArgs(&tm, 3);

    tm.data.apiCall.args[0].arg.ptrValue = arg0;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = arg1;
    tm.data.apiCall.args[1].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.ptrValue = arg2;
    tm.data.apiCall.args[2].type = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((QUEUEUSERAPC)HookList[HOOK_QUEUE_USER_APC].originalFunc)(arg0, arg1, arg2);
}

BOOL QueueUserAPC2_Handler(PAPCFUNC arg0, HANDLE arg1, ULONG_PTR arg2, QUEUE_USER_APC_FLAGS arg3) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_QUEUE_USER_APC2);
    FillEmptyArgs(&tm, 4);

    tm.data.apiCall.args[0].arg.ptrValue = arg0;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = arg1;
    tm.data.apiCall.args[1].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.ptrValue = arg2;
    tm.data.apiCall.args[2].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[3].arg.ptrValue = arg3;
    tm.data.apiCall.args[3].type = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((QUEUEUSERAPC2)HookList[HOOK_QUEUE_USER_APC2].originalFunc)(arg0, arg1, arg2, arg3);
}
*/
HANDLE OpenProcess_Handler(DWORD access, BOOL inherit, DWORD pid) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", "OpenProcess");
    FillEmptyArgs(&tm, 3);

    tm.data.apiCall.args[0].arg.dwValue = access;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[1].arg.boolValue = inherit;
    tm.data.apiCall.args[1].type = API_ARG_TYPE_BOOL;

    tm.data.apiCall.args[2].arg.dwValue = pid;
    tm.data.apiCall.args[2].type = API_ARG_TYPE_DWORD;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((OPENPROCESS)HookList[HOOK_OPEN_PROCESS].originalFunc)(access, inherit, pid);
}

NTSTATUS NtOpenProcess_Handler(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "ntdll.dll", "NtOpenProcess");
    FillEmptyArgs(&tm, 4);

    tm.data.apiCall.args[0].arg.ptrValue = ProcessHandle;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.dwValue = DesiredAccess;
    tm.data.apiCall.args[1].type = API_ARG_TYPE_DWORD;
    
    tm.data.apiCall.args[2].arg.ptrValue = (PVOID)ObjectAttributes;
    tm.data.apiCall.args[2].type = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[3].arg.ptrValue = ClientId;
    tm.data.apiCall.args[3].type = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((NTOPENPROCESS)HookList[HOOK_NT_OPEN_PROCESS].originalFunc)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}
/*
BOOL SetThreadContext_Handler(HANDLE arg0, const CONTEXT arg1) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", "SetThreadContext");
    FillEmptyArgs(&tm, 2);

    tm.data.apiCall.args[0].arg.ptrValue = arg0;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = arg1;
    tm.data.apiCall.args[1].type = API_ARG_TYPE_PTR;
    
    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((SETTHREADCONTEXT)HookList[HOOK_SET_THREAD_CONTEXT].originalFunc)(arg0, arg1);
}
*/
int MessageBoxA_Handler(HWND hWnd, LPCSTR caption, LPCSTR text, UINT type) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "user32.dll", "MessageBoxA");
    FillEmptyArgs(&tm, 4);
    
    tm.data.apiCall.args[0].arg.ptrValue = hWnd;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_PTR;

    strncpy(tm.data.apiCall.args[1].arg.astrValue, caption, sizeof(tm.data.apiCall.args[1].arg.astrValue) -1);
    tm.data.apiCall.args[1].arg.astrValue[sizeof(tm.data.apiCall.args[1].arg.astrValue)] = '\0';
    tm.data.apiCall.args[1].type = API_ARG_TYPE_ASTRING;
    
    strncpy(tm.data.apiCall.args[2].arg.astrValue, text, sizeof(tm.data.apiCall.args[2].arg.astrValue) -1);
    tm.data.apiCall.args[2].arg.astrValue[sizeof(tm.data.apiCall.args[2].arg.astrValue)] = '\0';
    tm.data.apiCall.args[2].type = API_ARG_TYPE_ASTRING;
    
    tm.data.apiCall.args[3].arg.dwValue = type;
    tm.data.apiCall.args[3].type = API_ARG_TYPE_DWORD;

    fprintf(stderr, "full packet size: %d\nsizeof data: %d\nsizeof header: %d\n", sizeof(tm), sizeof(tm.data), sizeof(tm.header));
    fprintf(stderr, "MessageBox hook\n\tHEADER\n\t\tpid: 0x%08X\n\t\ttype: 0x%08X\n\t\ttimestamp: 0x%X\n", tm.header.pid, tm.header.type, tm.header.timeStamp);
    fprintf(stderr, "\tDATA\n\t\ttid: 0x%08X\n\t\tdllName: %s\n\t\tfuncName: %s\n", tm.data.apiCall.tid, tm.data.apiCall.dllName, tm.data.apiCall.funcName);
    fprintf(stderr, "\n\t\tARG 0\n\t\ttype: 0x%08X\n\t\tPTR value: %p\n", tm.data.apiCall.args[0].type, tm.data.apiCall.args[0].arg.ptrValue);
    fprintf(stderr, "\n\t\tARG 1\n\t\ttype: 0x%08X\n\t\tANSI value: %s\n", tm.data.apiCall.args[1].type, tm.data.apiCall.args[1].arg.astrValue);
    fprintf(stderr, "\n\t\tARG 2\n\t\ttype: 0x%08X\n\t\tANSI value: %s\n", tm.data.apiCall.args[2].type, tm.data.apiCall.args[2].arg.astrValue);
    fprintf(stderr, "\n\t\tARG 3\n\t\ttype: 0x%08X\n\t\tDWORD value: 0x%08X\n", tm.data.apiCall.args[3].type, tm.data.apiCall.args[3].arg.dwValue);

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((MESSAGEBOXA)HookList[HOOK_MESSAGE_BOX_A].originalFunc)(hWnd, "Hooked!", "Hooked!", type);
}
/*
BOOL CreateProcessA_Handler(
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
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_CREATE_PROCESS_A);
    FillEmptyArgs(&tm, 10);

    strncpy(tm.data.apiCall.args[0].arg.astrValue, lpApplicationName, sizeof(tm.data.apiCall.args[0].arg.astrValue) -1);
    tm.data.apiCall.args[0].arg.astrValue = '\0';
    tm.data.apiCall.args[0].type = API_ARG_TYPE_ASTRING;

    strncpy(tm.data.apiCall.args[1].arg.astrValue, lpCommandLine, sizeof(tm.data.apiCall.args[1].arg.astrValue) -1);
    tm.data.apiCall.args[1].arg.astrValue = '\0';
    tm.data.apiCall.args[1].type = API_ARG_TYPE_ASTRING;
    
    tm.data.apiCall.args[2].arg.ptrValue = lpProcessAttributes;
    tm.data.apiCall.args[2].type = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpThreadAttributes;
    tm.data.apiCall.args[3].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[4].arg.boolValue = bInheritHandles;
    tm.data.apiCall.args[4].type = API_ARG_TYPE_BOOL;
    
    tm.data.apiCall.args[5].arg.dwValue = dwCreationFlags;
    tm.data.apiCall.args[5].type = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[6].arg.ptrValue = lpEnvironment;
    tm.data.apiCall.args[6].type = API_ARG_TYPE_PTR;

    strncpy(tm.data.apiCall.args[7].arg.astrValue, lpCurrentDirectory, sizeof(tm.data.apiCall.args[7].arg.astrValue) -1);
    tm.data.apiCall.args[7].arg.astrValue = '\0';
    tm.data.apiCall.args[7].type = API_ARG_TYPE_ASTRING;

    tm.data.apiCall.args[8].arg.ptrValue = lpStartupInfo;
    tm.data.apiCall.args[8].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[9].arg.ptrValue = lpProcessInformation;
    tm.data.apiCall.args[9].type = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((CREATEPROCESSA)HookList[HOOK_CREATE_PROCESS_A].originalFunc)();
}

BOOL CreateProcessW_Handler(
    LPCWSTR                lpApplicationName,
    LPWSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_CREATE_PROCESS_A);
    FillEmptyArgs(&tm, 10);

    wcsncpy(tm.data.apiCall.args[0].arg.wstrValue, lpApplicationName, sizeof(tm.data.apiCall.args[0].arg.astrValue) -1);
    tm.data.apiCall.args[0].arg.astrValue = '\0';
    tm.data.apiCall.args[0].type = API_ARG_TYPE_ASTRING;

    strncpy(tm.data.apiCall.args[1].arg.astrValue, lpCommandLine, sizeof(tm.data.apiCall.args[1].arg.astrValue) -1);
    tm.data.apiCall.args[1].arg.astrValue = '\0';
    tm.data.apiCall.args[1].type = API_ARG_TYPE_ASTRING;
    
    tm.data.apiCall.args[2].arg.ptrValue = lpProcessAttributes;
    tm.data.apiCall.args[2].type = API_ARG_TYPE_PTR;
    
    tm.data.apiCall.args[3].arg.ptrValue = lpThreadAttributes;
    tm.data.apiCall.args[3].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[4].arg.boolValue = bInheritHandles;
    tm.data.apiCall.args[4].type = API_ARG_TYPE_BOOL;
    
    tm.data.apiCall.args[5].arg.dwValue = dwCreationFlags;
    tm.data.apiCall.args[5].type = API_ARG_TYPE_DWORD;

    tm.data.apiCall.args[6].arg.ptrValue = lpEnvironment;
    tm.data.apiCall.args[6].type = API_ARG_TYPE_PTR;

    strncpy(tm.data.apiCall.args[7].arg.astrValue, lpCurrentDirectory, sizeof(tm.data.apiCall.args[7].arg.astrValue) -1);
    tm.data.apiCall.args[7].arg.astrValue = '\0';
    tm.data.apiCall.args[7].type = API_ARG_TYPE_ASTRING;

    tm.data.apiCall.args[8].arg.ptrValue = lpStartupInfo;
    tm.data.apiCall.args[8].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[9].arg.ptrValue = lpProcessInformation;
    tm.data.apiCall.args[9].type = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((CREATEPROCESSA)HookList[HOOK_CREATE_PROCESS_A].originalFunc)();
}*/