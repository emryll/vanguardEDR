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
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 7);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "CreateRemoteThread", 7);

    API_ARG args[7];
    args[0].arg.ptrValue = hProcess;
    args[0].type         = API_ARG_TYPE_PTR;
    
    args[1].arg.ptrValue = lpThreadAttributes;
    args[1].type         = API_ARG_TYPE_PTR;

    args[2].arg.dwValue = dwStackSize;
    args[2].type         = API_ARG_TYPE_DWORD;
    
    args[3].arg.ptrValue = lpStartAddress;
    args[3].type         = API_ARG_TYPE_PTR;
    
    args[4].arg.ptrValue = lpParameter;
    args[4].type         = API_ARG_TYPE_PTR;
    
    args[5].arg.dwValue  = dwCreationFlags;
    args[5].type         = API_ARG_TYPE_DWORD;

    args[6].arg.dwValue = *lpThreadId;
    args[6].type         = API_ARG_TYPE_DWORD;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
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
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 8);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "CreateRemoteThreadEx", 8);

    API_ARG args[8];
    args[0].arg.ptrValue = hProcess;
    args[0].type         = API_ARG_TYPE_PTR;
    
    args[1].arg.ptrValue = lpThreadAttributes;
    args[1].type         = API_ARG_TYPE_PTR;

    args[2].arg.dwValue = dwStackSize;
    args[2].type         = API_ARG_TYPE_DWORD;
    
    args[3].arg.ptrValue = lpStartAddress;
    args[3].type         = API_ARG_TYPE_PTR;
    
    args[4].arg.ptrValue = lpParameter;
    args[4].type         = API_ARG_TYPE_PTR;
    
    args[5].arg.dwValue  = dwCreationFlags;
    args[5].type         = API_ARG_TYPE_DWORD;

    args[6].arg.ptrValue = lpAttributeList;
    args[6].type         = API_ARG_TYPE_PTR;

    args[7].arg.dwValue = *lpThreadId;
    args[7].type         = API_ARG_TYPE_DWORD;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);

    return ((CREATEREMOTETHREADEX)HookList[HOOK_CREATE_REMOTE_THREAD_EX].originalFunc)(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}



LPVOID VirtualAlloc_Handler(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 4);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "VirtualAlloc", 4);

    API_ARG args[4];
    args[0].arg.ptrValue = lpAddress;
    args[0].type         = API_ARG_TYPE_PTR;
    
    args[1].arg.dwValue = dwSize;
    args[1].type         = API_ARG_TYPE_DWORD;

    args[2].arg.dwValue = flAllocationType;
    args[2].type         = API_ARG_TYPE_DWORD;
    
    args[3].arg.dwValue = flProtect;
    args[3].type         = API_ARG_TYPE_DWORD;

  // debug prints
    fprintf(stderr, "VirtualAlloc hook\n\tHEADER\n\t\tpid: 0x%08X\n\t\ttype: 0x%08X\n\t\ttimestamp: 0x%X\n", tm.header.pid, tm.header.type, tm.header.timeStamp);
    fprintf(stderr, "\tDATA\n\t\ttid: 0x%08X\n\t\tdllName: %s\n\t\tfuncName: %s\n", tm.data.apiCall.tid, tm.data.apiCall.dllName, tm.data.apiCall.funcName);
    fprintf(stderr, "\n\t\tARG 0\n\t\ttype: 0x%08X\n\t\tPTR value: %p\n", tm.data.apiCall.args[0].type, tm.data.apiCall.args[0].arg.ptrValue);
    fprintf(stderr, "\n\t\tARG 1\n\t\ttype: 0x%08X\n\t\tDWORD value: 0x%08X\n", tm.data.apiCall.args[1].type, tm.data.apiCall.args[1].arg.dwValue);
    fprintf(stderr, "\n\t\tARG 2\n\t\ttype: 0x%08X\n\t\tDWORD value: 0x%08X\n", tm.data.apiCall.args[2].type, tm.data.apiCall.args[2].arg.dwValue);
    fprintf(stderr, "\n\t\tARG 3\n\t\ttype: 0x%08X\n\t\tDWORD value: 0x%08X\n", tm.data.apiCall.args[3].type, tm.data.apiCall.args[3].arg.dwValue);

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
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
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 7);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernelbase.dll", "VirtualAlloc2", 7);
    
    API_ARG args[7];
    args[0].arg.ptrValue = Process;
    args[0].type         = API_ARG_TYPE_PTR;
    
    args[1].arg.ptrValue = BaseAddress;
    args[1].type         = API_ARG_TYPE_PTR;

    args[2].arg.dwValue = Size;
    args[2].type         = API_ARG_TYPE_DWORD;
    
    args[3].arg.dwValue  = AllocationType;
    args[3].type         = API_ARG_TYPE_DWORD;

    args[4].arg.dwValue  = PageProtection;
    args[4].type         = API_ARG_TYPE_DWORD;

    args[5].arg.ptrValue = ExtendedParameters;
    args[5].type         = API_ARG_TYPE_PTR;

    args[6].arg.dwValue  = ParameterCount;
    args[6].type         = API_ARG_TYPE_DWORD;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
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
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 5);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "VirtualAllocEx", 5);
    
    API_ARG args[5];
    args[0].arg.ptrValue = hProcess;
    args[0].type         = API_ARG_TYPE_PTR;

    args[1].arg.ptrValue = lpAddress;
    args[1].type         = API_ARG_TYPE_PTR;
    
    args[2].arg.dwValue = dwSize;
    args[2].type         = API_ARG_TYPE_DWORD;

    args[3].arg.dwValue = flAllocationType;
    args[3].type         = API_ARG_TYPE_DWORD;
    
    args[4].arg.dwValue = flProtect;
    args[4].type         = API_ARG_TYPE_DWORD;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
    if (flProtect != PAGE_EXECUTE_READWRITE) {
        return ((VIRTUALALLOCEX)HookList[HOOK_VIRTUAL_ALLOC_EX].originalFunc)(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    } else {
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
}

BOOL VirtualProtect_Handler(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 4);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernelbase.dll", "VirtualProtect", 4);

    API_ARG args[4];
    args[0].arg.ptrValue = lpAddress;
    args[0].type         = API_ARG_TYPE_PTR;
    
    args[1].arg.dwValue = dwSize;
    args[1].type         = API_ARG_TYPE_DWORD;

    args[2].arg.dwValue  = flNewProtect;
    args[2].type         = API_ARG_TYPE_DWORD;
    
    args[3].arg.ptrValue = lpflOldProtect;
    args[3].type         = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
    return ((VIRTUALPROTECT)HookList[HOOK_VIRTUAL_PROTECT].originalFunc)(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL VirtualProtectEx_Handler(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 5);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernelbase.dll", "VirtualProtectEx", 5);
    
    API_ARG args[5];
    args[0].arg.ptrValue = hProcess;
    args[0].type         = API_ARG_TYPE_PTR;

    args[1].arg.ptrValue = lpAddress;
    args[1].type         = API_ARG_TYPE_PTR;
    
    args[2].arg.dwValue = dwSize;
    args[2].type         = API_ARG_TYPE_DWORD;

    args[3].arg.dwValue  = flNewProtect;
    args[3].type         = API_ARG_TYPE_DWORD;
    
    args[4].arg.ptrValue = lpflOldProtect;
    args[4].type         = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
    return ((VIRTUALPROTECTEX)HookList[HOOK_VIRTUAL_PROTECT_EX].originalFunc)(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

NTSTATUS NtProtectVM_Handler(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 5);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("ntdll.dll", "NtProtectVirtualMemory", 5);

    API_ARG args[5];
    args[0].arg.ptrValue = ProcessHandle;
    args[0].type         = API_ARG_TYPE_PTR;

    args[1].arg.ptrValue = *BaseAddress;
    args[1].type         = API_ARG_TYPE_PTR;
    
    args[2].arg.dwValue = *RegionSize;
    args[2].type         = API_ARG_TYPE_DWORD;

    args[3].arg.dwValue = NewProtection;
    args[3].type         = API_ARG_TYPE_DWORD;
    
    args[4].arg.dwValue  = *OldProtection;
    args[4].type         = API_ARG_TYPE_DWORD;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
    return ((NTPROTECTVM)HookList[HOOK_NT_PROTECT_VM].originalFunc)(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);
}

NTSTATUS NtAllocateVM_Handler(
    HANDLE    ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 6);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("ntdll.dll", "NtAllocateVirtualMemory", 6);

    API_ARG args[6]
    args[0].arg.ptrValue = ProcessHandle;
    args[0].type         = API_ARG_TYPE_PTR;

    args[1].arg.ptrValue = BaseAddress;
    args[1].type         = API_ARG_TYPE_PTR;
    
    args[2].arg.ptrValue = (PVOID)ZeroBits;
    args[2].type         = API_ARG_TYPE_PTR;

    args[3].arg.ptrValue = RegionSize;
    args[3].type         = API_ARG_TYPE_PTR;
    
    args[4].arg.dwValue  = AllocationType;
    args[4].type         = API_ARG_TYPE_DWORD;

    args[5].arg.dwValue = Protect;
    args[5].type        = API_ARG_TYPE_DWORD;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
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
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 7);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("ntdll.dll", "NtAllocateVirtualMemoryEx", 7);

    API_ARG args[7];
    args[0].arg.ptrValue = ProcessHandle;
    args[0].type         = API_ARG_TYPE_PTR;

    args[1].arg.ptrValue = BaseAddress;
    args[1].type         = API_ARG_TYPE_PTR;
    
    args[2].arg.ptrValue = RegionSize;
    args[2].type         = API_ARG_TYPE_PTR;
    
    args[3].arg.dwValue  = AllocationType;
    args[3].type         = API_ARG_TYPE_DWORD;

    args[4].arg.dwValue = Protect;
    args[4].type        = API_ARG_TYPE_DWORD;

    args[5].arg.ptrValue = ExtendedParameters;
    args[5].type         = API_ARG_TYPE_PTR;

    args[6].arg.dwValue = ExtendedParameterCount;
    args[6].type        = API_ARG_TYPE_DWORD;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
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
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 7);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("ntdll.dll", "NtCreateThread", 7);
    
    API_ARG args[8];
    args[0].arg.ptrValue  = ThreadHandle;
    args[0].type          = API_ARG_TYPE_PTR;

    args[1].arg.dwValue   = DesiredAccess;
    args[1].type          = API_ARG_TYPE_DWORD;
    
    args[2].arg.ptrValue  = (PVOID)ObjectAttributes;
    args[2].type          = API_ARG_TYPE_PTR;

    args[3].arg.ptrValue  = ProcessHandle;
    args[3].type          = API_ARG_TYPE_PTR;
    
    args[4].arg.ptrValue  = ClientId;
    args[4].type          = API_ARG_TYPE_PTR;

    args[5].arg.ptrValue  = ThreadContext;
    args[5].type          = API_ARG_TYPE_PTR;

    args[6].arg.ptrValue  = InitialTeb;
    args[6].type          = API_ARG_TYPE_PTR;
    
    args[7].arg.boolValue = CreateSuspended;
    args[7].type          = API_ARG_TYPE_BOOL;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
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
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 11);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("ntdll.dll", "NtCreateThreadEx", 11);

    API_ARG args[11];
    args[0].arg.ptrValue = ThreadHandle;
    args[0].type         = API_ARG_TYPE_PTR;

    args[1].arg.dwValue  = DesiredAccess;
    args[1].type         = API_ARG_TYPE_DWORD;
    
    args[2].arg.ptrValue = (PVOID)ObjectAttributes;
    args[2].type         = API_ARG_TYPE_PTR;

    args[3].arg.ptrValue = ProcessHandle;
    args[3].type         = API_ARG_TYPE_PTR;
    
    args[4].arg.ptrValue = StartRoutine;
    args[4].type         = API_ARG_TYPE_PTR;

    args[5].arg.ptrValue = Argument;
    args[5].type         = API_ARG_TYPE_PTR;

    args[6].arg.dwValue = CreateFlags;
    args[6].type         = API_ARG_TYPE_DWORD;
    
    args[7].arg.dwValue = ZeroBits;
    args[7].type         = API_ARG_TYPE_DWORD;

    args[8].arg.dwValue = StackSize;
    args[8].type         = API_ARG_TYPE_DWORD;

    args[9].arg.dwValue = MaximumStackSize;
    args[9].type         = API_ARG_TYPE_DWORD;

    args[10].arg.ptrValue = AttributeList;
    args[10].type         = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
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
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 3);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "OpenProcess", 3);

    API_ARG args[3];
    args[0].arg.dwValue = access;
    args[0].type = API_ARG_TYPE_DWORD;

    args[1].arg.boolValue = inherit;
    args[1].type = API_ARG_TYPE_BOOL;

    args[2].arg.dwValue = pid;
    args[2].type = API_ARG_TYPE_DWORD;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
    return ((OPENPROCESS)HookList[HOOK_OPEN_PROCESS].originalFunc)(access, inherit, pid);
}

NTSTATUS NtOpenProcess_Handler(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 4);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("ntdll.dll", "NtOpenProcess", 4);

    API_ARG args[4];
    args[0].arg.ptrValue = ProcessHandle;
    args[0].type = API_ARG_TYPE_PTR;

    args[1].arg.dwValue = DesiredAccess;
    args[1].type = API_ARG_TYPE_DWORD;
    
    args[2].arg.ptrValue = (PVOID)ObjectAttributes;
    args[2].type = API_ARG_TYPE_PTR;
    
    args[3].arg.ptrValue = ClientId;
    args[3].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
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
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 4);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("user32.dll", "MessageBoxA", 4);
    
    API_ARG args[4];
    args[0].arg.ptrValue = hWnd;
    args[0].type = API_ARG_TYPE_PTR;

    strncpy(tm.data.apiCall.args[1].arg.astrValue, caption, sizeof(tm.data.apiCall.args[1].arg.astrValue) -1);
    args[1].arg.astrValue[sizeof(tm.data.apiCall.args[1].arg.astrValue)] = '\0';
    args[1].type = API_ARG_TYPE_ASTRING;
    
    strncpy(tm.data.apiCall.args[2].arg.astrValue, text, sizeof(tm.data.apiCall.args[2].arg.astrValue) -1);
    args[2].arg.astrValue[sizeof(tm.data.apiCall.args[2].arg.astrValue)] = '\0';
    args[2].type = API_ARG_TYPE_ASTRING;
    
    args[3].arg.dwValue = type;
    args[3].type = API_ARG_TYPE_DWORD;

    // debug prints
    fprintf(stderr, "full packet size: %d\nsizeof data: %d\nsizeof header: %d\n", sizeof(tm), sizeof(tm.data), sizeof(tm.header));
    fprintf(stderr, "MessageBox hook\n\tHEADER\n\t\tpid: 0x%08X\n\t\ttype: 0x%08X\n\t\ttimestamp: 0x%X\n", tm.header.pid, tm.header.type, tm.header.timeStamp);
    fprintf(stderr, "\tDATA\n\t\ttid: 0x%08X\n\t\tdllName: %s\n\t\tfuncName: %s\n", tm.data.apiCall.tid, tm.data.apiCall.dllName, tm.data.apiCall.funcName);
    fprintf(stderr, "\n\t\tARG 0\n\t\ttype: 0x%08X\n\t\tPTR value: %p\n", tm.data.apiCall.args[0].type, tm.data.apiCall.args[0].arg.ptrValue);
    fprintf(stderr, "\n\t\tARG 1\n\t\ttype: 0x%08X\n\t\tANSI value: %s\n", tm.data.apiCall.args[1].type, tm.data.apiCall.args[1].arg.astrValue);
    fprintf(stderr, "\n\t\tARG 2\n\t\ttype: 0x%08X\n\t\tANSI value: %s\n", tm.data.apiCall.args[2].type, tm.data.apiCall.args[2].arg.astrValue);
    fprintf(stderr, "\n\t\tARG 3\n\t\ttype: 0x%08X\n\t\tDWORD value: 0x%08X\n", tm.data.apiCall.args[3].type, tm.data.apiCall.args[3].arg.dwValue);

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet, &apiHeader, sizeof(apiHeader));
    memcpy(packet, &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
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
