#include "hook.h"

//?================================================================================+
//?   These are the functions API hooks point to, for now they are just simply     |
//?   sending the call and args to agent via named pipes. Currently the telemetry  |
//?   packets are very inefficient, however they will be redesigned soon...        |
//?   This file contains functions regarding threads and processes.
//?================================================================================+
// TODO: convert HANDLEs to send Id instead

//*============================================+
//*    Creation of processes and threads       |
//*============================================+

HANDLE CreateRemoteThread_Handler(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId) {
    fprintf(stderr, "Inside CreateRemoteThread hook\n");
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 7);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "CreateRemoteThread", 7);

    fprintf(stderr, "debug print 2\n");

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

    if (lpThreadId == NULL) {
        args[6].arg.dwValue = 0;
    } else {
        args[6].arg.dwValue = *lpThreadId;
    }
    args[6].type         = API_ARG_TYPE_DWORD;

    fprintf(stderr, "debug print 3\n");
    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    // detect DLL hijacking by checking if start address is LoadLibrary*
    if ((LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_A].originalFunc
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_A].handler
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_W].originalFunc
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_W].handler
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_A].originalFunc
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_A].handler
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_W].originalFunc
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_W].handler) {
        fprintf(stderr, "\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    } else {
        fprintf(stderr, "no issue with address, access granted\n");
        return ((CREATEREMOTETHREAD)HookList[HOOK_CREATE_REMOTE_THREAD].originalFunc)(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
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
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);
        
    // detect DLL hijacking by checking if start address is LoadLibrary*
    if ((LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_A].originalFunc
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_A].handler
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_W].originalFunc
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_W].handler
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_A].originalFunc
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_A].handler
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_W].originalFunc
    || (LPVOID)lpStartAddress == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_W].handler) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    } else {
        return ((CREATEREMOTETHREADEX)HookList[HOOK_CREATE_REMOTE_THREAD_EX].originalFunc)(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
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
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    //TODO check thread start address
    // detect DLL hijacking by checking if start address is LoadLibrary*
    if ((LPVOID)ThreadContext->Rip == (LPVOID)HookList[HOOK_LOAD_LIBRARY_A].originalFunc
    || (LPVOID)ThreadContext->Rip == (LPVOID)HookList[HOOK_LOAD_LIBRARY_A].handler
    || (LPVOID)ThreadContext->Rip == (LPVOID)HookList[HOOK_LOAD_LIBRARY_W].originalFunc
    || (LPVOID)ThreadContext->Rip == (LPVOID)HookList[HOOK_LOAD_LIBRARY_W].handler
    || (LPVOID)ThreadContext->Rip == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_A].originalFunc
    || (LPVOID)ThreadContext->Rip == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_A].handler
    || (LPVOID)ThreadContext->Rip == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_W].originalFunc
    || (LPVOID)ThreadContext->Rip == (LPVOID)HookList[HOOK_LOAD_LIBRARY_EX_W].handler) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        return STATUS_ACCESS_DENIED;
    } else {
        return ((NTCREATETHREAD)HookList[HOOK_NT_CREATE_THREAD].originalFunc)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
    }
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
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    // detect DLL hijacking by checking if start address is LoadLibrary*
    if (StartRoutine == HookList[HOOK_LOAD_LIBRARY_A].originalFunc
    || StartRoutine == HookList[HOOK_LOAD_LIBRARY_A].handler
    || StartRoutine == HookList[HOOK_LOAD_LIBRARY_W].originalFunc
    || StartRoutine == HookList[HOOK_LOAD_LIBRARY_W].handler
    || StartRoutine == HookList[HOOK_LOAD_LIBRARY_EX_A].originalFunc
    || StartRoutine == HookList[HOOK_LOAD_LIBRARY_EX_A].handler
    || StartRoutine == HookList[HOOK_LOAD_LIBRARY_EX_W].originalFunc
    || StartRoutine == HookList[HOOK_LOAD_LIBRARY_EX_W].handler) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        return STATUS_ACCESS_DENIED;
    } else {
        return ((NTCREATETHREADEX)HookList[HOOK_NT_CREATE_THREAD_EX].originalFunc)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    }
}

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
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 10);
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "CreateProcessA", 10);

    API_ARG args[10];
    strncpy(args[0].arg.astrValue, lpApplicationName, sizeof(args[0].arg.astrValue) -1);
    args[0].arg.astrValue[sizeof(args[0].arg.astrValue)-1] = '\0';
    args[0].type = API_ARG_TYPE_ASTRING;

    strncpy(args[1].arg.astrValue, lpCommandLine, sizeof(args[1].arg.astrValue) -1);
    args[0].arg.astrValue[sizeof(args[0].arg.astrValue)-1] = '\0';
    args[1].type = API_ARG_TYPE_ASTRING;
    
    args[2].arg.ptrValue = lpProcessAttributes;
    args[2].type = API_ARG_TYPE_PTR;
    
    args[3].arg.ptrValue = lpThreadAttributes;
    args[3].type = API_ARG_TYPE_PTR;

    args[4].arg.boolValue = bInheritHandles;
    args[4].type = API_ARG_TYPE_BOOL;
    
    args[5].arg.dwValue = dwCreationFlags;
    args[5].type = API_ARG_TYPE_DWORD;

    args[6].arg.ptrValue = lpEnvironment;
    args[6].type = API_ARG_TYPE_PTR;

    strncpy(args[7].arg.astrValue, lpCurrentDirectory, sizeof(args[7].arg.astrValue) -1);
    args[7].arg.astrValue[sizeof(args[7].arg.astrValue) -1] = '\0';
    args[7].type = API_ARG_TYPE_ASTRING;

    args[8].arg.ptrValue = lpStartupInfo;
    args[8].type = API_ARG_TYPE_PTR;

    args[9].arg.ptrValue = lpProcessInformation;
    args[9].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((CREATEPROCESSA)HookList[HOOK_CREATE_PROCESS_A].originalFunc)(lpApplicationName, lpCommandLine, lpProcessAttributes,
    lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
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
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {

    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 10);
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "CreateProcessW", 10);

    API_ARG args[10];
    wcsncpy(args[0].arg.wstrValue, lpApplicationName, sizeof(args[0].arg.wstrValue) -1);
    args[0].arg.wstrValue[sizeof(args[0].arg.wstrValue)-1] = L'\0';
    args[0].type = API_ARG_TYPE_WSTRING;

    wcsncpy(args[1].arg.wstrValue, lpCommandLine, sizeof(args[1].arg.wstrValue) -1);
    args[1].arg.wstrValue[sizeof(args[1].arg.wstrValue)-1] = L'\0';
    args[1].type = API_ARG_TYPE_WSTRING;
    
    args[2].arg.ptrValue = lpProcessAttributes;
    args[2].type = API_ARG_TYPE_PTR;
    
    args[3].arg.ptrValue = lpThreadAttributes;
    args[3].type = API_ARG_TYPE_PTR;

    args[4].arg.boolValue = bInheritHandles;
    args[4].type = API_ARG_TYPE_BOOL;
    
    args[5].arg.dwValue = dwCreationFlags;
    args[5].type = API_ARG_TYPE_DWORD;

    args[6].arg.ptrValue = lpEnvironment;
    args[6].type = API_ARG_TYPE_PTR;

    wcsncpy(args[7].arg.wstrValue, lpCurrentDirectory, sizeof(args[7].arg.wstrValue) -1);
    args[7].arg.wstrValue[sizeof(args[7].arg.wstrValue)-1] = L'\0';
    args[7].type = API_ARG_TYPE_WSTRING;

    args[8].arg.ptrValue = lpStartupInfo;
    args[8].type = API_ARG_TYPE_PTR;

    args[9].arg.ptrValue = lpProcessInformation;
    args[9].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((CREATEPROCESSW)HookList[HOOK_CREATE_PROCESS_W].originalFunc)(lpApplicationName, lpCommandLine, lpProcessAttributes,
    lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL CreateProcessAsUserA_Handler(
    HANDLE                hToken,
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

    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 11);
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "CreateProcessAsUserA", 11);

    API_ARG args[11];
    args[0].arg.ptrValue = hToken;
    args[0].type = API_ARG_TYPE_PTR;

    strncpy(args[1].arg.astrValue, lpApplicationName, sizeof(args[1].arg.astrValue)-1);
    args[1].arg.astrValue[sizeof(args[1].arg.astrValue)-1] = '\0';
    args[1].type = API_ARG_TYPE_ASTRING;

    strncpy(args[2].arg.astrValue, lpCommandLine, sizeof(args[2].arg.astrValue)-1);
    args[2].arg.astrValue[sizeof(args[2].arg.astrValue)-1] = '\0';
    args[2].type = API_ARG_TYPE_ASTRING;

    args[3].arg.ptrValue = lpProcessAttributes;
    args[3].type = API_ARG_TYPE_PTR;

    args[4].arg.ptrValue = lpThreadAttributes;
    args[4].type = API_ARG_TYPE_PTR;

    args[5].arg.boolValue = bInheritHandles;
    args[5].type = API_ARG_TYPE_BOOL;

    args[6].arg.dwValue = dwCreationFlags;
    args[6].type = API_ARG_TYPE_DWORD;

    args[7].arg.ptrValue = lpEnvironment;
    args[7].type = API_ARG_TYPE_PTR;

    args[8].arg.ptrValue = (LPVOID)lpCurrentDirectory;
    args[8].type = API_ARG_TYPE_PTR;

    args[9].arg.ptrValue = lpStartupInfo;
    args[9].type = API_ARG_TYPE_PTR;

    args[10].arg.ptrValue = lpProcessInformation;
    args[10].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((CREATEPROCESSASUSERA)HookList[HOOK_CREATE_PROCESS_AS_USER_A].originalFunc)(hToken, lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL CreateProcessAsUserW_Handler(
    HANDLE                hToken,
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

    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 11);
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "CreateProcessAsUserW", 11);

    API_ARG args[11];
    args[0].arg.ptrValue = hToken;
    args[0].type = API_ARG_TYPE_PTR;

    wcsncpy(args[1].arg.wstrValue, lpApplicationName, sizeof(args[1].arg.wstrValue)-1);
    args[1].arg.wstrValue[sizeof(args[1].arg.wstrValue)-1] = L'\0';
    args[1].type = API_ARG_TYPE_WSTRING;

    wcsncpy(args[2].arg.wstrValue, lpCommandLine, sizeof(args[2].arg.wstrValue)-1);
    args[2].arg.wstrValue[sizeof(args[2].arg.wstrValue)-1] = L'\0';
    args[2].type = API_ARG_TYPE_WSTRING;

    args[3].arg.ptrValue = lpProcessAttributes;
    args[3].type = API_ARG_TYPE_PTR;

    args[4].arg.ptrValue = lpThreadAttributes;
    args[4].type = API_ARG_TYPE_PTR;

    args[5].arg.boolValue = bInheritHandles;
    args[5].type = API_ARG_TYPE_BOOL;

    args[6].arg.dwValue = dwCreationFlags;
    args[6].type = API_ARG_TYPE_DWORD;

    args[7].arg.ptrValue = lpEnvironment;
    args[7].type = API_ARG_TYPE_PTR;

    args[8].arg.ptrValue = (LPVOID)lpCurrentDirectory;
    args[8].type = API_ARG_TYPE_PTR;

    args[9].arg.ptrValue = lpStartupInfo;
    args[9].type = API_ARG_TYPE_PTR;

    args[10].arg.ptrValue = lpProcessInformation;
    args[10].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((CREATEPROCESSASUSERW)HookList[HOOK_CREATE_PROCESS_AS_USER_W].originalFunc)(hToken, lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

NTSTATUS NtCreateProcess_Handler(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle) {

    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 8);
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("ntdll.dll", "NtCreateProcess", 8);

    API_ARG args[8];
    args[0].arg.ptrValue = ProcessHandle;
    args[0].type = API_ARG_TYPE_PTR;

    args[1].arg.dwValue = DesiredAccess;
    args[1].type = API_ARG_TYPE_DWORD;

    args[2].arg.ptrValue = (LPVOID)ObjectAttributes;
    args[2].type = API_ARG_TYPE_PTR;

    args[3].arg.ptrValue = ParentProcess;
    args[3].type = API_ARG_TYPE_PTR;

    args[4].arg.boolValue = InheritObjectTable;
    args[4].type = API_ARG_TYPE_BOOL;

    args[5].arg.ptrValue = SectionHandle;
    args[5].type = API_ARG_TYPE_PTR;
    
    args[6].arg.ptrValue = DebugPort;
    args[6].type = API_ARG_TYPE_PTR;

    args[7].arg.ptrValue = TokenHandle;
    args[7].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((NTCREATEPROCESS)HookList[HOOK_NT_CREATE_PROCESS].originalFunc)(ProcessHandle, DesiredAccess,
    ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, TokenHandle);
}

NTSTATUS NtCreateProcessEx_Handler(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle,
    ULONG Reserved) {

    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 9);
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("ntdll.dll", "NtCreateProcessEx", 9);

    API_ARG args[9];
    args[0].arg.ptrValue = ProcessHandle;
    args[0].type = API_ARG_TYPE_PTR;

    args[1].arg.dwValue = DesiredAccess;
    args[1].type = API_ARG_TYPE_DWORD;

    args[2].arg.ptrValue = (LPVOID)ObjectAttributes;
    args[2].type = API_ARG_TYPE_PTR;

    args[3].arg.ptrValue = ParentProcess;
    args[3].type = API_ARG_TYPE_PTR;

    args[4].arg.dwValue = Flags;
    args[4].type = API_ARG_TYPE_DWORD;

    args[5].arg.ptrValue = SectionHandle;
    args[5].type = API_ARG_TYPE_PTR;
    
    args[6].arg.ptrValue = DebugPort;
    args[6].type = API_ARG_TYPE_PTR;

    args[7].arg.ptrValue = TokenHandle;
    args[7].type = API_ARG_TYPE_PTR;

    args[8].arg.dwValue = Reserved;
    args[8].type = API_ARG_TYPE_DWORD;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((NTCREATEPROCESSEX)HookList[HOOK_NT_CREATE_PROCESS_EX].originalFunc)(ProcessHandle, DesiredAccess,
    ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, TokenHandle, Reserved);
}

NTSTATUS NtCreateUserProcess_Handler(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    PCOBJECT_ATTRIBUTES ProcessObjectAttributes,
    PCOBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
    ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
    void* ProcessParameters, //PTRL_USR_PROCESS_PARAMETERS
    void* CreateInfo, // PPS_CREATE_INFO
    void* AttributeList) {
        
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 11);
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("ntdll.dll", "NtCreateUserProcess", 11);

    API_ARG args[11];
    args[0].arg.ptrValue = ProcessHandle;
    args[0].type = API_ARG_TYPE_PTR;

    args[1].arg.ptrValue = ThreadHandle;
    args[1].type = API_ARG_TYPE_PTR;

    args[2].arg.dwValue = ProcessDesiredAccess;
    args[2].type = API_ARG_TYPE_DWORD;

    args[3].arg.dwValue = ThreadDesiredAccess;
    args[3].type = API_ARG_TYPE_DWORD;

    args[4].arg.ptrValue = (LPVOID)ProcessObjectAttributes;
    args[4].type = API_ARG_TYPE_PTR;

    args[5].arg.ptrValue = (LPVOID)ThreadObjectAttributes;
    args[5].type = API_ARG_TYPE_PTR;

    args[6].arg.dwValue = ProcessFlags;
    args[6].type = API_ARG_TYPE_DWORD;

    args[7].arg.dwValue = ThreadFlags;
    args[7].type = API_ARG_TYPE_DWORD;

    args[8].arg.ptrValue = ProcessParameters;
    args[8].type = API_ARG_TYPE_PTR;

    args[9].arg.ptrValue = CreateInfo;
    args[9].type = API_ARG_TYPE_PTR;

    args[10].arg.ptrValue = AttributeList;
    args[10].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((NTCREATEUSERPROCESS)HookList[HOOK_NT_CREATE_USER_PROCESS].originalFunc)(ProcessHandle, ThreadHandle,
    ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
}

//*======================================================+
//*   Opening handles to processes, threads and tokens   |
//*======================================================+

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
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

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
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((NTOPENPROCESS)HookList[HOOK_NT_OPEN_PROCESS].originalFunc)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}
/*
HANDLE OpenThread(DWORD DesiredAccess, BOOL InheritHandle, DWORD ThreadId) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 3);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "OpenThread", 3);

    API_ARG args[3];
    args[0].arg.dwValue = DesiredAccess;
    args[0].type = API_ARG_TYPE_DWORD;

    args[0].arg.boolValue = InheritHandle;
    args[0].type = API_ARG_TYPE_BOOL;

    args[2].arg.dwValue = ThreadId;
    args[2].type = API_ARG_TYPE_DWORD;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((OPENTHREAD)HookList[HOOK_OPEN_THREAD].originalFunc)(DesiredAccess, InheritHandle, ThreadId);
}

//TODO: OpenThread Nt alternative

BOOL OpenProcessToken_Handler(HANDLE hProcess, DWORD DesiredAccess, PHANDLE hToken) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 3);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("advapi32.dll", "OpenProcessToken", 3);

    API_ARG args[3];
    arg[0].arg.ptrValue = hProcess;
    arg[0].type = API_ARG_TYPE_PTR;

    arg[1].arg.dwValue = DesiredAccess;
    arg[1].type = API_ARG_TYPE_DWORD;

    arg[2].arg.ptrValue = hToken;
    arg[2].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((OPENPROCESSTOKEN)HookList[HOOK_OPEN_PROCESS_TOKEN].originalFunc)(hProcess, DesiredAccess, hToken);
}

BOOL OpenThreadToken_Handler(HANDLE hThread, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE hToken) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 4);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("advapi32.dll", "OpenThreadToken", 4);

    API_ARG args[4];
    arg[0].arg.ptrValue = hThread;
    arg[0].type = API_ARG_TYPE_PTR;

    arg[1].arg.dwValue = DesiredAccess;
    arg[1].type = API_ARG_TYPE_PTR;

    arg[2].arg.boolValue = OpenAsSelf;
    arg[2].type = API_ARG_TYPE_BOOL;

    arg[3].arg.ptrValue = hToken;
    arg[3].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((OPENTHREADTOKEN)HookList[HOOK_OPEN_THREAD_TOKEN].originalFunc)(hThread, DesiredAccess, OpenAsSelf, hToken);
}

//TODO: OpenThreadToken and OpenProcessToken Nt alternatives

//*===============================+
//*    Manipulation of objects    |
//*===============================+

BOOL SetThreadContext_Handler(HANDLE arg0, const CONTEXT arg1) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 2);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "SetThreadContext", 2);

    API_ARG args[2];
    args[0].arg.ptrValue = arg0;
    args[0].type = API_ARG_TYPE_PTR;

    args[1].arg.ptrValue = arg1;
    args[1].type = API_ARG_TYPE_PTR;
    
    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((SETTHREADCONTEXT)HookList[HOOK_SET_THREAD_CONTEXT].originalFunc)(arg0, arg1);
}

BOOL GetThreadContext_Handler(HANDLE hThread, LPCONTEXT lpContext) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 2);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "GetThreadContext", 2);

    API_ARG args[2];
    args[0].arg.ptrValue = hThread;
    args[0].type = API_ARG_TYPE_PTR;

    args[1].arg.ptrValue = lpContext;
    args[1].type = API_ARG_TYPE_PTR;
 
    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((GETTHREADCONTEXT)HookList[HOOK_GET_THREAD_CONTEXT].originalFunc)(hThread, lpContext);
}

//TODO: Get/SetThreadContext Nt alternatives

DWORD SuspendThread_Handler(HANDLE hThread) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 1);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "SuspendThread", 1);

    API_ARG args[1];
    args[0].arg.ptrValue = hThread;
    args[0].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((SUSPENDTHREAD)HookList[HOOK_SUSPEND_THREAD].originalFunc)(hThread);
}

DWORD ResumeThread_Handler(HANDLE hThread) {
    size_t packetSize = GetTelemetryPacketSize(TM_TYPE_API_CALL, 1);
    // raw buffer for dynamically sized packets
    BYTE* packet = (BYTE*)malloc(packetSize);
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, packetSize - sizeof(TELEMETRY_HEADER));
    API_CALL_HEADER apiHeader = GetApiCallHeader("kernel32.dll", "ResumeThread", 1);

    API_ARG args[1];
    args[0].arg.ptrValue = hThread;
    args[0].type = API_ARG_TYPE_PTR;

    // copy each component into buffer to form packet
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &apiHeader, sizeof(apiHeader));
    memcpy(packet + sizeof(header) + sizeof(apiHeader), &args, sizeof(args));
    
    DWORD dwBytesWritten;
    WriteFile(hTelemetry, packet, packetSize, &dwBytesWritten, NULL);
    free(packet);

    return ((RESUMETHREAD)HookList[HOOK_RESUME_THREAD].originalFunc)(hThread);
}

//TODO: Suspend/ResumeThread Nt alternatives

*/