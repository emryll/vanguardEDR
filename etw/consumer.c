#include <windows.h>
#include <stdio.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <winnt.h>
#include "etw.h"

//?==================================================================================+
//?  This is the ETW consumer for the agent. This runs in a seperate process,        |
//?  and forwards the received events as telemetry packets to the agent via IPC.     |
//?  This should be ran as a service, so it will automatically respawn if shutdown.  |
//?==================================================================================+

BOOL singlePid = TRUE;
DWORD pid = 0;

// Microsoft-Windows-Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289}
GUID FileProviderGuid = { 0xEDD08927, 0x9CC4, 0x4E65, { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 } };

// Microsoft-Windows-Kernel-Registry {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
GUID RegistryProviderGuid = { 0x70EB4F03, 0xC1DE, 0x4F73, { 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD } };

TRACEHANDLE SessionHandle = 0;
TRACEHANDLE traceHandle = 0;

BOOL Running = TRUE;
/*
// The paths from events are wide strings, and start with something like " \Device\HarddiskVolume".
// This function converts it to a normal ansi string path with drive letters
LPCSTR NormalizeEventPath(WCHAR* path) {
    //? should you also return string len?
    //TODO: get all drive letters with GetLogicalDriveStrings
        //TODO: query device name for this letter with QueryDosDevice
        //TODO: compare it against path
}
*/
VOID WINAPI EventCallback(PEVENT_RECORD event) {
    SYSTEMTIME st;
    FILETIME ft;
    ft.dwLowDateTime = event->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = event->EventHeader.TimeStamp.HighPart;
    FileTimeToSystemTime(&ft, &st);

    //TODO: instead craft a telemetry packet
    //TODO: send the telemetry packet into hPipe

    // demo mode: only process specific process' events
    if (singlePid && event->EventHeader.ProcessId != pid) {
        return;
    }
    LPCSTR stars = "*********************************************************************";
    printf("\n%s\n", stars);
    printf("[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    // check which provider
    if (IsEqualGUID(&event->EventHeader.ProviderId, &FileProviderGuid)) {
        switch (event->EventHeader.EventDescriptor.Id) {    
            case EVENT_FILE_CREATE:
            printf("FILE CREATE EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_FILE_DELETE:
            printf("FILE DELETE EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_FILE_READ:
            printf("FILE READ EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_FILE_WRITE:
            printf("FILE WRITE EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_FILE_RENAME:
            printf("FILE WRITE EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            default:
            printf("UNKNOWN FILE EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
        }
    } else if (IsEqualGUID(&event->EventHeader.ProviderId, &RegistryProviderGuid)) {
        switch (event->EventHeader.EventDescriptor.Id) {    
            case EVENT_REG_CREATE_KEY:
            printf("REGISTRY CREATE KEY EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_REG_DELETE_KEY:
            printf("REGISTRY DELETE KEY EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_REG_SET_KEY_VALUE:
            printf("REGISTRY SET KEY EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            default:
            printf("UNKNOWN REGISTRY EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
        }
    }

    //* print attached data
    if (event->UserDataLength > 0) {
        //printf("UserDataLength %d:\n", event->UserDataLength);
        if (event->EventHeader.Flags != EVENT_HEADER_FLAG_STRING_ONLY) {
            PTRACE_EVENT_INFO info = NULL;
            ULONG infoSize = 0;
            TdhGetEventInformation(event, 0, NULL, info, &infoSize);
            info = (PTRACE_EVENT_INFO)malloc(infoSize);
            DWORD r = TdhGetEventInformation(event, 0, NULL, info, &infoSize);
            if (r != ERROR_SUCCESS) {
                printf("TdhGetEventInformation failed. r=%d, error: %d\n", r, GetLastError());
            } else {
            for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
                EVENT_PROPERTY_INFO propInfo = info->EventPropertyInfoArray[i];

                PROPERTY_DATA_DESCRIPTOR propDesc;
                RtlZeroMemory(&propDesc, sizeof(propDesc));

                propDesc.PropertyName = (ULONGLONG)((PBYTE)info + propInfo.NameOffset);
                propDesc.ArrayIndex = ULONG_MAX;

                // First, get the size of the property
                ULONG propertySize = 0;
                DWORD status = TdhGetPropertySize(event, 0, NULL, 1, &propDesc, &propertySize);
                if (status != ERROR_SUCCESS) {
                    printf("Failed to get size of property %lu\n", i);
                    continue;
                }

                // Allocate buffer for the data
                BYTE* buffer = (BYTE*)malloc(propertySize);
                if (!buffer) continue;

                    // Now actually get the property value
                    status = TdhGetProperty(event, 0, NULL, 1, &propDesc, propertySize, buffer);
                    if (status == ERROR_SUCCESS) {
                        //? Note: InType refers to the actual type, as in how the bytes are arranged (string, pointer, etc.)
                        //?     while the OutType refers to what the data represents/how its interpreted (GUID, time, string, etc.)

                        //printf("propInfo.nonStructType: %ls\n\tInType: %d\n\tOutType: %d\n\tMapNameOffset: %d\n",
                            //propDesc.PropertyName, propInfo.nonStructType.InType, propInfo.nonStructType.OutType, propInfo.nonStructType.MapNameOffset);
                        if (wcscmp((WCHAR*)propDesc.PropertyName, L"FileName") == 0) {
                            wprintf(L"\tFileName: %ls\n", (WCHAR*)buffer);
                        } else {
                            switch (propInfo.nonStructType.InType) {
                                case TDH_INTYPE_UNICODESTRING:
                                    wprintf(L"\t%ls: %ls\n", propDesc.PropertyName, (WCHAR*)buffer);
                                    break;
                                case TDH_INTYPE_POINTER:
                                    wprintf(L"\t%ls: 0x%p\n", propDesc.PropertyName, *(PVOID*)buffer);
                                    break;
                                case TDH_INTYPE_UINT32:
                                    wprintf(L"\t%ls: %d\n", propDesc.PropertyName, *(UINT32*)buffer);
                                    break;
                                case TDH_INTYPE_UINT16:
                                    wprintf(L"\t%ls: %d\n", propDesc.PropertyName, *(UINT16*)buffer);
                                    break;
                                case TDH_INTYPE_BOOLEAN:
                                    wprintf(L"\t%ls: %s\n", propDesc.PropertyName, *(BOOL*)buffer ? "TRUE" : "FALSE");
                                    break;
                                case TDH_INTYPE_ANSISTRING:
                                    wprintf(L"\t%ls: %s\n", propDesc.PropertyName, (char*)buffer);
                                    break;
                            }
                        }

                    } else {
                        printf("Failed to get property %lu\n", i);
                    }

                    free(buffer);
                }

                free(info);
            
            }
        }
        /*BYTE* data = (BYTE*)event->UserData;
        for (USHORT i = 0; i < event->UserDataLength; i++) {
            if (i % 20 == 0) {
                printf("\n\t");
            }
            printf("%02X ", data[i]);
        }*/

    }

    if (event->ExtendedDataCount > 0) {
        printf("ExtendedDataCount %d:\n", event->ExtendedDataCount);
    }

    printf("\n%s\n", stars);
}

BOOL IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_CLOSE_EVENT) {
        printf("\nStopping trace session...\n");

        Running = FALSE;

        // Stop logger
        if (SessionHandle) {
            EVENT_TRACE_PROPERTIES props = {0};
            props.Wnode.BufferSize = sizeof(props);
            ControlTrace(SessionHandle, SESSION_NAME, &props, EVENT_TRACE_CONTROL_STOP);
        }
        
        if (traceHandle != 0 && traceHandle != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(traceHandle);
        }
        return TRUE;
    }
    return FALSE;
}

// seperate thread so termination works
DWORD WINAPI TraceThread(LPVOID arg) {
    ULONG status = ProcessTrace(&traceHandle, 1, NULL, NULL);
    switch (status) {
        case ERROR_SUCCESS:
            printf("ProcessTrace exited with ERROR_SUCCESS\n");
            break;
        case ERROR_CANCELLED:
            printf("ProcessTrace exited with ERROR_CANCELLED\n");
            break;
        default:
            printf("ProcessTrace exited with %lu\n", status);
    }
    return 0;
}

int main(int argc, char** argv) {
    if (!IsAdmin()) {
        printf("You must have elevated privileges to use ETW.\n");
        return 1;
    }

    if (singlePid) {
        if (argc < 2) {
            printf("Not enough args. Usage: %s <pid>\n", argv[0]);
            return 1;
        }
        pid = atoi(argv[1]);
    }

    // set up ctrl+c to end session
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // set up session properties
    EVENT_TRACE_PROPERTIES* SessionProperties = {0};
    // EVENT_TRACE_PROPERTIES is dynamically sized so you cant use stack or it will overflow
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (strlen(SESSION_NAME) + 1);
    SessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!SessionProperties) {
        printf("ERROR: Failed to allocate memory.\n");
        return 1;
    }

    ZeroMemory(SessionProperties, bufferSize);
    SessionProperties->Wnode.BufferSize = bufferSize;
    SessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    SessionProperties->Wnode.ClientContext = 1; // QPC clock resolution
    //SessionProperties->Wnode.Guid = FileProviderGuid;
    SessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    SessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    
    // stop any existing session of same name
    ControlTrace(0, SESSION_NAME, SessionProperties, EVENT_TRACE_CONTROL_STOP);

    // start trace session
    ULONG status = StartTrace(&SessionHandle, SESSION_NAME, SessionProperties);
    if (status != ERROR_SUCCESS) {
        printf("Failed to start ETW tracing session, error %lu\n", status);
        free(SessionProperties);
        return 1;
    }

    status = EnableTraceEx2(SessionHandle, &FileProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        printf("WARNING: Failed to enable File provider (error %lu)\n", status);
    } else {
        printf("File provider enabled.\n");
    }
    
    status = EnableTraceEx2(SessionHandle, &RegistryProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        printf("WARNING: Failed to enable Registry provider (error %lu)\n", status);
    } else {
        printf("Registry provider enabled.\n");
    }

    EVENT_TRACE_LOGFILE traceFile = {0};
    traceFile.LoggerName = SESSION_NAME;
    traceFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceFile.EventRecordCallback = EventCallback;
    
    traceHandle = OpenTrace(&traceFile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        printf("ERROR: OpenTrace failed with error %lu\n", GetLastError());
        ControlTrace(SessionHandle, SESSION_NAME, SessionProperties, EVENT_TRACE_CONTROL_STOP);
        free(SessionProperties);
        return 1;
    }

    // Process events (blocks until stopped)
    status = ProcessTrace(&traceHandle, 1, NULL, NULL);
    if (status != ERROR_CANCELLED && status != ERROR_SUCCESS) {
        printf("ERROR: ProcessTrace failed with error %lu\n", status);
    }

    return 0;
}