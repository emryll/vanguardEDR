#include <windows.h>
#include <stdio.h>
#include "etw.h"

HANDLE hPipe;

void ShutdownWaiter() {
    while(1) {
        ETW_CMD packet;
        BOOL ok = ReadFull(hPipe, &packet, sizeof(packet));
        if (!ok) {
            printf("[debug] failed to read from pipe, error: %d\n", GetLastError());
            break;
        }
        switch (packet.type) {
        case ETW_CMD_SHUTDOWN:
            //* shut down etw session
            if (SessionHandle) {
                EVENT_TRACE_PROPERTIES props = {0};
                props.Wnode.BufferSize = sizeof(props);
                ControlTrace(SessionHandle, SESSION_NAME, &props, EVENT_TRACE_CONTROL_STOP);
            }
            
            if (traceHandle != 0 && traceHandle != INVALID_PROCESSTRACE_HANDLE) {
                CloseTrace(traceHandle);
            }
            
            free(SessionProperties);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            return;
        case ETW_CMD_PLIST_ADD:
            DWORD* processList = (DWORD*)malloc(packet.dataSize);    
            ok = ReadFull(hPipe, processList, packet.dataSize);
            if (!ok) {
                printf("[debug] Failed to read tracked process list from pipe, error: %d\n", GetLastError());
                break;
            }
            //* add them to a global map
            for (size_t i = 0; i < (packet.dataSize / sizeof(DWORD)); i++) {
                TrackProcess(processList[i]);
            }
            free(processList);
            break;
        case ETW_CMD_PLIST_REMOVE:
            DWORD* processList = (DWORD*)malloc(packet.dataSize);    
            ok = ReadFull(hPipe, processList, packet.dataSize);
            if (!ok) {
                printf("[debug] Failed to read tracked process list from pipe, error: %d\n", GetLastError());
                break;
            }
            //* add them to a global map
            for (size_t i = 0; i < (packet.dataSize / sizeof(DWORD)); i++) {
                UntrackProcess(processList[i]);
            }
            free(processList);
            break;
        }
    }
}

HANDLE InitializeComms() {
    //TODO: add ACL to pipe comms. elevated processes only.
    // create duplex pipe. max 1 instance. pipe reads/writes block until finished.
    hPipe = CreateNamedPipe(
        PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 64*1024, 64*1024, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[debug] failed to create pipe, error: %d\n", GetLastError());
        return NULL;
    }

    // create thread to receive shutdown signal
    HANDLE WaiterThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ShutdownWaiter, NULL, 0, NULL);
    if (WaiterThread == INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        hPipe = NULL;
        return NULL;
    }
}

BOOL ReadFull(HANDLE pipe, void* buffer, DWORD size) {
    DWORD totalRead = 0;
    while (totalRead < size) {
        DWORD bytesRead = 0;
        if (!ReadFile(pipe, buffer + totalRead, size - totalRead, &bytesRead, NULL)) {
            if (GetLastError() == ERROR_MORE_DATA) {
                totalRead += bytesRead;
                continue;
            }
            return FALSE;
        }
        
        // pipe closed (?)
        if (bytesRead == 0) {
            return FALSE;
        }
        totalRead += bytesRead;
    }
    return TRUE;
}