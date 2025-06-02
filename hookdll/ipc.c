#include <windows.h>

void WaiterThread() {
    DWORD myPid = GetCurrentProcessId();
    while(1) {
        COMMAND commandPacket;
        DWORD bytesRead;
        BOOL ok = ReadFile(hCommands, &commandPacket, sizeof(commandPacket), &bytesRead, NULL);
        if (!ok || bytesRead == 0) {
            printf("\n[!] Failed to read from pipe, error: 0x%X\n", GetLastError());
            break;
        }
        
        if (commandPacket.pid == myPid || commandPacket.pid == 0) {
            if (strncmp(commandPacket.command, "exit", 4) == 0) {
                printf("[i] Received exit command, exiting...\n");
                CloseHandle(hCommands);
                CloseHandle(hHeartbeat);
                CloseHandle(hTelemetry);
                exit(0);
            }
        }
    }
    CloseHandle(hCommands);
}

// returns handle to commands waiter thread
HANDLE InitializeComms() {
    hHeartbeat = CreateFile(
        HEARTBEAT_PIPE_NAME,
        GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    
    hTelemetry = CreateFile(
        TELEMETRY_PIPE_NAME,
        GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    hCommands = CreateFile(
        COMMANDS_PIPE_NAME,
        GENERIC_READ,
        0, NULL, OPEN_EXISTING, 0, NULL);
    
    if (hHeartbeat == INVALID_HANDLE_VALUE ||
        hTelemetry == INVALID_HANDLE_VALUE ||
        hCommands == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "\n[!] Failed to open pipes, error code: 0x%X\n", GetLastError());
            return NULL;
    }

    //? create a thread to wait on commands
    DWORD threadID;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaiterThread, NULL, 0, &threadID);
    if (hThread == NULL) {
        fprintf(stderr, "\n[!] Failed to create thread, error code: 0x%X\n", GetLastError());
    }

    return hThread;
}

