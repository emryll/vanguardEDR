#include <windows.h>

#define HEARTBEAT_PIPE_NAME "\\\\.\\pipe\\vgrd_hb"
#define TELEMETRY_PIPE_NAME "\\\\.\\pipe\\vgrd_tm"
#define COMMANDS_PIPE_NAME "\\\\.\\pipe\\vgrd_cmd"

#define HEARTBEAT_EVENT_NAME "Global\\vgrd_hb"
#define TELEMETRY_EVENT_NAME "Global\\vgrd_tm"
#define COMMANDS_EVENT_NAME "Global\\vgrd_cmd"

#define HEARTBEAT_INTERVAL 30000
#define INTEGRITY_CHECK_INTERVAL 45000

HANDLE hHeartbeat = NULL;
HANDLE hTelemetry = NULL;
HANDLE hCommands = NULL;

HANDLE hHbEvent = NULL;
HANDLE hTmEvent = NULL;
HANDLE hCmdEvent = NULL;

void WaiterThread() {
    while(TRUE) {
        DWORD waitResult = WaitForSingleObject(hCmdEvent, INFINITE);
        if (waitResult == WAIT_OBJECT_0) {
            //TODO: read pipe, process command
        } else {
            printf("\n[!] Failed to read command from pipe, error: 0x%X\n", GetLastError());
            break;
        }
    }
}

int main() {
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
            printf("\n[!] Failed to open pipes, error code: 0x%X\n", GetLastError());
            return 1;
        }

    hHbEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, HEARTBEAT_EVENT_NAME);
    hTmEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, TELEMETRY_EVENT_NAME);
    hCmdEvent = OpenEvent(SYNCHRONIZE, FALSE, COMMANDS_EVENT_NAME);

    if (!hHbEvent || !hTmEvent || !hCmdEvent) {
        printf("\n[!] Failed to open events, error code: 0x%X\n", GetLastError());        
        return 1;
    }

    //TODO: create a thread to wait on commands
    DWORD threadID;
    HANDLE hThread = CreateThread(NULL, 0, WaiterThread, NULL, 0, &threadID);
    if (hThread == NULL) {
        printf("\n[!] Failed to create thread, error code: 0x%X\n", GetLastError());
    }

    //TODO: start main loop
    DWORD lastHeartbeat = 0;
    DWORD lastIntegrityCheck = 0;

    HMODULE moduleBase = GetModuleHandle(DLL_NAME);
    if (moduleBase == NULL) {
        printf("\n[!] Failed to get module handle, error code: 0x%X\n", GetLastError());
        return 1;
    }

    while(1) {
        DWORD now = GetTickCount(); //ms

        if (now - lastHeartbeat >= HEARTBEAT_INTERVAL) {
            printf("[i] Sending heartbeat...\n");
            heartbeat(hHeartbeat);
        }
        if (now - lastIntegrityCheck >= INTEGRITY_CHECK_INTERVAL) {
            printf("[i] Performing integrity check...\n");

            unsigned char hash[EVP_MAX_MD_SIZE];
            HashTextSection(moduleBase, hash);
            if (memcmp(originalHash, hash, 32) == 0) {
                //? hashes match
                //TODO: send results
                SetEvent(hTmEvent);
            } else {
                //? hashes dont match
                //TODO: send results
                SetEvent(hTmEvent);
            }
        }
    }

    CloseHandle(hHeartbeat);
    CloseHandle(hTelemetry);
    CloseHandle(hCommands);
    CloseHandle(hHbEvent);
    CloseHandle(hTmEvent);
    CloseHandle(hCmdEvent);
    CloseHandle(hThread);
}