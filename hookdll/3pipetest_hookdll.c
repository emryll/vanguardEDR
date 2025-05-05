#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define HEARTBEAT_PIPE_NAME "\\\\.\\pipe\\vgrd_hb"
#define TELEMETRY_PIPE_NAME "\\\\.\\pipe\\vgrd_tm"
#define COMMANDS_PIPE_NAME "\\\\.\\pipe\\vgrd_cmd"

#define HEARTBEAT_EVENT_NAME "Global\\vgrd_hb"
#define TELEMETRY_EVENT_NAME "Global\\vgrd_tm"
#define COMMANDS_EVENT_NAME "Global\\vgrd_cmd"

#define HEARTBEAT_INTERVAL 15000
#define INTEGRITY_CHECK_INTERVAL 20000

#define DLL_NAME "kernel32.dll"
#define EVP_MAX_MD_SIZE 64

HANDLE hHeartbeat = NULL;
HANDLE hTelemetry = NULL;
HANDLE hCommands = NULL;

//HANDLE hHbEvent = NULL;
//HANDLE hTmEvent = NULL;
//HANDLE hCmdEvent = NULL;

unsigned char originalTextHash[EVP_MAX_MD_SIZE] = {0};

typedef struct {
    DWORD pid;
    char command[64];
} COMMAND;

typedef struct {
    DWORD pid;
    DWORD type;
    time_t timeStamp;
} TELEMETRY_HEADER;

typedef struct {
    TELEMETRY_HEADER header;
    union {
        struct {
			char dllName[64];
			char funcName[64];
		} apiCall;
		
		struct {
			DWORD action; // 0: dropped 1: modified 2: deleted
			char path[260];
		} fileEvent;

		struct {
			char path[260];
			char newValue[260];
		} regEvent;

		struct {
			BOOL result;
		} textCheck;
    } data;
} TELEMETRY;

// start routine for thread waiting on commands
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


    //? create a thread to wait on commands
    DWORD threadID;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaiterThread, NULL, 0, &threadID);
    if (hThread == NULL) {
        printf("\n[!] Failed to create thread, error code: 0x%X\n", GetLastError());
    }

    //? start main loop

    HMODULE moduleBase = GetModuleHandle(DLL_NAME);
    if (moduleBase == NULL) {
        printf("\n[!] Failed to get module handle, error code: 0x%X\n", GetLastError());
        CloseHandle(hHeartbeat);
        CloseHandle(hTelemetry);
        CloseHandle(hCommands);
        CloseHandle(hThread);
        return 1;
    }

    unsigned int hashLen = 0;
    HashTextSection(moduleBase, originalTextHash, &hashLen);
    printf("[i] Original hash of .text: ");
    for (int i = 0; i < hashLen; i++) {
        printf("%02X ", originalTextHash[i]);
    }
    printf("\n");

    DWORD lastHeartbeat = 0;
    DWORD lastIntegrityCheck = GetTickCount();
    
    while(1) {
        DWORD now = GetTickCount(); //ms

        if (now - lastHeartbeat >= HEARTBEAT_INTERVAL) {
            printf("[i] Sending heartbeat...\n");
            heartbeat(hHeartbeat);
            lastHeartbeat = now;
        }
        if (now - lastIntegrityCheck >= INTEGRITY_CHECK_INTERVAL) {
            printf("[i] Performing integrity check...\n");

            unsigned int hashLen2 = 0;
            unsigned char hash[EVP_MAX_MD_SIZE];
            HashTextSection(moduleBase, hash, &hashLen2);
            TELEMETRY tm;
            tm.header.pid = GetCurrentProcessId();
            tm.header.type = 3;
            tm.header.timeStamp = time(NULL);
            if (memcmp(originalTextHash, hash, 32) == 0) {
                //* hashes match
                tm.data.textCheck.result = TRUE;
            } else {
                //! hashes dont match
                tm.data.textCheck.result = FALSE;
            }
            DWORD dwBytesWritten;
            if (!WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL)) {
                printf("[telemetry] Failed to send data to pipe, error code: 0x%X\n", GetLastError());
            } else {
                printf("[telemetry] Sent data to pipe\n");
            }
            lastIntegrityCheck = now;
        }
    }

    WaitForSingleObject(hThread, INFINITE);
//cleanup
    CloseHandle(hHeartbeat);
    CloseHandle(hTelemetry);
    CloseHandle(hCommands);
    CloseHandle(hThread);
}