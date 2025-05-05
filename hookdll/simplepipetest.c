#include <windows.h>
#include <stdio.h>

#define HEARTBEAT_INTERVAL 5000

typedef struct {
    DWORD pid;
    char Heartbeat[260];
} HeartbeatPacket;

void heartbeat(HANDLE hPipe) {
    HeartbeatPacket heartbeat;
    strcpy(heartbeat.Heartbeat, "heartbeat");
    heartbeat.pid = GetCurrentProcessId();
    DWORD dwBytesWritten;
    if (!WriteFile(hPipe, &heartbeat, sizeof(heartbeat), &dwBytesWritten, NULL)) {
        printf("\n[!] Failed to send heartbeat, error code: 0x%X\n", GetLastError());
    } else {
        //SetEvent(hHbEvent);
        printf("[+] Sent heartbeat\n");
    }
}

int main() {
    HANDLE hPipe = CreateFile("\\\\.\\pipe\\vgrd", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("\n[!] Failed to open pipe, error code: 0x%X\n", GetLastError());
        return 1;
    }

    DWORD lastHeartbeat = 0;

    while(1) {
        DWORD now = GetTickCount();
        if (now - lastHeartbeat >= HEARTBEAT_INTERVAL) {
            heartbeat(hPipe);
            lastHeartbeat = now;
        }
        Sleep(500);
    }
    CloseHandle(hPipe);
    return 0;
}