#include <windows.h>

#define HEARTBEAT_PIPE_NAME "\\\\.\\pipe\\vgrd_hb"
#define TELEMETRY_PIPE_NAME "\\\\.\\pipe\\vgrd_tm"
#define COMMANDS_PIPE_NAME "\\\\.\\pipe\\vgrd_cmd"

#define HEARTBEAT_EVENT_NAME "Global\\vgrd_hb"
#define TELEMETRY_EVENT_NAME "Global\\vgrd_tm"
#define COMMANDS_EVENT_NAME "Global\\vgrd_cmd"

int main() {
    HANDLE hHeartbeat = NULL;
    HANDLE hTelemetry = NULL;
    HANDLE hCommands = NULL;
    
    HANDLE hHbEvent = NULL;
    HANDLE hTmEvent = NULL;
    HANDLE hCmdEvent = NULL;
    
    hHeartbeat = CreateNamedPipe(
        HEARTBEAT_PIPE_NAME,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 4096, 4096, 0, NULL);

    hTelemetry = CreateNamedPipe(
        TELEMETRY_PIPE_NAME,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 4096, 4096, 0, NULL);

    hCommands = CreateNamedPipe(
        COMMANDS_PIPE_NAME,
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 4096, 4096, 0, NULL);

    if (hHeartbeat == INVALID_HANDLE_VALUE ||
        hTelemetry == INVALID_HANDLE_VALUE ||
        hCommands == INVALID_HANDLE_VALUE) {
            printf("\n[!] Failed to create pipes, error code: 0x%X\n", GetLastError());
            return 1;
        }
    
    hHbEvent = CreateEvent(NULL, FALSE, FALSE, HEARTBEAT_EVENT_NAME);
    hTmEvent = CreateEvent(NULL, FALSE, FALSE, TELEMETRY_EVENT_NAME);
    hCmdEvent = CreateEvent(NULL, FALSE, FALSE, COMMANDS_EVENT_NAME);

    if (!hHbEvent || !hTmEvent || !hCmdEvent) {
        printf("\n[!] Failed to create events, error code: 0x%X\n", GetLastError());        
        CloseHandle(hHeartbeat);
        CloseHandle(hTelemetry);
        CloseHandle(hCommands);
        return 1;
    }


}