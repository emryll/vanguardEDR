#include <windows.h>

#define HEARTBEAT_INTERVAL       45000
#define INTEGRITY_CHECK_INTERVAL 30000
#define HOOK_CHECK_INTERVAL      60000
#define FUNC_HASH_LENGTH 256 // how many bytes to hash from start of function

static const char DLL_NAME[] = "vgrd_hk.dll"
// original hash of own modules .text
unsigned char* OwnTextHash = NULL;
unsigned char* originalNtTextHash = NULL;
unsigned char* originalKernel32TextHash = NULL;

HANDLE hTelemetry = NULL;
HANDLE hCommands = NULL;
HANDLE hCommands = NULL;

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID lpReserved) {
    switch(fdwReason) {
    case DLL_PROCESS_ATTACH:
        //TODO: Setup comms with agent
        if (!SetupComms()) {
            return FALSE;
        }
        
        //TODO: Setup ntdll hooks (inline)
        
        int r = FillFunctionAddresses();
        if (r == -1) {
            return FALSE;
        }

        BOOL ok = SetupHooks();
        if (!ok) {
            return FALSE;
        }
        //* init hashes for integrity checks
        HMODULE dllBase = GetModuleHandle(DLL_NAME);
        if (dllBase == NULL) {
            return FALSE;
        }
        HMODULE ntBase = GetModuleHandle("ntdll.dll");
        if (ntBase == NULL) {
            return FALSE;
        }
        HMODULE kernel32 = GetModuleHandle("kernel32.dll");
        if (kernel32 == NULL) {
            return FALSE;
        }
        unsigned int hashLen = 0;
        HashTextSection(dllBase, OwnTextHash, &hashLen);
        if (OwnTextHash == NULL) {
            return FALSE;
        }
        hashLen = 0;
        HashTextSection(ntbase, originalNtTextHash, &hashLen);
        if (originalNtTextHash == NULL) {
            return FALSE;
        }
        hashLen = 0;
        HashTextSection(ntbase, originalKernel32TextHash, &hashLen);
        if (originalKernel32TextHash == NULL) {
            return FALSE;
        }
        FillFunctionHashes(FUNC_HASH_LENGTH);
        break;
    case DLL_PROCESS_DETACH:
        //TODO: uninstall hooks / cleanup
        UninstallFunctionHooks();
        break;
    }
}

int CounterLoop() {
    DWORD lastHeartbeat = 0;
    DWORD lastIntegrityCheck = 0;
    DWORD lastHookCheck = 0;
    HMODULE hookDllBase = GetModuleHandle(DLL_NAME)
    if (hookDllBase == NULL) {
        return -1;
    }    
    HMODULE ntBase = GetModuleHandle("ntdll.dll");
    if (ntBase == NULL) {
        return -1;
    }    
    HMODULE kernel32Base = GetModuleHandle("kernel32.dll");
    if (kernel32Base == NULL) {
        return -1;
    }    

    while(1) {
        DWORD now = GetTickCount(); //milliseconds
        
        if (now - lastHeartbeat >= HEARTBEAT_INTERVAL) {
            heartbeat(hHbPipe);
        }

        if (now - lastIntegrityCheck >= INTEGRITY_CHECK_INTERVAL) {
            BOOL ownMatch = CheckTextSectionIntegrity(OwnTextHash, hookDllBase);
            BOOL ntdllMatch = CheckTextSectionIntegrity(originalNtTextHash, ntBase);
            BOOL kernel32Match = CheckTextSectionIntegrity(originalKernel32TextHash, kernel32Base);
            
            //* send scan results to agent
            TELEMETRY ownCheck;
            TELEMETRY ntCheck;
            TELEMETRY k32Check;
            
            GetTextTelemetryPacket(&ownCheck, DLL_NAME, ownMatch);
            GetTextTelemetryPacket(&ntCheck, "ntdll.dll", ntdllMatch);
            GetTextTelemetryPacket(&k32Check, "kernel32.dll", kernel32Match);

            DWORD dwBytesWritten;
            WriteFile(hTelemetry, &ownCheck, sizeof(ownCheck), &dwBytesWritten, NULL);
            WriteFile(hTelemetry, &ntCheck, sizeof(ntCheck), &dwBytesWritten, NULL);
            WriteFile(hTelemetry, &k32Check, sizeof(k32Check), &dwBytesWritten, NULL);
            //* performer further checks to find out if a specific hook was tampered with
            //TODO: hash check all functions in specified module?
            if (!ntdllMatch || !kernel32Match) {
                int mismatchCount = 0;
                mismatches = CheckHookIntegrity(&mismatchCount); //? Seperate thread?
                
                //* send hook integrity results to agent
                TELEMETRY hookIntegrity;
                GetHookIntegrityTelemetryPacket(&hookIntegrity, mismatches, mismatchCount)
                WriteFile(hTelemetry, &hookIntegrity, sizeof(hookIntegrity), &dwBytesWritten, NULL);
                free(mismatches);
            }
        }

        if (now - lastHookCheck >= HOOK_CHECK_INTERVAL) {
            //TODO: walk through each module and check for iat-eat address mismatch
        }
    }
}