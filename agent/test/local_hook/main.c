#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "hook.h"

HANDLE hTelemetry = NULL;

// still need to fill out args manually
void GetHookBaseTelemetryPacket(TELEMETRY* tm, LPCSTR dllName, int funcId) {
    tm->header.timeStamp = time(NULL);
    tm->header.pid = GetCurrentProcessId();
    tm->header.type = TM_TYPE_API_CALL;

    tm->data.apiCall.tid = GetCurrentThreadId();
    strncpy(tm->data.apiCall.dllName, dllName, sizeof(tm->data.apiCall.dllName)-1);
    tm->data.apiCall.funcId = funcId;
    return;
}

void FillEmptyArgs(TELEMETRY* tm, int index) {
    for (int i = index; i < MAX_API_ARGS; i++) {
        tm->data.apiCall.args[i].type = API_ARG_TYPE_EMPTY;
        tm->data.apiCall.args[i].arg.dwValue = 0;
    }
    return;
}

BOOL Setup() {
    BOOL iswow;
    IsWow64Process(GetCurrentProcess(), &iswow);
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    fprintf(f, "iswow64: %d\n", iswow);
    fclose(f);

    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    //* initialize comms
    for (int i = 0; i < 20; i++) {
        hTelemetry = CreateFile(
            TELEMETRY_PIPE_NAME,
            GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (hTelemetry == NULL) {
            fprintf(f, "failed to open telemetry pipe, error: %d\n", GetLastError());
        } else {
            fprintf(f, "opened telemetry pipe\n");
            break;
        }
    }
    fclose(f);
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    //* setup api hooks
    int r = FillFunctionAddresses();
    if (r == -1) {
        fprintf(f, "failed to get module bases\n");
        return FALSE;
    } else {
        fprintf(f, "filled function addresses, fail count: %d\n", r);
    }
    fclose(f);

    r = InstallFunctionHooks();
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    if (r == -1) {
        fprintf(f, "failed to install hooks\n");
    } else if (r != 0) {
        fprintf(f, "%d hooks failed to be setup\n", r);
    } else {
        fprintf(f, "installed hooks\n");
    }
    fclose(f);
    return TRUE;
}

/*BOOL WINAPI DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID lpReserved) {
    switch(fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hInst);
            f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
            fprintf(f, "inside dllmain\n");
            fclose(f);

            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Setup, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            UninstallFunctionHooks();
            break;
    }
}*/
int main() {
    Setup();

    Sleep(1000);

    MessageBoxA(0, "Hello World!", "Hello World!", MB_OK);
    /*MEMORY_BASIC_INFORMATION mbi;
    SIZE_T r = VirtualQuery(HookList[HOOK_VIRTUAL_QUERY].funcAddress, &mbi, 420);
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    if (r == 0) {
        fprintf(f, "failed to virtualquery, error: %d\n", GetLastError());
    } else {
        fprintf(f, "virtualquery success, n: %d\n", r);
    }*/

    //* virtualalloc
    BOOL need2free = FALSE;
    LPVOID pMem = VirtualAlloc(NULL, 420, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    if (pMem == NULL) {
        printf("VirtualAlloc failed, error: %d\n", GetLastError());
        fprintf(f, "virtualalloc failed, error:  %d\n", GetLastError());
    } else {
        fprintf(f, "virtualalloc success\n");
        need2free = TRUE;
    }
    fclose(f);
    f = fopen("D:\\dev\\edr\\agent\\test\\log.txt", "a");
    //* createprocess
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcess(
        NULL, "C:\\Windows\\System32\\calc.exe", NULL, NULL,
        FALSE, 0, NULL, NULL, &si, &pi)) {
            printf("CreateProcess failed, error: %d\n", GetLastError());
            fprintf(f, "CreateProcess failed, error: %d\n", GetLastError());
        }
    fprintf(f, "createprocess success\n");
    fclose(f);
    //* virtualprotect
    if (need2free) {
        DWORD oldProtect;
        BOOL ok = VirtualProtect(pMem, 420, PAGE_EXECUTE_READ, &oldProtect);
        VirtualFree(pMem, 420, MEM_RELEASE);
    }
    UninstallFunctionHooks();
}