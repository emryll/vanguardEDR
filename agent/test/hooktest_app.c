#include <windows.h>
#include <stdio.h>

int main() {
    HMODULE hook = LoadLibrary("hook.dll");
    if (hook == NULL) {
        printf("Failed to load hook DLL, error: %d\n", GetLastError());
    }

/*    //* wait for event
    HANDLE hEvent = NULL;
    while (hEvent == NULL) {
        HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, EVENT_NAME);
        if (hEvent == NULL) {
            printf("Failed to open event, error: %d\n", GetLastError());
        }
    }
    printf("Opened event\n");
    DWORD wait = WaitForSingleObject(hEvent, INFINITE);
    switch (wait) {
        case WAIT_OBJECT_0:*/
/*    //* virtualalloc
    BOOL need2free = FALSE;
    LPVOID pMem = VirtualAlloc(NULL, 420, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pMem == NULL) {
        printf("VirtualAlloc failed, error: %d\n", GetLastError());
    } else {
        need2free = TRUE;
    }
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
        }
    //* virtualprotect
    if (need2free) {
        DWORD oldProtect;
        BOOL ok = VirtualProtect(pMem, 420, PAGE_EXECUTE_READ, &oldProtect);
        VirtualFree(pMem, 420, MEM_RELEASE);
    }*/
    Sleep(3000);
    MessageBoxA(NULL, "Hello World!", "Hello World!", MB_OK);
/*            break;
        default:
            printf("Wait failed, error: %d\n", GetLastError());
    }
    CloseHandle(hEvent);*/
}