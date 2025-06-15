#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        FILE* f = fopen("D:\\dev\\edr\\agent\\test\\hooklog.txt", "a");
        if (f) {
            fprintf(f, "DLL loaded\n");
            fclose(f);
        }
    }
    return TRUE;
}