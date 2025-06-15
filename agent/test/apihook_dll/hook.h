#ifndef HOOK_H
#define HOOK_H

#define MAX_API_ARGS 10
#define TELEMETRY_PIPE_NAME "\\\\.\\pipe\\vg_tm"

#include <windows.h>

int FillFunctionAddresses();
int InstallFunctionHooks();
int UninstallFunctionHooks();

BOOL WINAPI CreateProcessA_HookHandler(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
BOOL WINAPI CreateProcessW_HookHandler(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
BOOL WINAPI VirtualProtect_HookHandler(LPVOID, SIZE_T, DWORD, PDWORD);
LPVOID WINAPI VirtualAlloc_HookHandler(LPVOID, SIZE_T, DWORD, DWORD);
int WINAPI MessageBoxA_HookHandler(HWND, LPCSTR, LPCSTR, UINT);
SIZE_T WINAPI VirtualQuery_HookHandler(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);




extern HANDLE hTelemetry;
extern FILE* f;
extern HookEntry* HookList;

typedef enum {
    TM_TYPE_API_CALL       = 0,
    TM_TYPE_FILE_EVENT     = 1,
    TM_TYPE_REG_EVENT      = 2,
    TM_TYPE_TEXT_INTEGRITY = 3,
    TM_TYPE_HOOK_INTEGRITY = 4,
} TELEMETRY_TYPE;

typedef struct {
    DWORD  pid;
    DWORD  type;
    time_t timeStamp;
} TELEMETRY_HEADER;


typedef enum {
    API_ARG_TYPE_DWORD,
    API_ARG_TYPE_ASTRING,
    API_ARG_TYPE_WSTRING,
    API_ARG_TYPE_BOOL,
    API_ARG_TYPE_PTR,
    API_ARG_TYPE_EMPTY
} API_ARGTYPE;

typedef struct {
    API_ARGTYPE type;
    union {
        DWORD   dwValue;
        char    astrValue[260];
        wchar_t wstrValue[260];
        BOOL    boolValue;
        PVOID   ptrValue;
    } arg;
} API_ARGPAIR;

typedef struct {
    DWORD    tid;
    char     dllName[64];
    DWORD     funcId;
    API_ARGPAIR args[MAX_API_ARGS];
} API_CALL;

typedef enum {
    ACTION_CREATE,
    ACTION_MODIFY,
    ACTION_REMOVE,
    ACTION_MOVE
} FILE_ACTION;

typedef struct {
    char path[260];
    DWORD action;
} FILE_EVENT;

typedef struct {
    char path[260];
    char value[260];
} REG_EVENT;

typedef struct {
    BOOL result;
    char module[260];
} TEXT_CHECK;

/*typedef struct {
    size_t mismatchCount;
    char mismatches[260][260];
} FUNC_CHECK;
*/
typedef struct {
    TELEMETRY_HEADER header;
    union {
        API_CALL   apiCall;
        FILE_EVENT fileEvent;
        REG_EVENT  regEvent;
        TEXT_CHECK textCheck;
        //FUNC_CHECK funcCheck;
    } data;
} TELEMETRY;

void GetHookBaseTelemetryPacket(TELEMETRY*, LPCSTR, int);

typedef enum {
    HOOK_VIRTUAL_QUERY,
    HOOK_MESSAGE_BOX_A,
    HOOK_CREATE_PROCESS_A,
    HOOK_CREATE_PROCESS_W,
    //HOOK_VIRTUAL_ALLOC,
//    HOOK_VIRTUAL_PROTECT,
} HOOK_INDEX;

typedef BOOL (WINAPI *CREATEPROCESSA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CREATEPROCESSW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
typedef SIZE_T (WINAPI *VIRTUALQUERY)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);

#endif