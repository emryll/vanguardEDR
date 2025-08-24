#ifndef HOOK_H
#define HOOK_H

#define MAX_API_ARGS 10 
#define HEARTBEAT_INTERVAL 20000
#define INTEGRITY_CHECK_INTERVAL 30000
#define DLL_NAME "kernel32.dll"

#define EVP_MAX_MD_SIZE 64

#define HEARTBEAT_PIPE_NAME "\\\\.\\pipe\\vgrd_hb"
#define TELEMETRY_PIPE_NAME "\\\\.\\pipe\\vgrd_tm"
#define COMMANDS_PIPE_NAME "\\\\.\\pipe\\vgrd_cmd"

#include <windows.h>

typedef struct {
    DWORD pid;
    char  command[64];
    char  arg[64];
} COMMAND;

typedef struct {
    DWORD pid;
    char  heartbeat[64];
} HEARTBEAT;

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

typedef struct {
    TELEMETRY_HEADER header;
    union {
        API_CALL   apiCall;
        FILE_EVENT fileEvent;
        REG_EVENT  regEvent;
        TEXT_CHECK textCheck;
        FUNC_CHECK funcCheck;
    } data;
} TELEMETRY;

typedef enum {
    API_ARG_TYPE_DWORD,
    API_ARG_TYPE_ASTRING,
    API_ARG_TYPE_WSTRING,
    API_ARG_TYPE_BOOL,
    API_ARG_TYPE_PTR
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
    char     dllName[260];
    char     funcName[260];
    ARG_PAIR args[MAX_API_ARGS];
} API_CALL;

typedef struct {
    char path[260];
    FILE_ACTION action;
} FILE_EVENT;

typedef struct {
    char path[260];
    char value[260];
} REG_EVENT;

typedef struct {
    BOOL result;
    char module[260];
} TEXT_CHECK;

typedef struct {
    size_t mismatchCount;
    char mismatches[260][260];
} FUNC_CHECK;

typedef enum {
    FILE_CREATE,
    FILE_MODIFY,
    FILE_REMOVE,
    FILE_MOVE,
} FILE_ACTION;

typedef enum {
    HOOK_CREATE_REMOTE_THREAD,
    HOOK_CREATE_REMOTE_THREAD_EX,
    HOOK_VIRTUAL_PROTECT,
    HOOK_VIRTUAL_ALLOC,
    HOOK_VIRTUAL_ALLOC2,
    HOOK_VIRTUAL_ALLOC_EX,
    HOOK_NT_ALLOC_VM,
    HOOK_NT_CREATE_THREAD,
    HOOK_NT_CREATE_THREAD_EX,
    HOOK_CREATE_PROCESS_A,
    HOOK_CREATE_PROCESS_W,
    HOOK_NT_CREATE_PROCESS,
    HOOK_NT_CREATE_PROCESS_EX,
    HOOK_NT_CREATE_USER_PROCESS,
    HOOK_NT_PROTECT_VM,
    HOOK_QUEUE_USER_APC,
    HOOK_NT_QUEUE_APC_THREAD,
    HOOK_HEAP_ALLOC,
    HOOK_HEAP_REALLOC,
    HOOK_NT_UNMAP_VIEW,
    HOOK_NT_MAP_VIEW,
    HOOK_GET_PROC_ADDRESS,
    HOOK_GET_MODULE_A,
    HOOK_GET_MODULE_W,
    HOOK_SET_WINDOWS_HOOK_EX_A,
    HOOK_SET_WINDOWS_HOOK_EX_W,
    HOOK_WIN_EXEC,
    HOOK_IS_DEBUGGER_PRESENT,
    HOOK_CRYPT_CREATE_HASH,
    HOOK_CRYPT_ENCRYPT,
    HOOK_ENCRYPT_FILE_A,
    HOOK_ENCRYPT_FILE_W,
} HOOK_INDEX;

//? These are for calling hooked api functions from address in the hook handler function
//* user32.dll!MessageBoxA
typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
//* kernel32.dll!VirtualAlloc
typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
//* kernel32.dll!VirtualAllocEx
typedef LPVOID (WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
//* kernelbase.dll!VirtualAlloc2
typedef PVOID (WINAPI *VIRTUALALLOC2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER, ULONG);
//* kernel32.dll!VirtualProtect
typedef BOOL (WINAPI *VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
//* kernel32.dll!VirtualProtectEx
typedef BOOL (WINAPI *VIRTUALPROTECTEX)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
//* kernel32.dll!CreateProcessA
typedef BOOL (WINAPI *CREATEPROCESSA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
  BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
//* kernel32.dll!CreateProcessW
typedef BOOL (WINAPI *CREATEPROCESSW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
  BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
//* kernel32.dll!CreateProcessAsUserA
typedef BOOL (WINAPI *CREATEPROCESSASUSERA)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
//* kernel32.dll!CreateProcessAsUserW
typedef BOOL (WINAPI *CREATEPROCESSASUSERW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
//* kernel32.dll!OpenProcess
typedef HANDLE (WINAPI *OPENPROCESS)(DWORD, BOOL, DWORD);
//* kernel32.dll!OpenProcessToken
typedef BOOL (WINAPI *OPENPROCESSTOKEN)(HANDLE, DWORD, PHANDLE);
//* kernel32.dll!OpenThread
typedef HANDLE (WINAPI *OPENTHREAD)(DWORD, BOOL, DWORD);
//* kernel32.dll!OpenThreadToken
typedef BOOL (WINAPI *OPENTHREADTOKEN)(HANDLE, DWORD, BOOL, PHANDLE);
//* kernel32.dll!CreateRemoteThread
typedef HANDLE (WINAPI *CREATEREMOTETHREAD)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
//* kernel32.dll!CreateRemoteThreadEx
typedef HANDLE (WINAPI *CREATEREMOTETHREADEX)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
//* kernel32.dll!QueueUserAPC
typedef DWORD (WINAPI *QUEUEUSERAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
//* kernel32.dll!QueueUserAPC2
typedef BOOL (WINAPI *QUEUEUSERAPC2)(PAPCFUNC, HANDLE, ULONG_PTR, QUEUE_USER_APC_FLAGS);
//* kernel32.dll!SetThreadContext
typedef BOOL (WINAPI *SETTHREADCONTEXT)(HANDLE, const CONTEXT);
//* kernel32.dll!GetThreadContext
typedef BOOL (WINAPI *GETTHREADCONTEXT)(HANDLE, LPCONTEXT);
//* kernel32.dll!SuspendThread
typedef DWORD (WINAPI *SUSPENDTHREAD)(HANDLE);
//* kernel32.dll!LoadLibraryA
typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);
//* kernel32.dll!LoadLibraryW
typedef HMODULE (WINAPI *LOADLIBRARYW)(LPCWSTR);
//* kernel32.dll!LoadLibraryExA
typedef HMODULE (WINAPI *LOADLIBRARYEXA)(LPCSTR, HANDLE, DWORD);
//* kernel32.dll!LoadLibraryExW
typedef HMODULE (WINAPI *LOADLIBRARYEXW)(LPCWSTR, HANDLE, DWORD);
//* kernel32.dll!SetDefaultDllDirectories
typedef BOOL (WINAPI *SETDEFAULTDLLDIRECTORIES)(DWORD);
//* user32.dll!SetWindowsHookExA
typedef HHOOK (WINAPI *SETWINDOWSHOOKEXA)(int, HOOKPROC, HINSTANCE, DWORD);
//* user32.dll!SetWindowsHookExW
typedef HHOOK (WINAPI *SETWINDOWSHOOKEXW)(int, HOOKPROC, HINSTANCE, DWORD);
//* kernel32.dll!GetProcAddress
typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
//* kernel32.dll!GetModuleHandleA
typedef HMODULE (WINAPI *GETMODULEHANDLEA)(LPCSTR);
//* kernel32.dll!GetModuleHandleW
typedef HMODULE (WINAPI *GETMODULEHANDLEW)(LPCWSTR);
//* kernel32.dll!GetModuleHandleExA
typedef BOOL (WINAPI *GETMODULEHANDLEEXA)(DWORD, LPCSTR, HANDLE*);
//* kernel32.dll!GetModuleHandleExW
typedef BOOL (WINAPI *GETMODULEHANDLEEXW)(DWORD, LPCWSTR, HANDLE*);


#endif