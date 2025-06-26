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

#endif