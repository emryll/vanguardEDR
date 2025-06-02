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
    BOOL result;
    char module[260];
} TEXT_CHECK;

typedef struct {
    size_t mismatchCount;
    char mismatches[260][260];
} FUNC_CHECK;

#endif