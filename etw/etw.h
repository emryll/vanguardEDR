#ifndef ETW_H
#define ETW_H

#include <windows.h>
#include <evntrace.h>

#define PIPE_NAME "\\\\.\\pipe\\em_etw"
#define SESSION_NAME "testETWsession"
#define MAX_CMD_DATA 32

extern HANDLE hPipe;
extern TRACEHANDLE SessionHandle;
extern TRACEHANDLE traceHandle;

typedef enum {
    ETW_CMD_EMPTY,
    ETW_CMD_SHUTDOWN,
    ETW_CMD_PING,
} ETW_CMD_TYPE;

// these enums are the event IDs
// https://github.com/jdu2600/Windows10EtwEvents
typedef enum {
    EVENT_FILE_CREATE = 12, // create/open
    EVENT_FILE_DELETE = 26,
    EVENT_FILE_READ = 15,
    EVENT_FILE_WRITE = 16,
    EVENT_FILE_RENAME = 27, // "RenamePath", rename happened

    EVENT_REG_CREATE_KEY = 1,
    EVENT_REG_OPEN_KEY = 2, // not used
    EVENT_REG_DELETE_KEY = 3,
    EVENT_REG_QUERY_KEY = 4, // not used
    EVENT_REG_SET_KEY_VALUE = 5,
    EVENT_REG_DELETE_KEY_VALUE = 6,
    EVENT_REG_SET_INFO_KEY = 11, // change key metadata (permissions, for example)
    EVENT_REG_CLOSE_KEY = 13, // not used
    EVENT_REG_SET_SECURITY_KEY = 15,
} ETW_EVENT_ID;

// this type describes packets received by this component from agent
typedef struct {
    DWORD type; // 0: empty, 1: shutdown, 2: ping
    WORD majorVersion;
    WORD minorVersion;
    unsigned char data[MAX_CMD_DATA]; // this can be used for validation
} ETW_CMD;

#endif