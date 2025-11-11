#ifndef HOOK_H
#define HOOK_H

#define STATUS_ACCESS_DENIED 0xC0000022
#define PE_SIGNATURE 0x4550
#define SHA256_DIGEST_LENGTH 32
#define MAX_API_ARGS 10 
#define HEARTBEAT_INTERVAL 20000
#define INTEGRITY_CHECK_INTERVAL 30000
#define COUNTER_LOOP_SLEEP_INTERVAL 10000
#define HOOK_CHECK_INTERVAL      60000
#define IAT_CHECK_INTERVAL      60000
#define FUNC_HASH_LENGTH 256 // how many bytes to hash from start of function
#define EVP_MAX_MD_SIZE 64
#define DLL_NAME "hook.dll"

#define HEARTBEAT_PIPE_NAME "\\\\.\\pipe\\vgrd_hb"
#define TELEMETRY_PIPE_NAME "\\\\.\\pipe\\vgrd_tm"
#define COMMANDS_PIPE_NAME "\\\\.\\pipe\\vgrd_cmd"

#include <windows.h>
#include <winbase.h>
#include <winternl.h>
#include <ntdef.h>
#include <openssl/evp.h>

typedef struct {
    LPCSTR funcName;
    LPCSTR moduleName;
    LPVOID moduleBase;
    FARPROC originalFunc;
    FARPROC handler;
    unsigned char funcHash[SHA256_DIGEST_LENGTH];
} HookEntry;

typedef struct {
    LPCSTR name;
    LPVOID base;
    unsigned char textHash[EVP_MAX_MD_SIZE];
} Module;

extern HANDLE hHeartbeat;
extern HANDLE hTelemetry;
extern HANDLE hCommands;
extern HookEntry HookList[];
extern Module TrackedModules[];
extern const size_t HookListSize;
extern const size_t NumTrackedModules;

typedef struct {
    DWORD pid;
    char  command[64];
    char  arg[64];
} COMMAND;

typedef struct {
    DWORD pid;
    char  Heartbeat[64];
} HEARTBEAT;

typedef enum {
    TM_TYPE_EMPTY_VALUE    = 0, // so agent does not parse empty values
    TM_TYPE_API_CALL       = 1,
    TM_TYPE_FILE_EVENT     = 2,
    TM_TYPE_REG_EVENT      = 3,
    TM_TYPE_TEXT_INTEGRITY = 4,
    TM_TYPE_IAT_INTEGRITY = 5,
    TM_TYPE_GENERIC_ALERT = 6,
} TELEMETRY_TYPE;

typedef enum {
    API_ARG_TYPE_EMPTY, // so agent does not parse empty values
    API_ARG_TYPE_DWORD,
    API_ARG_TYPE_ASTRING,
    API_ARG_TYPE_WSTRING,
    API_ARG_TYPE_BOOL,
    API_ARG_TYPE_PTR
} API_ARGTYPE;

//TODO make this dynamic too, not union
// union to describe an arg and its type (for parsing)
typedef struct {
    API_ARGTYPE type;
    union {
        DWORD   dwValue;
        char    astrValue[260];
        wchar_t wstrValue[260];
        BOOL    boolValue;
        PVOID   ptrValue;
    } arg;
} API_ARG;

// api call telemetry packets' first part after header
typedef struct {
    DWORD    tid;
    char     dllName[60];
    char     funcName[60];
    DWORD    argCount;
} API_CALL_HEADER;

// file system action types
typedef enum {
    FILE_ACTION_CREATE,
    FILE_ACTION_MODIFY,
    FILE_ACTION_REMOVE,
    FILE_ACTION_MOVE,
} FILE_ACTION;

// file system events' telemetry packet (etw)
typedef struct {
    char path[260];
    FILE_ACTION action;
} FILE_EVENT;

// registry events' telemetry packet (etw)
typedef struct {
    char path[260];
    char value[260];
} REG_EVENT;

// text integrity checks' telemetry packet
typedef struct {
    BOOL result;
    char module[260];
} TEXT_CHECK;

//TODO change this shit lmaoo, dont list so many damn matches especially with strings. makes it 67kB
typedef struct {
    size_t mismatchCount;
    char mismatches[260][260];
} FUNC_CHECK;

typedef struct {
    DWORD  pid;
    DWORD  type;
    size_t  dataSize;
    time_t timeStamp;
} TELEMETRY_HEADER;

typedef struct {
    char funcName[64];
    LPVOID address; // this is the invalid address IAT is pointing to
} IAT_MISMATCH;

typedef struct {
    size_t descSize;
    char* description;
} GENERIC_ALERT;

//? instead of using an union, be more memory efficient and send only what you need
//? in a different struct which you can just memcpy() into a buffer after the header
/*
typedef struct {
    TELEMETRY_HEADER header; //24B
    union {
        API_CALL   apiCall;
        FILE_EVENT fileEvent;
        REG_EVENT  regEvent;
        TEXT_CHECK textCheck;
        FUNC_CHECK funcCheck;
    } data;
} TELEMETRY;
*/
// utils.c
//void GetHookIntegrityTelemetryPacket(TELEMETRY*, int*, int);
//void GetHookBaseTelemetryPacket(TELEMETRY*, LPCSTR, LPCSTR);
//void GetTextTelemetryPacket(TELEMETRY*, char*, BOOL);
//void FillEmptyArgs(TELEMETRY*, int);
PIMAGE_IMPORT_DESCRIPTOR GetIatImportDescriptor(LPVOID);
size_t GetTelemetryPacketSize(DWORD, size_t);
TELEMETRY_HEADER GetTelemetryHeader(DWORD, size_t);
API_CALL_HEADER GetApiCallHeader(LPCSTR, LPCSTR, size_t);
TEXT_CHECK GetTextIntegrityPacket(LPCSTR, BOOL);
BYTE* GetGenericAlertPacket(LPCSTR);
void SendDllInjectionAlert();

HANDLE InitializeComms();           // ipc.c
void WaiterThread(); // ipc.c
int FillFunctionHash(unsigned char*, LPVOID, size_t);     // utils.c
int InitializeHookList();           // iathook.c
int InitializeIatHooksByHookList(); // iathook.c
void InitializeModuleList(); // iathook.c

// tampering.c
void heartbeat(HANDLE);
//int* CheckHookIntegrity(int*);
BOOL CheckTextSectionIntegrity(unsigned char*, HMODULE);
void HashTextSection(HMODULE, unsigned char*, unsigned int*);
//void PerformIntegrityChecks(HMODULE, HMODULE, HMODULE);
void CheckIatIntegrity(LPVOID);

// utils.cpp
#ifdef __cplusplus
extern "C" {
#endif
void InitializeHookMap();
HookEntry* FindHookEntry(LPCSTR);
#ifdef __cplusplus
}
#endif

//*=============================[ API hooks ]========================================

//? this is the index into HookList; the enums must be in correct order
typedef enum {
    HOOK_MESSAGE_BOX_A,
    HOOK_VIRTUAL_PROTECT,
    HOOK_VIRTUAL_PROTECT_EX,
    HOOK_NT_PROTECT_VM,
    HOOK_VIRTUAL_ALLOC,
    HOOK_VIRTUAL_ALLOC2,
    HOOK_VIRTUAL_ALLOC_EX,
    HOOK_NT_ALLOC_VM,
    HOOK_NT_ALLOC_VM_EX,
    HOOK_OPEN_PROCESS,
    HOOK_NT_OPEN_PROCESS,
    HOOK_CREATE_PROCESS_A,
    HOOK_CREATE_PROCESS_W,
    HOOK_CREATE_PROCESS_AS_USER_A,
    HOOK_CREATE_PROCESS_AS_USER_W,
    HOOK_NT_CREATE_PROCESS,
    HOOK_NT_CREATE_PROCESS_EX,
    HOOK_NT_CREATE_USER_PROCESS,
    HOOK_CREATE_REMOTE_THREAD,
    HOOK_CREATE_REMOTE_THREAD_EX,
    HOOK_NT_CREATE_THREAD,
    HOOK_NT_CREATE_THREAD_EX,
    HOOK_GET_PROC_ADDRESS,
    HOOK_GET_MODULE_HANDLE_A,
    HOOK_GET_MODULE_HANDLE_W,
    HOOK_GET_MODULE_HANDLE_EX_A,
    HOOK_GET_MODULE_HANDLE_EX_W,
    HOOK_LOAD_LIBRARY_A,
    HOOK_LOAD_LIBRARY_W,
    HOOK_LOAD_LIBRARY_EX_A,
    HOOK_LOAD_LIBRARY_EX_W,
    //HOOK_QUEUE_USER_APC,
/*    HOOK_NT_QUEUE_APC_THREAD,
    HOOK_HEAP_ALLOC,
    HOOK_HEAP_REALLOC,
    HOOK_NT_UNMAP_VIEW,
    HOOK_NT_MAP_VIEW,
    HOOK_SET_WINDOWS_HOOK_EX_A,
    HOOK_SET_WINDOWS_HOOK_EX_W,
    HOOK_WIN_EXEC,
    HOOK_IS_DEBUGGER_PRESENT,
    HOOK_CRYPT_CREATE_HASH,
    HOOK_CRYPT_ENCRYPT,
    HOOK_ENCRYPT_FILE_A,
    HOOK_ENCRYPT_FILE_W,*/
} HOOK_INDEX;

//? These are for calling hooked api functions from address in the hook handler function
//* user32.dll!MessageBoxA
typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
int MessageBoxA_Handler(HWND, LPCSTR, LPCSTR, UINT);

//? These are for calling hooked api functions from address in the hook handler function
//* user32.dll!MessageBoxA
typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
int MessageBoxA_Handler(HWND, LPCSTR, LPCSTR, UINT);

//* kernel32.dll!VirtualProtect
typedef BOOL (WINAPI *VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
BOOL VirtualProtect_Handler(LPVOID, SIZE_T, DWORD, PDWORD);
//* kernel32.dll!VirtualProtectEx
typedef BOOL (WINAPI *VIRTUALPROTECTEX)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
BOOL VirtualProtectEx_Handler(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
//* ntdll!NtProtectVirtualMemory
typedef NTSTATUS (NTAPI *NTPROTECTVM)(HANDLE, PVOID, PSIZE_T, ULONG, PULONG);
NTSTATUS NtProtectVM_Handler(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

//* kernel32.dll!VirtualAlloc
typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
LPVOID VirtualAlloc_Handler(LPVOID, SIZE_T, DWORD, DWORD);
//* kernel32.dll!VirtualAllocEx
typedef LPVOID (WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
LPVOID VirtualAllocEx_Handler(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
//* kernelbase.dll!VirtualAlloc2
typedef LPVOID (WINAPI *VIRTUALALLOC2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG);
PVOID VirtualAlloc2_Handler(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG);
//* ntdll.dll!NtAllocateVirtualMemory
typedef NTSTATUS (NTAPI *NTALLOCVM)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
NTSTATUS NtAllocateVM_Handler(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
//* ntdll.dll!NtAllocateVirtualMemoryEx
typedef NTSTATUS (NTAPI *NTALLOCVMEX)(HANDLE, PVOID*, PSIZE_T, ULONG, ULONG, PMEM_EXTENDED_PARAMETER, ULONG);
NTSTATUS NtAllocateVMEx_Handler(HANDLE, PVOID*, PSIZE_T, ULONG, ULONG, PMEM_EXTENDED_PARAMETER, ULONG);

//* kernel32.dll!OpenProcess
typedef HANDLE (WINAPI *OPENPROCESS)(DWORD, BOOL, DWORD);
HANDLE OpenProcess_Handler(DWORD, BOOL, DWORD);
//* ntdll.dll!NtOpenProcess
typedef NTSTATUS (NTAPI* NTOPENPROCESS)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, PCLIENT_ID);
NTSTATUS NtOpenProcess_Handler(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, PCLIENT_ID);

//* kernel32.dll!CreateProcessA
typedef BOOL (WINAPI *CREATEPROCESSA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
  BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
BOOL CreateProcessA_Handler(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
  BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
//* kernel32.dll!CreateProcessW
typedef BOOL (WINAPI *CREATEPROCESSW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
  BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
BOOL CreateProcessW_Handler(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
  BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
//* kernel32.dll!CreateProcessAsUserA
typedef BOOL (WINAPI *CREATEPROCESSASUSERA)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
BOOL CreateProcessAsUserA_Handler(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
//* kernel32.dll!CreateProcessAsUserW
typedef BOOL (WINAPI *CREATEPROCESSASUSERW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
BOOL CreateProcessAsUserW_Handler(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
//* ntdll.dll!NtCreateProcess
typedef NTSTATUS (NTAPI* NTCREATEPROCESS)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE,
BOOLEAN, HANDLE, HANDLE, HANDLE);
NTSTATUS NtCreateProcess_Handler(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
//* ntdll.dll!NtCreateProcessEx
typedef NTSTATUS (NTAPI* NTCREATEPROCESSEX)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE,
ULONG, HANDLE, HANDLE, HANDLE, ULONG);
NTSTATUS NtCreateProcessEx_Handler(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, ULONG);
//* ntdll.dll!NtCreateUserProcess
typedef NTSTATUS (NTAPI* NTCREATEUSERPROCESS)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, PCOBJECT_ATTRIBUTES,
PCOBJECT_ATTRIBUTES, ULONG, ULONG, void*, void*, void*);
NTSTATUS NtCreateUserProcess_Handler(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, PCOBJECT_ATTRIBUTES,
    PCOBJECT_ATTRIBUTES, ULONG, ULONG, void*, void*, void*);


//* kernel32.dll!OpenProcessToken
typedef BOOL (WINAPI *OPENPROCESSTOKEN)(HANDLE, DWORD, PHANDLE);
BOOL OpenProcessToken_Handler(HANDLE, DWORD, PHANDLE);
//* kernel32.dll!OpenThreadToken
typedef BOOL (WINAPI *OPENTHREADTOKEN)(HANDLE, DWORD, BOOL, PHANDLE);
BOOL OpenThreadToken_Handler(HANDLE, DWORD, BOOL, PHANDLE);

//* kernel32.dll!OpenThread
typedef HANDLE (WINAPI *OPENTHREAD)(DWORD, BOOL, DWORD);
HANDLE OpenThread_Handler(DWORD, BOOL, DWORD);
//* kernel32.dll!SetThreadContext
typedef BOOL (WINAPI *SETTHREADCONTEXT)(HANDLE, const CONTEXT);
BOOL SetThreadContext_Handler(HANDLE, const CONTEXT);
//* kernel32.dll!GetThreadContext
typedef BOOL (WINAPI *GETTHREADCONTEXT)(HANDLE, LPCONTEXT);
BOOL GetThreadContext_Handler(HANDLE, LPCONTEXT);
//* kernel32.dll!SuspendThread
typedef DWORD (WINAPI *SUSPENDTHREAD)(HANDLE);
DWORD SuspendThread_Handler(HANDLE);
//* kernel32.dll!ResumeThread
typedef DWORD (WINAPI *RESUMETHREAD)(HANDLE);
DWORD ResumeThread_Handler(HANDLE);

//* kernel32.dll!CreateRemoteThread
typedef HANDLE (WINAPI *CREATEREMOTETHREAD)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
HANDLE CreateRemoteThread_Handler(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
//* kernel32.dll!CreateRemoteThreadEx
typedef HANDLE (WINAPI *CREATEREMOTETHREADEX)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
HANDLE CreateRemoteThreadEx_Handler(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
//* ntdll.dll!NtCreateThread
typedef NTSTATUS (NTAPI *NTCREATETHREAD)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, void*, BOOL);
NTSTATUS NtCreateThread_Handler(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, void*, BOOL);
//* ntdll.dll!NtCreateThreadEx
typedef NTSTATUS (NTAPI *NTCREATETHREADEX)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE, void*, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, void*);
NTSTATUS NtCreateThreadEx_Handler(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE, void*, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, void*);

/*
//* kernel32.dll!QueueUserAPC
typedef DWORD (WINAPI *QUEUEUSERAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
DWORD QueueUserAPC_Handler(PAPCFUNC, HANDLE, ULONG_PTR);
//* kernel32.dll!QueueUserAPC2
typedef BOOL (WINAPI *QUEUEUSERAPC2)(PAPCFUNC, HANDLE, ULONG_PTR, QUEUE_USER_APC_FLAGS);
BOOL QueueUserAPC2_Handler(PAPCFUNC, HANDLE, ULONG_PTR, QUEUE_USER_APC_FLAGS);
*/
//* kernel32.dll!LoadLibraryA
typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);
HMODULE LoadLibraryA_Handler(LPCSTR);
//* kernel32.dll!LoadLibraryW
typedef HMODULE (WINAPI *LOADLIBRARYW)(LPCWSTR);
HMODULE LoadLibraryW_Handler(LPCWSTR);
//* kernel32.dll!LoadLibraryExA
typedef HMODULE (WINAPI *LOADLIBRARYEXA)(LPCSTR, HANDLE, DWORD);
HMODULE LoadLibraryExA_Handler(LPCSTR, HANDLE, DWORD);
//* kernel32.dll!LoadLibraryExW
typedef HMODULE (WINAPI *LOADLIBRARYEXW)(LPCWSTR, HANDLE, DWORD);
HMODULE LoadLibraryExW_Handler(LPCWSTR, HANDLE, DWORD);

//* kernel32.dll!GetProcAddress
typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
FARPROC GetProcAddress_Handler(HMODULE, LPCSTR);
//* kernel32.dll!GetModuleHandleA
typedef HMODULE (WINAPI *GETMODULEHANDLEA)(LPCSTR);
HMODULE GetModuleHandleA_Handler(LPCSTR);
//* kernel32.dll!GetModuleHandleW
typedef HMODULE (WINAPI *GETMODULEHANDLEW)(LPCWSTR);
HMODULE GetModuleHandleW_Handler(LPCWSTR);
//* kernel32.dll!GetModuleHandleExA
typedef BOOL (WINAPI *GETMODULEHANDLEEXA)(DWORD, LPCSTR, HMODULE*);
BOOL GetModuleHandleExA_Handler(DWORD, LPCSTR, HMODULE*);
//* kernel32.dll!GetModuleHandleExW
typedef BOOL (WINAPI *GETMODULEHANDLEEXW)(DWORD, LPCWSTR, HMODULE*);
BOOL GetModuleHandleExW_Handler(DWORD, LPCWSTR, HMODULE*);

//* kernel32.dll!SetDefaultDllDirectories
typedef BOOL (WINAPI *SETDEFAULTDLLDIRECTORIES)(DWORD);
BOOL SetDefaultDllDirectories_Handler(DWORD);

//* user32.dll!SetWindowsHookExA
typedef HHOOK (WINAPI *SETWINDOWSHOOKEXA)(int, HOOKPROC, HINSTANCE, DWORD);
HHOOK SetWindowsHookExA_Handler(int, HOOKPROC, HINSTANCE, DWORD);
//* user32.dll!SetWindowsHookExW
typedef HHOOK (WINAPI *SETWINDOWSHOOKEXW)(int, HOOKPROC, HINSTANCE, DWORD);
HHOOK SetWindowsHookExW_Handler(int, HOOKPROC, HINSTANCE, DWORD);

//* kernel32.dll!IsDebuggerPresent
typedef BOOL (WINAPI *ISDEBUGGERPRESENT)();
BOOL IsDebuggerPresent_Handler();

#endif