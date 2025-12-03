#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <time.h>
#include "memscan.h"

#define RULES_DIR ".\\rules"
#define DEFAULT_LOG "agent.log"
/*
FILE* output = stdout;

// open default or specified log file for appending
FILE* OpenLog(char* path) {
    if (path == NULL) {
        return fopen(DEFAULT_LOG, "a");
    }
    return fopen(path, "a");
}

// print formatted text to stdout or log file; where ever output is pointing to
void Log(const char* format, ...) {
    time_t now = time(NULL);
    fprintf(output, "[%ld] ", now);

    va_list args;
    va_start(args, format);
    vfprintf(output, format, args);
    va_end(args);
}
*/

// get all .yara files in RULES_DIR. Caller is responsible for freeing with FreePaths()
int GetYaraRules(char*** paths, size_t* count) {
    *count = 0;
    char** tmp = realloc(*paths, (*count + 1) * sizeof(char*));
    if (tmp == NULL) {
        return -1;
    } 
    *paths = tmp;

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char rulePath[MAX_PATH];
    snprintf(rulePath, MAX_PATH, "%s\\*.yara", RULES_DIR);
    
    hFind = FindFirstFile(rulePath, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Failed to open directory: %s\n", RULES_DIR);
        return GetLastError();
    }
    do {
        // skip . and ..
        if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0) {
            continue;
        }
        // allocate space for pointer to string
        char** tmp = realloc(*paths, (*count + 1) * sizeof(char*));
        if (tmp == NULL) {
            FindClose(hFind);
            return -1;
        }
        *paths = tmp;

        // allocate actual string
        (*paths)[*count] = malloc(MAX_PATH);
        if ((*paths)[*count] == NULL) {
            FindClose(hFind);
            return -1;
        }
        snprintf((*paths)[*count], MAX_PATH, "%s\\%s", RULES_DIR, findFileData.cFileName);
        (*count)++;
    } while (FindNextFile(hFind, &findFileData));
    FindClose(hFind);
    return 0;
}

void FreePaths(char*** paths, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free((*paths)[i]);
    }
    free(*paths);
}


/*
int NotifyMatchAndRequestScan(char* programName, DWORD pid, YRX_SCANNER* scanner) {
    char text[520];
    sprintf("%s(%d) is suspicious and may be malware, would you like to run a full scan in the background? It may affect performance.", programName, pid);
    int answer = MessageBox(NULL, text, "Alert!", MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL);
    if answer == 0 {
        printf("\n[!] Failed to display message box, error: %d\n", GetLastError());
    } else if (answer == IDYES) {
        MemoryScanEx(pid, scanner);
        //TODO: check api, file and reg patterns
        //TODO: check hook and self integrity
    }
}
*/

// inject hook to specified process, via simple dll injection
int InjectDll(DWORD pid) {
    //* open handle to process
    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, pid);
    if (hProcess == NULL) {
        return GetLastError();
    }

    //* get address of LoadLibraryA
    HMODULE k32Base     = GetModuleHandle("kernel32.dll");
    LPVOID pLoadLibrary = GetProcAddress(k32Base, "LoadLibraryA");


    //* allocate memory for dll name
    LPVOID buffer = VirtualAllocEx(hProcess, NULL, strlen(DLL_NAME) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        return GetLastError();
    }

    //* write dll name to allocated memory
    BOOL ok = WriteProcessMemory(hProcess, buffer, DLL_NAME, strlen(DLL_NAME)+1, NULL);
    if (!ok) {
        return GetLastError();
    }

    //* create remote thread to call LoadLibraryA(dll)
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
    (LPTHREAD_START_ROUTINE)pLoadLibrary, buffer, 0, NULL);
    if (hThread == NULL) {
        CloseHandle(hProcess);
        return GetLastError();
    }
    CloseHandle(hProcess);
    CloseHandle(hThread);
    return 0;
}


typedef NTSTATUS (NTAPI* QUERYTHREADINFO)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

// This function will enumerate all accessible threads of a process (or 0 for all),
// query its start routine address and then check if it points to a module's text section.
// Additionally you may check if the start routine address points to a LoadLibrary* function.
// Caller is responsible for freeing the resulting array of length oddCount.
THREAD_ENTRY* ScanProcessThreads(DWORD pid, size_t* oddCount) {
    (*oddCount) = 0;
    THREAD_ENTRY* oddThreads = NULL;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to get snapshot of threads, error: %d\n", GetLastError());
        return NULL;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (!Thread32First(snapshot, &te)) {
        printf("Failed to enumerate first thread, error: %d", GetLastError());
        return NULL;
    }
    // NtQueryInformationThread is not in headers so I manually declare and use it 
    HMODULE ntBase = GetModuleHandle("ntdll.dll");
    if (ntBase == INVALID_HANDLE_VALUE) {
        printf("Failed to get handle to ntdll.dll, error: %d\n", GetLastError());
        return NULL;
    }
    FARPROC NtQueryInformationThread = GetProcAddress(ntBase, "NtQueryInformationThread");
    if (NtQueryInformationThread == NULL) {
        printf("Failed to get address of NtQueryInformationThread, error: %d\n", GetLastError());
        return NULL;
    }
    
    do {
        if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)
        && (pid == te.th32OwnerProcessID || pid == 0)) {

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (hThread == INVALID_HANDLE_VALUE) {
                if (GetLastError() != ERROR_ACCESS_DENIED) {
                    printf("Failed to open handle to thread %d, error: %d\n", te.th32ThreadID, GetLastError());
                }
                continue;
            }

            LPVOID startAddress;
            NTSTATUS status = ((QUERYTHREADINFO)NtQueryInformationThread)(hThread,
            ThreadQuerySetWin32StartAddress, &startAddress, sizeof(LPVOID), NULL);
            if (status != STATUS_SUCCESS) {
                printf("Failed to query thread info, error: %d\n", GetLastError());
                CloseHandle(hThread);
                continue;
            }
            CloseHandle(hThread);

            BOOL result = DoesAddressPointToModule(startAddress, te.th32OwnerProcessID);
            if (!result) {
                THREAD_ENTRY* tmp = NULL;
                tmp = (THREAD_ENTRY*)realloc(oddThreads, ((*oddCount)+1)*sizeof(THREAD_ENTRY));
                if (tmp == NULL) {
                    printf("Failed to realloc thread list to size of %dB\n", ((*oddCount)+1)*sizeof(THREAD_ENTRY));
                    return oddThreads;
                }
                oddThreads = tmp;
                oddThreads[(*oddCount)].tid = te.th32ThreadID;
                oddThreads[(*oddCount)].pid = te.th32OwnerProcessID;
                oddThreads[(*oddCount)].startAddress = startAddress;
                (*oddCount)++;
            }
            //TODO: Stack walk and check return address of each frame
            //TODO: check if address points to lib loading function
        }
    } while (Thread32Next(snapshot, &te));
    CloseHandle(snapshot);
    return oddThreads;
}

THREAD_ENTRY* ScanThreadsGlobally(size_t* oddCount) {
    return ScanProcessThreads(0, oddCount);
}

// This function will return an array of all stack frames' return addresses
LPVOID* StackWalkForReturnAddresses(HANDLE hThread, HANDLE hProcess, size_t* frameCount) {

}

// simple wrapper over StackWalkForReturnAddresses
LPVOID* StackWalkForReturnAddressesById(DWORD tid, DWORD pid, size_t* frameCount) {
    HANDLE hProcess = OpenProcess(, FALSE, pid);
    if (hProcess == INVALID_HANDLE_VALUE) {

        return NULL;
    }

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (hThread == INVALID_HANDLE_VALUE) {

        return NULL;
    }

    return StackWalkForReturnAddresses(hThread, hProcess, frameCount);
}

DWORD GetParentPid(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
    if (status != STATUS_SUCCESS) {
        return 0;
    }
    return (DWORD)pbi.InheritedFromUniqueProcessId;
}

BOOL IsProcessElevated(HANDLE hProcess) {
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return elevation.TokenIsElevated != 0;
}

DWORD GetProcessIntegrityLevel(HANDLE hProcess) {
    HANDLE hToken = NULL;
    DWORD dwSize = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD integrityLevel = 0;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return 0;
    }

    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    pTIL = (PTOKEN_MANDATORY_LABEL)malloc(dwSize);

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize)) {
        free(pTIL);
        CloseHandle(hToken);
        return 0;
    }

    integrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, 
        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    free(pTIL);
    CloseHandle(hToken);
    return integrityLevel;
}

// Is the memory MEM_IMAGE, MEM_MAPPED or MEM_PRIVATE?
// File mappings without SEC_IMAGE flag are MEM_MAPPED.
// "Normal" allocations like VirtualAlloc are MEM_PRIVATE. 
// All normally loaded code should be MEM_IMAGE. It is a file mapping with SEC_IMAGE flag.
int GetAddressMemoryType(HANDLE hProcess, LPVOID address) {
    if (VirtualQueryEx(hProcess, lpBaseAddress, &mbi, sizeof(mbi)) == 0) {
        printf("VirtualQueryEx failed, error: %d\n", GetLastError());
        return -1;
    }
    return mbi.Type;
}

HANDLE* SuspendProcess(DWORD pid, size_t* threadCount) {
    (*threadCount)  = 0;
    HANDLE* threads = NULL;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to get snapshot of threads, error: %d\n", GetLastError());
        return NULL;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (!Thread32First(snapshot, &te)) {
        printf("Failed to enumerate first thread, error: %d", GetLastError());
        return NULL;
    }

    do {
        if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)
        && (pid == te.th32OwnerProcessID)) {

            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (hThread == INVALID_HANDLE_VALUE) {
                if (GetLastError() != ERROR_ACCESS_DENIED) {
                    printf("Failed to open handle to thread %d, error: %d\n", te.th32ThreadID, GetLastError());
                }
                continue;
            }
            DWORD result = SuspendThread(hThread);
            if (result == -1) {
                printf("Failed to suspend thread, error: %d\n", GetLastError());
                continue;
            }
            printf("Suspended thread %d (previous suspension count: %d)\n", te.th32ThreadID, result);


            HANDLE* tmp = NULL;
            tmp = (HANDLE*)realloc(threads, ((*threadCount)+1)*sizeof(HANDLE));
            if (tmp == NULL) break;
            threads = tmp;
            threads[*threadCount] = hThread;
            (*threadCount)++;
        }
    } while (Thread32Next(snapshot, &te));
    CloseHandle(snapshot);
    return threads;
}

void ResumeProcess(HANDLE* threads, size_t threadCount) {
    for (size_t i = 0; i < threadCount; i++) {
        DWORD result = ResumeThread(threads[i]);
        if (result == -1) {
            printf("[!] Failed to suspend thread, error: %d\n", GetLastError());
        }
        CloseHandle(threads[i]);
    }
    free(threads);
}