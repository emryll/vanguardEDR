#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "memscan.h"

#define RULES_DIR ".\\rules"
#define DEFAULT_LOG "agent.log"

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

// read file contents onto buffer. caller is responsible for freeing buffer
uint8_t* ReadFileEx(char* path, size_t* out_len) {
    HANDLE file = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("Failed to open file, error: %d\n", GetLastError());
        return NULL;
    }
    DWORD size = GetFileSize(file, NULL);
    if (size == INVALID_FILE_SIZE) {
        printf("Failed to get file size, error: %d\n", GetLastError());
        CloseHandle(file);
        return NULL;
    }
    uint8_t* content = (uint8_t*)malloc(size+1);
    if (content == NULL) {
        printf("Failed to allocate buffer for file\n");
        CloseHandle(file);
        return NULL;
    }
    DWORD bytesRead;
    if (!ReadFile(file, content, size, &bytesRead, NULL) || bytesRead < size) {
        printf("Failed to read file, error: %d\n", GetLastError());
        CloseHandle(file);
        return NULL;
    }
    content[size] = '\0';
    CloseHandle(file);
    *out_len = size;
    return content;
}

// caller is responsible for freeing buffer if call succeeds. NULL return value means fail
uint8_t* ReadProcessMemoryEx(HANDLE hProcess, LPVOID address, size_t size, size_t* readBytes) {
    if (size == 0) {
        printf("[!] Invalid size entered to ReadProcessMemoryEx, size must be >0\n");
        return NULL;
    }
    if (address == NULL) {
        printf("[!] NULL address entered to ReadProcessMemoryEx\n");
        return NULL;
    }

    uint8_t* buffer = (uint8_t*)malloc(size);
    if (buffer == NULL) {
        return NULL;
    }

    if (!ReadProcessMemory(hProcess, address, buffer, size, readBytes)) {
        printf("[!] Failed to read remote process memory at 0x%p, error: %d\n", address, GetLastError());
        free(buffer);
        return NULL;
    }

    return buffer;
}

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

//works
// reads .text of main module, of a remote process. Caller is responsible for freeing buffer
uint8_t* GetModuleText(HANDLE hProcess, size_t* size) {
    DWORD numModules;
    DWORD bytesNeeded;

    // Get amount of modules loaded by the process
    if (EnumProcessModules(hProcess, NULL, 0, &bytesNeeded)) {
        numModules = bytesNeeded / sizeof(HMODULE);
    } else {
        printf("[!] Failed to get module amount, error: %d\n", GetLastError());
        return GetLastError();
    }

    HMODULE* hModules = (HMODULE*)malloc(bytesNeeded);
    if (hModules == NULL) {
        printf("[!] Failed to allocate array of module handles, size: %d\n", bytesNeeded);
        return NULL;
    }
    // get the handles of all loaded modules
    if (!EnumProcessModules(hProcess, hModules, bytesNeeded, &bytesNeeded)) {
        return NULL;
    }
    MODULE_INFO modInfo;
    if (GetModuleInformation(hProcess, hModules[0], &modInfo, sizeof(modInfo))) {
        free(hModules);
        LPVOID baseAddress = modInfo.lpBaseOfDll;
        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), NULL)) {
            printf("[!] Failed to read DOS header of remote process, error: %d\n", GetLastError());
            return NULL;
        }

        LPVOID ntHeaderAddress = baseAddress + dosHeader.e_lfanew;
        IMAGE_NT_HEADERS ntHeader;
        if (!ReadProcessMemory(hProcess, ntHeaderAddress, &ntHeader, sizeof(ntHeader), NULL)) {
            printf("[!] Failed to read NT header of remote process, error: %d\n", GetLastError());
            return NULL;
        }

        LPVOID sectionHeadersAddress = ntHeaderAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders.FileHeader.SizeOfOptionalHeader;
        DWORD numSections = ntHeaders.FileHeader.NumberOfSections;
        PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * numSections);
        if (sectionHeaders == NULL) {
            printf("[!] Failed to allocate memory for section headers\n");
            return NULL;
        }

        if (!ReadProcessMemory(hProcess, sectionHeadersAddress, sectionHeaders, sizeof(IMAGE_SECTION_HEADER) * numSections, NULL)) {
            printf("[!] Failed to read sections headers of remote process, error: %d\n", GetLastError());
            return NULL;
        }

        LPVOID textAddress;
        for (DWORD i = 0; i < numSections; i++) {
            if (stricmp((char*)sectionHeaders[i].Name, ".text") == 0) {
                textAddress = (LPVOID)((DWORD_PTR)baseAddress + sectionHeaders[i].VirtualAddress);
                *size = sectionHeaders[i].VirtualSize;

                //printf("Text section found!\n\t\\==={ Address: 0x%p\n\t \\=={ Size: %d\n", textAddress, *size);
                break;
            }
        }
        free(sectionHeaders);

        uint8_t* buffer = (uint8_t*)malloc(*size);
        if (buffer == NULL) {
            printf("[!] Failed to allocate buffer for .text, size: %d\n", size);
            return NULL;
        }
        size_t bytesRead;
        if (ReadProcessMemory(hProcess, textAddress, buffer, *size, &bytesRead)) {
            if (bytesRead != *size) {
                printf("[!] Bytes read is not equivelant to .text size:\n\t.text size: %dB\n\tbytes read: %dB\n", *size, bytesRead);
            }
            return buffer;
        } else {
            printf("[!] Failed to read .text(%dB), error: %d\n", size, GetLastError());
            free(buffer);
            return NULL;
        }
    } else { free(hModules); }
    return NULL;
}

// get addresses of all rwx regions within remote process. Caller is responsible for freeing returned array
MEMORY_REGION* GetRWXMemory(HANDLE hProcess, size_t* numRegions) {
    SYSTEM_INFO sysInfo;
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID lpBaseAddress = NULL;
    MEMORY_REGION* regions = NULL;
    *numRegions = 0;
    size_t bytesRead;

    // Get system info to determine the valid address range
    GetSystemInfo(&sysInfo);

    // Get all RWX memory regions
    while (lpBaseAddress < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, lpBaseAddress, &mbi, sizeof(mbi)) == 0) {
            lpBaseAddress = (LPBYTE)lpBaseAddress + sysInfo.dwPageSize;
            continue;
        }

        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE) {
            // Reallocate the array to store a new region
            regions = (MEMORY_REGION*)realloc(regions, (regionsCount + 1) * sizeof(MEMORY_REGION));
            if (regions == NULL) {
                printf("Failed to realloc memory for regions array.\n");
                return NULL;
            }

            regions[regionsCount].address = mbi.BaseAddress;
            regions[regionsCount].size = mbi.RegionSize;
            (*numRegions)++;
        }

        lpBaseAddress = (LPBYTE)lpBaseAddress + mbi.RegionSize;
    }
    return regions;
}

// gets all commited memory regions of remote process
MEMORY_REGION* GetAllMemoryRegions(HANDLE hProcess, size_t* numRegions) {
    SYSTEM_INFO sysInfo;
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID lpBaseAddress = NULL;
    MEMORY_REGION* regions = NULL;
    *numRegions = 0;
    size_t bytesRead;

    // Get system info to determine the valid address range
    GetSystemInfo(&sysInfo);

    while (lpBaseAddress < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, lpBaseAddress, &mbi, sizeof(mbi)) == 0) {
            lpBaseAddress = (LPBYTE)lpBaseAddress + sysInfo.dwPageSize;
            continue;
        }
        //if (mbi.State == MEM_COMMIT && mbi.Protect & PAGE_READONLY && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS) && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS)) {
            // Reallocate the array to store a new region
            regions = (MEMORY_REGION*)realloc(regions, (*numRegions + 1) * sizeof(MEMORY_REGION));
            if (regions == NULL) {
                printf("Failed to realloc memory for regions array.\n");
                return NULL;
            }

            regions[*numRegions].address = mbi.BaseAddress;
            regions[*numRegions].size = mbi.RegionSize;
            (*numRegions)++;
        }
        lpBaseAddress = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    return regions;
}

//works
// returns all sections of all modules within a specified process. caller is responsible for freeing with FreeRemoteModuleArray()
REMOTE_MODULE* GetAllSectionsOfProcess(HANDLE hProcess, size_t* moduleCount) {
    DWORD numModules;
    DWORD bytesNeeded;

    // Get amount of modules loaded by the process
    if (EnumProcessModules(hProcess, NULL, 0, &bytesNeeded)) {
        numModules = bytesNeeded / sizeof(HMODULE);
    } else {
        printf("[!] Failed to get module amount, error: %d\n", GetLastError());
        return NULL;
    }

    HMODULE* hModules = (HMODULE*)malloc(bytesNeeded);
    if (hModules == NULL) {
        printf("[!] Failed to allocate array of module handles, size: %d\n", bytesNeeded);
        return NULL;
    }
    // get the handles of all loaded modules
    if (!EnumProcessModules(hProcess, hModules, bytesNeeded, &bytesNeeded)) {
        printf("[!] Failed to enumerate remote process modules, error: %d\n", GetLastError());
        free(hModules);
        return NULL;
    }

    REMOTE_MODULE* modules = (REMOTE_MODULE*)malloc(sizeof(REMOTE_MODULE) * numModules);
    if (modules == NULL) {
        printf("[!] Failed to allocate memory for REMOTE_MODULE array\n");
        free(hModules);
        return NULL;
    }

    //* loop through modules 
    for (DWORD i = 0; i < numModules; i++) {
        char baseName[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, hModules[i], baseName, MAX_PATH) == 0) {
            printf("[!] Failed to get module name, error: %d\n", GetLastError());
            continue;
        }
        //printf("[i] Found %s\n", baseName);

        strncpy(modules[i].name, baseName, MAX_PATH);
        modules[i].name[MAX_PATH-1] = '\0';

        MODULEINFO modInfo;
        if (!GetModuleInformation(hProcess, hModules[i], &modInfo, sizeof(modInfo))) {
            printf("[!] Failed to get module information, error: %d\n", GetLastError());
            free(hModules);
            free(modules);
            return NULL;
        }
        // find section headers to get addresses
        LPBYTE baseAddress = (LPBYTE)modInfo.lpBaseOfDll;
        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), NULL)) {
            printf("[!] Failed to read DOS header of remote process, error: %d\n", GetLastError());
            free(hModules);
            free(modules);
            return NULL;
        }

        LPBYTE ntHeaderAddress = baseAddress + dosHeader.e_lfanew;
        IMAGE_NT_HEADERS ntHeader;
        if (!ReadProcessMemory(hProcess, ntHeaderAddress, &ntHeader, sizeof(ntHeader), NULL)) {
            printf("[!] Failed to read NT header of remote process, error: %d\n", GetLastError());
            free(hModules);
            free(modules);
            return NULL;
        }

        LPVOID sectionHeadersAddress = ntHeaderAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader.FileHeader.SizeOfOptionalHeader;
        modules[i].numSections = ntHeader.FileHeader.NumberOfSections;
        //printf("[i] Found %d sections\n", modules[i-failCount].numSections);
        modules[i].sections = (MEMORY_REGION*)malloc(sizeof(MEMORY_REGION) * (modules[i].numSections));
        if (modules[i].sections == NULL) {
            printf("[!] Failed to allocate MEMORY_REGION array\n");
            free(hModules);
            free(modules);
            return NULL;
        }

        PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * (modules[i].numSections));
        if (sectionHeaders == NULL) {
            printf("[!] Failed to allocate memory for section headers\n");
            free(hModules);
            for (int j = 0; j < i; j++) {
                free(modules[j].sections);
            }
            free(modules);
            return NULL;
        }

        if (!ReadProcessMemory(hProcess, sectionHeadersAddress, sectionHeaders, sizeof(IMAGE_SECTION_HEADER) * (modules[i].numSections), NULL)) {
            printf("[!] Failed to read sections headers of remote process, error: %d\n", GetLastError());
            free(hModules);
            free(sectionHeaders);
            for (int j = 0; j < i; j++) {
                free(modules[j].sections);
            }
            free(modules);
            return NULL;
        }

        // loop through sections
        for (DWORD j = 0; j < modules[i].numSections; j++) {
            modules[i].sections[j].address = (LPVOID)((DWORD_PTR)baseAddress + sectionHeaders[j].VirtualAddress);
            modules[i].sections[j].size = sectionHeaders[j].Misc.VirtualSize;
        }
        free(sectionHeaders);
    }
    free(hModules);
    *moduleCount = numModules;
    return modules;
}

//works
// returns all sections of a specified module withing specified process. caller is responsible for freeing
MEMORY_REGION* GetAllSectionsOfModule(HANDLE hProcess, char* moduleName, size_t* numRegions) {
    DWORD numModules;
    DWORD bytesNeeded;

    // Get amount of modules loaded by the process
    if (EnumProcessModules(hProcess, NULL, 0, &bytesNeeded)) {
        numModules = bytesNeeded / sizeof(HMODULE);
    } else {
        printf("[!] Failed to get module amount, error: %d\n", GetLastError());
        return NULL;
    }

    HMODULE* hModules = (HMODULE*)malloc(bytesNeeded);
    if (hModules == NULL) {
        printf("[!] Failed to allocate array of module handles, size: %d\n", bytesNeeded);
        return NULL;
    }
    // get the handles of all loaded modules
    if (!EnumProcessModules(hProcess, hModules, bytesNeeded, &bytesNeeded)) {
        printf("[!] Failed to enumerate remote process modules, error: %d\n", GetLastError());
        free(hModules);
        return NULL;
    }

    //* loop through modules looking for specified one
    for (DWORD i = 0; i < numModules; i++) {
        char baseName[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, hModules[i], baseName, MAX_PATH) == 0) {
            printf("[!] Failed to get module name, error: %d\n", GetLastError());
            continue;
        }

        // check if its right one
        if (strlen(moduleName) != strlen(baseName) || stricmp(moduleName, baseName, strlen(moduleName)) != 0) {
            continue;
        }
        printf("[i] Found %s\n", baseName);

        MODULEINFO modInfo;
        if (!GetModuleInformation(hProcess, hModules[i], &modInfo, sizeof(modInfo))) {
            printf("[!] Failed to get module information, error: %d\n", GetLastError());
            free(hModules);
            return NULL;
        }
        // find section headers to get addresses
        LPVOID baseAddress = modInfo.lpBaseOfDll;
        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), NULL)) {
            printf("[!] Failed to read DOS header of remote process, error: %d\n", GetLastError());
            free(hModules);
            return NULL;
        }

        LPVOID ntHeaderAddress = baseAddress + dosHeader.e_lfanew;
        IMAGE_NT_HEADERS ntHeader;
        if (!ReadProcessMemory(hProcess, ntHeaderAddress, &ntHeader, sizeof(ntHeader), NULL)) {
            printf("[!] Failed to read NT header of remote process, error: %d\n", GetLastError());
            free(hModules);
            return NULL;
        }

        LPVOID sectionHeadersAddress = ntHeaderAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader.FileHeader.SizeOfOptionalHeader;
        *numRegions = ntHeader.FileHeader.NumberOfSections;
        printf("[i] Found %d sections\n", *numRegions);
        MEMORY_REGION* sections = (MEMORY_REGION*)malloc(sizeof(MEMORY_REGION) * (*numRegions));
        if (sections == NULL) {
            printf("[!] Failed to allocate MEMORY_REGION array\n");
            free(hModules);
            return NULL;
        }

        PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * (*numRegions));
        if (sectionHeaders == NULL) {
            printf("[!] Failed to allocate memory for section headers\n");
            free(hModules);
            free(sections);
            return NULL;
        }

        if (!ReadProcessMemory(hProcess, sectionHeadersAddress, sectionHeaders, sizeof(IMAGE_SECTION_HEADER) * (*numRegions), NULL)) {
            printf("[!] Failed to read sections headers of remote process, error: %d\n", GetLastError());
            free(hModules);
            free(sectionHeaders);
            return NULL;
        }

        // loop through sections
        for (DWORD i = 0; i < (*numRegions); i++) {
                sections[i].address = (LPVOID)((DWORD_PTR)baseAddress + sectionHeaders[i].VirtualAddress);
                sections[i].size = sectionHeaders[i].Misc.VirtualSize;
        }
        free(sectionHeaders);
        free(hModules);
        return sections;
    }
    free(hModules);
    return NULL;
}

void FreeRemoteModuleArray(REMOTE_MODULE* modules, size_t numModules) {
    for (size_t i = 0; i < numModules; i++) {
        free(modules[i].sections);
    }
    free(modules);
}

int NotifyMatchAndRequestScan(char* programName, DWORD pid, YRX_SCANNER* scanner) {
    char text[520];
    sprintf("%s(%d) is suspicious and may be malware, would you like to run a full scan in the background? It may affect performance.", programName, pid);
    int answer = MessageBox(NULL, text, "Alert!", MB_YESNO | MB_ICONWARNING | MB_SYSTEMODAL);
    if answer == 0 {
        printf("\n[!] Failed to display message box, error: %d\n", GetLastError());
    } else if (answer == IDYES) {
        MemoryScanEx(pid, scanner);
        //TODO: check api, file and reg patterns
        //TODO: check hook and self integrity
    }
}