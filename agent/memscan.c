#include <yara_x.h>

//? How do I portray results of scan to go side?

// takes any userdata callback can read/write to, returns rules and scanner. 
// Caller must free scanner then rules
int InitializeYara(YRX_RULES* rules, YRX_SCANNER* scanner, void* user_data) {
    //* create YARA compiler
    rules = NULL;
    scanner = NULL;
    YRX_COMPILER* compiler;
    if (yrx_compiler_create(0, &compiler) != SUCCESS) {
        printf("Failed to create YARA compiler\n");
        return -1;
    }

    //* load and compile YARA rules from disk
    char** paths = NULL;
    size_t count;
    int r = GetYaraRules(&paths, &count);
    if (r != 0) {
        printf("Failed to get yara rule files: %d\n", r);
        return -2;
    }

    for (size_t i = 0; i < count; i++) {
        size_t ruleSize;
        char* rule = ReadFileEx(paths[i], &ruleSize);
        if (rule == NULL || strlen(rule) == 0) {
            printf("Failed to read %s, it may not exist\n", paths[i]);
            return -3;
        }
        if (yrx_compiler_add_source(compiler, rule) != SUCCESS) {
            printf("Failed to add %s to compiler", paths[i]);
            FreePaths(&paths, count);
            free(rule);
            return -4;
        }
        free(rule);
    }
    FreePaths(&paths, count);

    //* build the rules
    rules = yrx_compiler_build(compiler) 
    if (rules == NULL) {
        printf("Failed to compile rules\n");
        yrx_compiler_destroy(compiler);
        return -5;
    }
    yrx_compiler_destroy(compiler);

    //* create scanner
    if (yrx_scanner_create(rules, &scanner) != SUCCESS) {
        printf("Failed to create scanner\n");
        yrx_rules_destroy(rules);
        return -6;
    }

    //* register scanner callback
    if (yrx_scanner_on_matching_rule(scanner, YaraCallback, user_data) != SUCCESS) {
        printf("Failed to register scanner callback\n");
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
        return -7;
    }

    return 0;
}

void UninitializeYara(YRX_RULES* rules, YRX_SCANNER* scanner) {
    yrx_scanner_dstroy(scanner);
    yrx_rules_destroy(rules);
}

//TODO: what to do when a pattern matches?
    // have some sort of array to store matches (rule id and severity)
void YaraCallback(YRX_RULE* rule, void* data) {
    const uint8_t* identifier;
    size_t len;

    if (yrx_rule_identifier(rule, &ident, &len) == SUCCESS) {
        printf("[i] Matched rule: %.*s\n", (int)len, ident);
    } else {
        printf("[!] Failed to get rule identifier\n");
    }
}

// scan all rwx memory of process
//TODO: test
int ScanRWXMemory(void* hProcess, YRX_SCANNER* scanner) {
    size_t numRegions;
    MEMORY_REGION* rwxRegions = GetRWXMemory(hProcess, &numRegions);
    if (rwxRegions == NULL) {
        printf("[!] Failed to get RWX regions\n");
        return -1;
    }
    printf("[i] Found %d RWX memory regions\n", numRegions);

    for (size_t i = 0; i < numRegions; i++) {
        size_t readBytes = 0;
        uint8_t* buffer = ReadProcessMemoryEx(hProcess, rwxRegions[i].address, rwxRegions[i].size, &readBytes);
        if (buffer == NULL || readBytes == 0) {
            printf("[!] Failed to read remote process memory at 0x%p\n", rwxRegions[i].address);
            continue;
        }
        printf("[i] Read %dB of RWX memory at 0x%p\n", bytesRead, rwxRegions[i].address);
        if (yrx_scanner_scan(scanner, buffer, readBytes) != SUCCESS) {
            printf("[!] Failed to scan buffer\n");
        }
        free(buffer);
    }
    return 0;
}

//TODO: test
int ScanMainModuleText(HANDLE hProcess, YRX_SCANNER* scanner) {
    size_t size;
    uint8_t* buffer = GetModuleText(hProcess, &size);
    if (buffer == NULL) {
        printf("[!] Failed to get main .text\n");
        return -1;
    }

    if (yrx_scanner_scan(scanner, buffer, size) != SUCCESS) {
        printf("[!] Failed to scan buffer\n");
        free(buffer);
        return -2;
    }
    free(buffer);
}

// scan rwx and .text of main module
int MemoryScan(unsigned int pid, YRX_SCANNER* scanner) {
    printf("\n[i] Performing basic memory scan on process %d...\n", pid);
    DWORD hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return GetLastError();
    }
    int r = ScanRWXMemory(hProcess, scanner);
    if (r != 0) {
        printf("[!] Failed to scan RWX memory of process %d, return value: %d\n", pid, r);
    }
    r = ScanMainModuleText(hProcess, scanner);
    if (r != 0) {
        printf("[!] Failed to scan main .text of process %d, return value: %d\n", pid, r);
    }
    CloseHandle(hProcess);
    return r;
}

// scan all sections of all modules
int MemoryScanEx(unsigned int pid, YRX_SCANNER* scanner) {
    printf("\n[i] Performing full memory scan on process %d...\n", pid);
    DWORD hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return GetLastError();
    }
    
    size_t numModules = 0;
    REMOTE_MODULE* modules = GetAllSectionsOfProcess(hProcess, &numModules);
    if (modules == NULL || numModules == 0) {
        printf("[!] Failed to get sections of process %d\n", pid);
        return -1;
    }

    for (size_t i = 0; i < numModules; i++) {
        printf("[i] Scanning %s...\n", modules[i].name);
        // loop through sections and scan them
        for (size_t j = 0; j < modules[i].numSections; j++) {
            printf("\t* section %d\n", j);
            size_t readBytes = 0;
            uint8_t* buffer = ReadProcessMemoryEx(hProcess, modules[i].sections[j].address, modules[i].sections[j].size, &readBytes);
            if (buffer == NULL || readBytes == 0) {
                printf("[!] Failed to read remote process memory at 0x%p\n", modules[i].sections[j].address);
                continue;
            }
            if (yrx_scanner_scan(scanner, buffer, readBytes) != SUCCESS) {
                printf("[!] Failed to scan section %d at 0x%p\n", j, modules[i].sections[j].address);
            }
            free(buffer);
        }
    }
    FreeRemoteModuleArray(modules);
    return 0;
}

// scan all sections of specified module 
int ModuleMemoryScan(unsigned int pid, char* moduleName, YRX_SCANNER* scanner) {
    printf("\n[i] Performing %s memory scan on process %d...\n", moduleName, pid);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return GetLastError();
    }
    size_t numSections = 0;
    MEMORY_REGION* sections = GetAllSectionsOfModule(hProcess, moduleName, &numSections);
    if (sections == NULL || numSections == 0) {
        printf("[!] Failed to get sections of %s within process %d\n", moduleName, pid);
        return -1;
    }
    
    for (size_t i = 0; i < numSections; i++) {
        size_t readBytes = 0;
        uint8_t* buffer = ReadProcessMemoryEx(hProcess, sections[i].address, sections[i].size, &readBytes);
        if (buffer == NULL || readBytes == 0) {
            printf("[!] Failed to read remote process memory at 0x%p\n", sections[i].address);
            continue;
        }
        if (yrx_scanner_scan(scanner, buffer, readBytes) != SUCCESS) {
            printf("[!] Failed to scan section %d at 0x%p\n", i, sections[i].address);
            free(buffer);
        }
        free(buffer);
    }
    free(sections);
}