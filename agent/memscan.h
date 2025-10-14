#ifndef MEMSCAN_H
#define MEMSCAN_H

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <yara_x.h>

typedef struct {
    void* address;
    size_t size;
} MEMORY_REGION;

typedef struct {
    char name[MAX_PATH];
    size_t         numSections;
    MEMORY_REGION* sections;
} REMOTE_MODULE;

//FILE* OpenLog(char*);
//void Log(const char*, ...);

int GetYaraRules(char***, size_t*);
void FreePaths(char***, size_t);
uint8_t* ReadFile2(char*, size_t*);
uint8_t* GetModuleText(HANDLE, size_t*);
uint8_t* ReadProcessMemoryEx(HANDLE, LPVOID, size_t, size_t*);
MEMORY_REGION* GetRWXMemory(HANDLE, size_t*);
MEMORY_REGION* GetAllMemoryRegions(HANDLE, size_t*);
MEMORY_REGION* GetAllSectionsOfModule(HANDLE, char*, size_t*);
REMOTE_MODULE* GetAllSectionsOfProcess(HANDLE, size_t*);
void FreeRemoteModuleArray(REMOTE_MODULE*, size_t);

int InitializeYara(YRX_RULES*, YRX_SCANNER*, void*);
void UninitializeYara(YRX_RULES*, YRX_SCANNER*);
int ScanRWXMemory(HANDLE, YRX_SCANNER*);
int ScanMainModuleText(HANDLE, YRX_SCANNER*);
int MemoryScanEx(unsigned int, YRX_SCANNER*);
int ModuleMemoryScan(unsigned int, char*, YRX_SCANNER*);
int InjectDll(DWORD);

#endif