#include <windows.h>
#include <openssl/evp.h>
#include "hook.h"

size_t GetTelemetryPacketSize(DWORD type, size_t dynamicCount) {
    switch (type) {
        case TM_TYPE_API_CALL:
            return sizeof(TELEMETRY_HEADER) + sizeof(API_CALL_HEADER) + (dynamicCount * sizeof(API_ARG));
        case TM_TYPE_TEXT_INTEGRITY:
            return sizeof(TELEMETRY_HEADER) + sizeof(TEXT_CHECK);
        case TM_TYPE_IAT_INTEGRITY:
            return sizeof(TELEMETRY_HEADER) + (dynamicCount * sizeof(IAT_MISMATCH));
    }
    return 0;
}

// data size is packet size - telemetry header
TELEMETRY_HEADER GetTelemetryHeader(DWORD type, size_t dataSize) {
    TELEMETRY_HEADER header;
    header.pid       = GetCurrentProcessId();
    header.type      = type;
    header.dataSize  = dataSize;
    header.timeStamp = time(NULL);
    return header;
}

API_CALL_HEADER GetApiCallHeader(LPCSTR dllName, LPCSTR funcName, size_t argCount) {
    API_CALL_HEADER header;
    header.tid = GetCurrentThreadId();
    strncpy(header.dllName, dllName, sizeof(header.dllName));
    strncpy(header.funcName, funcName, sizeof(header.dllName));
    header.argCount = argCount;
    return header;
}

TEXT_CHECK GetTextIntegrityPacket(LPCSTR moduleName, BOOL match) {
    TEXT_CHECK packet;
    if (match) {
        packet.result = TRUE;
    } else {
        packet.result = FALSE;
    }
    strncpy(packet.module, moduleName, sizeof(packet.module));
    return packet;
}
/*
void GetHookIntegrityTelemetryPacket(TELEMETRY* tm, int* mismatches, int mismatchCount) {
    tm.header.timeStamp = time(NULL);
    tm.header.pid = GetCurrentProcessId;
    tm.header.type = TM_TYPE_HOOK_INTEGRITY;

    tm.data.funcCheck.mismatchCount = mismatchCount;
    for (size_t i = 0; i < mismatchCount; i++) {
        strncpy(tm.data.funcCheck.mismatches[i], 
        HookList[mismatches[i]].funcName,
        sizeof(tm.data.funcCheck.mismatches[i]));
    }
    return;
}*/

// return pointer to the Process Environment Block
PPEB getPEB() {
    return (PPEB)__readgsqword(0x60);  // For x64
}

//TODO: get addresses of every function of module by walking EAT

// boilerplate code for iat parsing
PIMAGE_IMPORT_DESCRIPTOR GetIatImportDescriptor(LPVOID moduleBase) {
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != PE_SIGNATURE) {
        return NULL;
    }

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	return (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)moduleBase);
}

// works
int FillFunctionHash(unsigned char* output, LPVOID address, size_t hashLen) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_MD_CTX_new() failed\n");
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Error initializing digest\n");
        EVP_MD_CTX_free(ctx);
        return -2;
    }

    if (EVP_DigestUpdate(ctx, address, hashLen) != 1) {
        fprintf(stderr, "Error updating digest\n");
        EVP_MD_CTX_free(ctx);
        return -3;
    }

    unsigned int len;
    if (EVP_DigestFinal_ex(ctx, output, &len) != 1) {
        fprintf(stderr, "Error finalizing digest\n");
        EVP_MD_CTX_free(ctx);
        return -3;
    }
    EVP_MD_CTX_free(ctx);

    fprintf(stderr, "[i] Hash:\n");
    for (int i = 0; i < len; i++) {
        fprintf(stderr, "%02X ", output[i]);
    }
    fprintf(stderr, "\n");

    return 0;
}