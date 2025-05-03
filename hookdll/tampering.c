#include <windows.h>
#include <openssl/sha.h>

void heartbeat(HANDLE hPipe) {
    LPCVOID message = "heartbeat";
    if (!WriteFile(hPipe, message, strlen(message), &dwBytesWritten, NULL)) {
        printf("\n[!] Failed to send heartbeat, error code: 0x%X\n", GetLastError());
    } else {
        SetEvent(hHbEvent);
        printf("[+] Sent heartbeat\n");
    }
}

// returns hash of modules .text
void hashModuleText(HMODULE moduleBase, unsigned char output[SHA256_DIGEST_LENGTH]) {
    //TODO: parse pe file to locate .text section
    //TODO: get DOS header

    //TODO: get NT headers


    //TODO: hash the contents
}

void getFuncHash(PVOID funcAddress, int length, unsigned char output[SHA256_DIGEST_LENGTH]) {
    // check that memory can be read
    /*MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(funcAddress, &mbi, sizeof(mbi))) {
        if (!(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE))) {

        }
    }*/
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, funcAddress, length);
    SHA256_Final(output, &ctx);
}

