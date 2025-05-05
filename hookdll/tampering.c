#include <windows.h>
#include <openssl/evp.h>
#include <stdio.h>

#define EVP_MAX_MD_SIZE 64

typedef struct {
    DWORD pid;
    char Heartbeat[260];
} HEARTBEAT;

void heartbeat(HANDLE hPipe) {
    HEARTBEAT heartbeat;
    strcpy(heartbeat.Heartbeat, "heartbeat");
    heartbeat.pid = GetCurrentProcessId();
    DWORD dwBytesWritten;
    if (!WriteFile(hPipe, &heartbeat, sizeof(heartbeat), &dwBytesWritten, NULL)) {
        printf("\n[!] Failed to send heartbeat, error code: 0x%X\n", GetLastError());
    } else {
        //SetEvent(hHbEvent);
        printf("[+] Sent heartbeat\n");
    }
}

// returns hash of modules .text
void HashTextSection(HMODULE moduleBase, unsigned char* output, unsigned int* hashLen) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("\n[!] Invalid DOS Header!\n");
        return;
    }
    
    // get PE header offset
    DWORD peHeader = dosHeader->e_lfanew;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + peHeader);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("\n[!] Invalid NT Header!\n");
        return;
    }
    printf("[+] NT header signature is valid\n");

    // the section table comes after optional header
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            ULONG_PTR textAddress = (ULONG_PTR)moduleBase + sectionHeader[i].VirtualAddress;
            DWORD textSize = sectionHeader[i].SizeOfRawData;

            //printf("[+] Found .text section!\n\t\\==={ Address: 0x%X\n\t \\=={ Size: %d\n\t  \\={ RVA: 0x%X\n", textAddress, textSize, sectionHeader[i].VirtualAddress);
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
//            unsigned char hash[EVP_MAX_MD_SIZE];
            *hashLen = 0;

            // Initialize the context for SHA256
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
                printf("[.text] Error initializing digest\n");
                return;
            }

            // Update the hash with the .text section data
            if (EVP_DigestUpdate(ctx, (LPCVOID)textAddress, textSize) != 1) {
                printf("[.text] Error updating digest\n");
                return;
            }

            // Finalize the hash and get the result
            if (EVP_DigestFinal_ex(ctx, output, hashLen) != 1) {
                printf("Error finalizing digest\n");
                return;
            }

            EVP_MD_CTX_free(ctx);  // Free the context

            printf("[i] Hash of .text section: ");
            for (int i = 0; i < *hashLen; i++) {
                printf("%02X ", output[i]);
            }
            printf("\n");
            return;
        }
    }
    printf("\n[!] Couldn't find .text section!\n");
}
/*
void getFuncHash(PVOID funcAddress, int length, unsigned char output[SHA256_DIGEST_LENGTH]) {
    // check that memory can be read
    /*MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(funcAddress, &mbi, sizeof(mbi))) {
        if (!(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE))) {

        }
    }

}

*/