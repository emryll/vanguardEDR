#include <windows.h>
#include <stdio.h>
#include <openssl/evp.h>

void DumpTextSection(HMODULE moduleBase) {
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

    for (int i = 0; ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            ULONG_PTR textAddress = (ULONG_PTR)moduleBase + sectionHeader[i].VirtualAddress;
            DWORD textSize = sectionHeader[i].SizeOfRawData;

            printf("[+] Found .text section!\n\t\\==={ Address: 0x%X\n\t \\=={ Size: %d\n\t  \\={ RVA: 0x%X\n", textAddress, textSize, sectionHeader[i].VirtualAddress);
            
            /*unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, (LPCVOID)textAddress, textSize);
            SHA256_Final(hash, &ctx);*/
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hashLen = 0;

            // Initialize the context for SHA256
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
                printf("Error initializing digest\n");
                return;
            }

            // Update the hash with the .text section data
            if (EVP_DigestUpdate(ctx, (LPCVOID)textAddress, textSize) != 1) {
                printf("Error updating digest\n");
                return;
            }

            // Finalize the hash and get the result
            if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
                printf("Error finalizing digest\n");
                return;
            }

            EVP_MD_CTX_free(ctx);  // Free the context

            printf("[i] Hash of .text section: ");
            for (int i = 0; i < hashLen; i++) {
                printf("%02X ", hash[i]);
            }
            printf("\n");
            /*
            unsigned char* buf = (unsigned char*)malloc(textSize);
            if (buf == NULL) {
                printf("\n[!] Failed to malloc!\n");
                return;
            }
            size_t bytesRead;
            HANDLE hProcess = GetCurrentProcess();
            if (hProcess == NULL) {
                printf("\n[!] Failed to get process handle, error code: 0x%X\n", GetLastError());
                free(buf);
                return;
            }
            BOOL ok = ReadProcessMemory(hProcess, (LPCVOID)textAddress, buf, textSize, &bytesRead);
            if (!ok) {
                printf("\n[!] Failed to read .text, error code: 0x%X\n", GetLastError());
                free(buf);
                return;
            }
            printf("[+] Read %d bytes\n", bytesRead);
            for (size_t i = 0; i < bytesRead; i++) {
                if (i % 16 == 0 && i != 0) {
                    printf("\n");
                }
                printf("%02X ", buf[i]);
            }
            printf("\n");
            free(buf);*/
            return;
        }
    }
    printf("\n[!] Couldn't find .text section!\n");
}

int main() {
    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    if (hKernel32 != NULL) {
        DumpTextSection(hKernel32);
    } else {
        printf("\n[!] Failed to get kernel32 handle, error code: 0x%X", GetLastError());
    }
}