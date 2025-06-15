#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <stdio.h>

#pragma comment (lib, "wintrust.lib")

int verify_signature(const wchar_t* filepath) {
    LONG status;

    // Define the WinTrust structures
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filepath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;
    trustData.hWVTStateData = NULL;

    // Call WinVerifyTrust
    status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    // Clean up
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return status;
}

int main(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        wprintf(L"Usage: %s <path-to-exe>\n", argv[0]);
        return 1;
    }

    LONG result = verify_signature(argv[1]);

    switch (result) {
        case ERROR_SUCCESS:
            wprintf(L"Signature is valid.\n");
            break;
        case TRUST_E_NOSIGNATURE:
            wprintf(L"The file is not signed.\n");
            break;
        case TRUST_E_BAD_DIGEST:
            wprintf(L"The file is signed but has been tampered with.\n");
            break;
        default:
            wprintf(L"Signature verification failed. Error: 0x%08X\n", result);
            break;
    }

    return 0;
}