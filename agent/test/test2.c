#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <stdio.h>

// Link with wintrust.lib and crypt32.lib
#pragma comment (lib, "wintrust")
#pragma comment (lib, "crypt32")

// VerifyEmbeddedSignature:
//   pwszSourceFile - full path to the file to be verified.
LONG VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
    LONG lStatus;
    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    WINTRUST_DATA WinTrustData;
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.dwProvFlags = WTD_USE_DEFAULT_OSVER_CHECK;
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    // Do not show any UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    // Verify file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    // Set pointer to WINTRUST_FILE_INFO structure.
    WinTrustData.pFile = &FileData;
    // Specify that we want to verify and then close state data.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;

    // This GUID is for the action: WINTRUST_ACTION_GENERIC_VERIFY_V2
    GUID WVTPolicyGUID = { 
        0xaac56b, 0xcd44, 0x11d0,
        {0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}
    };

    // Call WinVerifyTrust to verify the file.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    // Close the state data. This is necessary to free resources.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return lStatus;
}

int main(void)
{
    LPCWSTR filePath = L"C:\\Windows\\System32\\notepad.exe"; // Change to your target file

    LONG status = VerifyEmbeddedSignature(filePath);

    if (status == ERROR_SUCCESS)
    {
        wprintf(L"The file \"%ls\" is signed and the signature is valid.\n", filePath);
    }
    else if (status == TRUST_E_NOSIGNATURE)
    {
        wprintf(L"The file \"%ls\" is not signed.\n", filePath);
    }
    else
    {
        wprintf(L"The file \"%ls\" is signed but the signature is invalid or untrusted (error: 0x%08lx).\n", filePath, status);
    }
    return 0;
}