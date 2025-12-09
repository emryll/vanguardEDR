#include <windows.h>
#include <ntdef.h>
#include <tdh.h>
#include <stdio.h>
#include "etw.h"

BOOL IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

// Only works with null terminated wide strings.
// Helper function to convert wide string to ansi. Caller must free the returned string.
char* ConvertWideToAnsi(WCHAR* wideStr) {
    // First call to get the required buffer size
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    if (sizeNeeded == 0) {
        printf("[debug] failed to get size, error: %d\n", GetLastError());
        return NULL;
    }

    char* ansiStr = (char*)malloc(sizeNeeded);
    if (!ansiStr) {
        printf("[debug] failed to allocate memory\n");
        return NULL;
    }

    // Using UTF-8 for safer conversion (https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte)
    int result = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, ansiStr, sizeNeeded, NULL, NULL);
    if (result == 0) {
        printf("[debug] Failed to convert wide string to UTF8, error: %d\n", GetLastError());
        free(ansiStr);
        return NULL;
    }

    return ansiStr;
}

char* ConvertUnicodeStringToAnsi(UNICODE_STRING* ustr) {
    if (!ustr || !ustr->Buffer || ustr->Length == 0 || ustr->MaximumLength == 0) {
        if (!ustr) {
            printf("[debug] !ustr\n");
        }
        if (!ustr->Buffer) {
            printf("[debug] !ustr->Buffer\n");
        }
        if (ustr->Length == 0) {
            printf("[debug] !ustr->Length == 0\n");
            printf("[debug] test print: %ls\n", ustr);
        }
        return NULL;
    }
    if (ustr->Length % 2 != 0) {
        printf("[debug] length field not divisible by 2, cant be unicode_string\n");
        return NULL;
    }

    wprintf(L"[debug] unicode_string (%d): %ls\n", ustr->Length, ustr->Buffer);

    size_t wcharCount = ustr->Length / sizeof(WCHAR);
    // ensure null terminated string
    WCHAR* nullTmp = (WCHAR*)malloc((wcharCount + 1) * sizeof(WCHAR));
    memcpy(nullTmp, ustr->Buffer, ustr->Length);
    nullTmp[wcharCount] = L'\0';

    char* ansi = ConvertWideToAnsi(nullTmp);
    printf("[debug] us -> ansi, resulting length: %d\n", strlen(ansi));
    free(nullTmp);
    return ansi;
}

//TODO: make this more memory efficient. also dont limit path to 260 chars
// The paths from events are wide strings and start with something like " \Device\HarddiskVolume".
// This function converts it to a normal ansi string path with drive letters. Caller must free string.
char* NormalizeEventPath(WCHAR* path) {
    //? should you also return string len?
    WCHAR drives[512] = {0};
    WCHAR deviceName[MAX_PATH] = {0};
    WCHAR driveLetter[3] = L"A:";
    WCHAR normalPath[MAX_PATH] = {0};

    // Get all logical drives' letters
    if (GetLogicalDriveStringsW(sizeof(drives) / sizeof(WCHAR), drives) == 0) {
        return FALSE;
    }
    
    // Iterate through each drive letter
    WCHAR* drive = drives;
    while (*drive) {
        driveLetter[0] = drive[0];
        
        // Query the device name for this drive letter
        if (QueryDosDeviceW(driveLetter, deviceName, MAX_PATH) != 0) {
            size_t deviceNameLen = wcslen(deviceName);
            
            // Check if path starts with this device name
            if (_wcsnicmp(path, deviceName, deviceNameLen) == 0) {
                swprintf(normalPath, MAX_PATH, L"%ls%ls", driveLetter, path + deviceNameLen);
                char* ansiPath = ConvertWideToAnsi(normalPath);
                
                return ansiPath;
            }
        }
        drive += wcslen(drive) + 1; // move to next one
    }
    return NULL;
}

//TODO: use TdhFormatProperty instead of TdhGetProperty, as its more efficient according to MSDN
BYTE* CreateFileEventPacket(PEVENT_RECORD event, size_t* packetSize) {
    FILE_EVENT etwHeader = {0};
    etwHeader.action = event->EventHeader.EventDescriptor.Id;
    (*packetSize) = sizeof(FILE_EVENT);
    BYTE* packet = (BYTE*)malloc(*packetSize);

    // get attached file paths
    if (event->UserDataLength > 0 && event->EventHeader.Flags != EVENT_HEADER_FLAG_STRING_ONLY) {
        PTRACE_EVENT_INFO info = NULL;
        ULONG infoSize = 0;
        TdhGetEventInformation(event, 0, NULL, info, &infoSize);
        info = (PTRACE_EVENT_INFO)malloc(infoSize);
        DWORD r = TdhGetEventInformation(event, 0, NULL, info, &infoSize);
        if (r != ERROR_SUCCESS) {
            printf("TdhGetEventInformation failed. r=%d, error: %d\n", r, GetLastError());
        } else {
            for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
                ParseFileEventParameter(event, i, info, &packet, packetSize, &etwHeader);
            }
            free(info);
        }
    }
    // the telemetry header is added to the packet at the end, because its values change while parsing parameters
    memcpy(packet, &etwHeader, sizeof(etwHeader));
    return packet;
}

BYTE* CreateRegistryEventPacket(PEVENT_RECORD event, size_t* packetSize) {
    REG_EVENT etwHeader = {0};
    etwHeader.action = event->EventHeader.EventDescriptor.Id;
    (*packetSize) = sizeof(REG_EVENT);
    BYTE* packet = (BYTE*)malloc(*packetSize);

    // get attached file paths
    if (event->UserDataLength > 0 && event->EventHeader.Flags != EVENT_HEADER_FLAG_STRING_ONLY) {
        PTRACE_EVENT_INFO info = NULL;
        ULONG infoSize = 0;
        TdhGetEventInformation(event, 0, NULL, info, &infoSize);
        info = (PTRACE_EVENT_INFO)malloc(infoSize);
        DWORD r = TdhGetEventInformation(event, 0, NULL, info, &infoSize);
        if (r != ERROR_SUCCESS) {
            printf("TdhGetEventInformation failed. r=%d, error: %d\n", r, GetLastError());
        } else {
            for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
                ParseRegEventParameter(event, i, info, &packet, packetSize, &etwHeader);
            }
            free(info);
        }
    }
    // the telemetry header is added to the packet at the end, because its values change while parsing parameters
    memcpy(packet, &etwHeader, sizeof(etwHeader));
    return packet;
}

BOOL ParseFileEventParameter(PEVENT_RECORD event, ULONG index, PTRACE_EVENT_INFO info, BYTE** packet, size_t* packetSize, FILE_EVENT* etwHeader) {
    EVENT_PROPERTY_INFO propInfo = info->EventPropertyInfoArray[index];

    PROPERTY_DATA_DESCRIPTOR propDesc;
    RtlZeroMemory(&propDesc, sizeof(propDesc));

    propDesc.PropertyName = (ULONGLONG)((PBYTE)info + propInfo.NameOffset);
    propDesc.ArrayIndex = ULONG_MAX;

    // First, get the size of the property
    ULONG propertySize = 0;
    DWORD status = TdhGetPropertySize(event, 0, NULL, 1, &propDesc, &propertySize);
    if (status != ERROR_SUCCESS) {
        printf("Failed to get size of property %lu\n", index);
        return FALSE;
    }

    // Allocate buffer for the data
    BYTE* buffer = (BYTE*)malloc(propertySize);
    if (!buffer) return FALSE;

    // Now actually get the property value
    status = TdhGetProperty(event, 0, NULL, 1, &propDesc, propertySize, buffer);
    if (status != ERROR_SUCCESS) {
        printf("Failed to get property %lu\n", index);
        free(buffer);
        return FALSE;
    }
        //? Note: InType refers to the actual type, as in how the bytes are arranged (string, pointer, etc.)
        //?     while the OutType refers to what the data represents/how its interpreted (GUID, time, string, etc.)

        //printf("propInfo.nonStructType: %ls\n\tInType: %d\n\tOutType: %d\n\tMapNameOffset: %d\n",
            //propDesc.PropertyName, propInfo.nonStructType.InType, propInfo.nonStructType.OutType, propInfo.nonStructType.MapNameOffset);        

    //* here comes the parameter parsing, how could this be made less ugly?
    if (wcscmp((WCHAR*)propDesc.PropertyName, L"FileName") == 0 || wcscmp((WCHAR*)propDesc.PropertyName, L"FilePath") == 0) {
        //wprintf(L"\tFileName: %ls\n", (WCHAR*)buffer);
        char* path = NormalizeEventPath((WCHAR*)buffer);
        if (path == NULL) {
            wprintf(L"[debug] failed to normalize path \"%ls\"!\n", (WCHAR*)buffer);
        } else {
            printf("\tFileName: %s\n", path);
            strncpy(etwHeader->path, path, sizeof(etwHeader->path));
            printf("[debug] after strncpy\n");

            PARAMETER filename = CreateEventParameterHead("FileName", PARAMETER_ANSISTRING, sizeof(path));
            printf("[debug] after creating parameter header\n");


            //* add the parameter to end of packet
            (*packetSize) += sizeof(filename) + strlen(path) +1;
            *packet = (BYTE*)realloc(*packet, (*packetSize));
            if (*packet == NULL) {
                printf("[debug] failed to realloc for size of %dB\n", (*packetSize));
                return FALSE;
            }
            size_t offset = sizeof(FILE_EVENT) + etwHeader->totalAttributesSize;
            memcpy((*packet) + offset, &filename, sizeof(filename));
            memcpy((*packet) + offset + sizeof(filename), path, strlen(path)+1);
            etwHeader->totalAttributesSize += sizeof(filename) + strlen(path) +1;
            etwHeader->attributeCount++;
            printf("[debug] after memcpy\n");
            free(path);
        }
    } else { //* debug print
        switch (propInfo.nonStructType.InType) {
            case TDH_INTYPE_UNICODESTRING: {
                wprintf(L"\t%ls: %ls\n", propDesc.PropertyName, (WCHAR*)buffer);
                char* name = ConvertWideToAnsi((WCHAR*)propDesc.PropertyName);
                char* ansiValue = ConvertUnicodeStringToAnsi((UNICODE_STRING*)buffer);
                if (ansiValue == NULL) {
                    free(name);
                    free(buffer);
                    return FALSE;
                }

                PARAMETER param = CreateEventParameterHead(name, PARAMETER_ANSISTRING, strlen(ansiValue));
                free(name);
//                printf("[debug] after creating parameter header\n");

                //* add the parameter to end of packet
                (*packetSize) += sizeof(param) + strlen(ansiValue) +1;
                *packet = (BYTE*)realloc(*packet, (*packetSize));
                if (!packet) {
                    printf("[debug] failed to realloc for size of %dB\n", (*packetSize));
                    return FALSE;
                }
                size_t offset = sizeof(FILE_EVENT) + etwHeader->totalAttributesSize;
                memcpy(*packet + offset, &param, sizeof(param));
                memcpy(*packet + offset + sizeof(param), ansiValue, strlen(ansiValue)+1);
                etwHeader->totalAttributesSize += sizeof(param) + strlen(ansiValue) +1;
                etwHeader->attributeCount++;
                break;
            }
            case TDH_INTYPE_POINTER: {
                wprintf(L"\t%ls: 0x%p\n", propDesc.PropertyName, *(PVOID*)buffer);
                char* name = ConvertWideToAnsi((WCHAR*)propDesc.PropertyName);
                PARAMETER param = CreateEventParameterHead(name, PARAMETER_POINTER, sizeof(PVOID));
                free(name);
//                printf("[debug] after creating parameter header\n");

                //* add the parameter to end of packet
                (*packetSize) += sizeof(param) + sizeof(PVOID);
                *packet = (BYTE*)realloc(*packet, (*packetSize));
                if (*packet == NULL) {
                    printf("[debug] failed to realloc for size of %dB\n", (*packetSize));
                    return FALSE;
                }
                size_t offset = sizeof(FILE_EVENT) + etwHeader->totalAttributesSize;
                memcpy(*packet + offset, &param, sizeof(param));
                memcpy(*packet + offset + sizeof(param), (PVOID*)buffer, sizeof(PVOID));
                etwHeader->totalAttributesSize += sizeof(param) + sizeof(PVOID);
                etwHeader->attributeCount++;
                break;
            }
            case TDH_INTYPE_UINT32:
                wprintf(L"\t%ls: %d\n", propDesc.PropertyName, *(UINT32*)buffer);
                break;
            case TDH_INTYPE_UINT16:
                wprintf(L"\t%ls: %d\n", propDesc.PropertyName, *(UINT16*)buffer);
                break;
            case TDH_INTYPE_BOOLEAN:
                wprintf(L"\t%ls: %s\n", propDesc.PropertyName, *(BOOL*)buffer ? "TRUE" : "FALSE");
                break;
            case TDH_INTYPE_ANSISTRING: {
                wprintf(L"\t%ls: %s\n", propDesc.PropertyName, (char*)buffer);
                char* name = ConvertWideToAnsi((WCHAR*)propDesc.PropertyName);
                PARAMETER param = CreateEventParameterHead(name, PARAMETER_ANSISTRING, strlen((char*)buffer)+1);
                free(name);
//                printf("[debug] after creating parameter header\n");

                //* add the parameter to end of packet
                (*packetSize) += sizeof(param) + strlen((char*)buffer) +1;
                *packet = (BYTE*)realloc(*packet, (*packetSize));
                if (*packet == NULL) {
                    printf("[debug] failed to realloc for size of %dB\n", (*packetSize));
                    return FALSE;
                }
                size_t offset = sizeof(FILE_EVENT) + etwHeader->totalAttributesSize;
                memcpy((*packet) + offset, &param, sizeof(param));
                memcpy((*packet) + offset + sizeof(param), (char*)buffer, strlen((char*)buffer)+1);
                etwHeader->totalAttributesSize += sizeof(param) + strlen((char*)buffer) +1;
                etwHeader->attributeCount++;
                break;
            }
        }
    }
    free(buffer);
    return TRUE;
}

BOOL ParseRegEventParameter(PEVENT_RECORD event, ULONG index, PTRACE_EVENT_INFO info, BYTE** packet, size_t* packetSize, REG_EVENT* etwHeader) {
    EVENT_PROPERTY_INFO propInfo = info->EventPropertyInfoArray[index];

    PROPERTY_DATA_DESCRIPTOR propDesc;
    RtlZeroMemory(&propDesc, sizeof(propDesc));

    propDesc.PropertyName = (ULONGLONG)((PBYTE)info + propInfo.NameOffset);
    propDesc.ArrayIndex = ULONG_MAX;

    // First, get the size of the property
    ULONG propertySize = 0;
    DWORD status = TdhGetPropertySize(event, 0, NULL, 1, &propDesc, &propertySize);
    if (status != ERROR_SUCCESS) {
        printf("Failed to get size of property %lu\n", index);
        return FALSE;
    }

    // Allocate buffer for the data
    BYTE* buffer = (BYTE*)malloc(propertySize);
    if (!buffer) return FALSE;

    // Now actually get the property value
    status = TdhGetProperty(event, 0, NULL, 1, &propDesc, propertySize, buffer);
    if (status != ERROR_SUCCESS) {
        printf("Failed to get property %lu\n", index);
        free(buffer);
        return FALSE;
    }
        //? Note: InType refers to the actual type, as in how the bytes are arranged (string, pointer, etc.)
        //?     while the OutType refers to what the data represents/how its interpreted (GUID, time, string, etc.)

        //printf("propInfo.nonStructType: %ls\n\tInType: %d\n\tOutType: %d\n\tMapNameOffset: %d\n",
            //propDesc.PropertyName, propInfo.nonStructType.InType, propInfo.nonStructType.OutType, propInfo.nonStructType.MapNameOffset);

    //* here comes the parameter parsing, how could this be made less ugly?
    if (wcscmp((WCHAR*)propDesc.PropertyName, L"RelativeName") == 0 || wcscmp((WCHAR*)propDesc.PropertyName, L"KeyName") == 0) {
        //wprintf(L"\tFileName: %ls\n", (WCHAR*)buffer);
        char* path = ConvertWideToAnsi((WCHAR*)buffer);
        if (path == NULL) {
            wprintf(L"[debug] failed to convert wide to ansi \"%ls\"!\n", (WCHAR*)buffer);
        } else {
            printf("[debug] RelativeName intype: %d\n", propInfo.nonStructType.InType);
            wprintf(L"\tRelativeName: %s\n", path);
            strncpy(etwHeader->path, path, sizeof(etwHeader->path));

            free(path);
        }
    } else if (wcscmp((WCHAR*)propDesc.PropertyName, L"KeyValue") == 0) {
        char* value = ConvertUnicodeStringToAnsi((UNICODE_STRING*)buffer);
        if (value == NULL) {
            printf("[debug] failed to convert KeyValue to ansi!\n");
            free(buffer);
            return FALSE;
        }
        printf("\tKeyValue: %s\n", value);
        //* create PARAMETER
        PARAMETER paramHead = CreateEventParameterHead("KeyValue", PARAMETER_ANSISTRING, strlen(value));

        //* add the parameter to end of packet
        (*packetSize) += sizeof(paramHead) + strlen(value)+1;
        *packet = (BYTE*)realloc(*packet, (*packetSize));
        if (*packet == NULL) {
            printf("[debug] failed to realloc for size of %dB\n", (*packetSize));
            return FALSE;
        }
        size_t offset = sizeof(REG_EVENT) + etwHeader->totalAttributesSize;
        memcpy((*packet) + offset, &paramHead, sizeof(paramHead));
        memcpy((*packet) + offset + sizeof(paramHead), value, sizeof(value));
        etwHeader->totalAttributesSize += sizeof(paramHead) + strlen(value)+1;
        etwHeader->attributeCount++;
        free(value);
    
    } else { //* debug print
        printf("[debug] intype: %d\n", propInfo.nonStructType.InType);
        switch (propInfo.nonStructType.InType) {
            case TDH_INTYPE_UNICODESTRING: {
                wprintf(L"\t%ls: %ls\n", propDesc.PropertyName, (WCHAR*)buffer);
                char* name = ConvertWideToAnsi((WCHAR*)propDesc.PropertyName);
                if (name == NULL) return FALSE;
                /*wprintf(L"[debug] test unicode_string raw content (%d):\n", propInfo.length);
                for (size_t i = 0; i < 32; i++) {
                    if (i%16 == 0) {
                        printf("\n\t");
                    }
                    printf("%02X ", buffer[i]);
                }*/
                /*char* ansiValue = ConvertUnicodeStringToAnsi((UNICODE_STRING*)buffer);
                if (ansiValue == NULL) {
                    printf("[debug] failed to convert to unicode string");
                    free(name);
                    free(buffer);
                    return FALSE;
                }
                printf("[debug] after converting unicode string to ansi (%s)\n", ansiValue);
                */
                char* ansiValue = ConvertWideToAnsi((WCHAR*)buffer);
                if (ansiValue == NULL) return FALSE;
                PARAMETER param = CreateEventParameterHead(name, PARAMETER_ANSISTRING, strlen(ansiValue));
                free(name);
//                printf("[debug] after creating parameter header\n");

                //* add the parameter to end of packet
                (*packetSize) += sizeof(param) + strlen(ansiValue) +1;
                *packet = (BYTE*)realloc(*packet, (*packetSize));
                if (*packet == NULL) {
                    printf("[debug] failed to realloc for size of %dB\n", (*packetSize));
                    return FALSE;
                }
                size_t offset = sizeof(REG_EVENT) + etwHeader->totalAttributesSize;
                memcpy((*packet) + offset, &param, sizeof(param));
                memcpy((*packet) + offset + sizeof(param), ansiValue, strlen(ansiValue)+1);
                etwHeader->totalAttributesSize += sizeof(param) + strlen(ansiValue) +1;
                etwHeader->attributeCount++;
                free(ansiValue);
                printf("[debug] end of unicode_string case (reg)\n");
                break;
            }
            case TDH_INTYPE_POINTER: {
                wprintf(L"\t%ls: 0x%p\n", propDesc.PropertyName, *(PVOID*)buffer);
                char* name = ConvertWideToAnsi((WCHAR*)propDesc.PropertyName);
                printf("[debug] 1");
                PARAMETER param = CreateEventParameterHead(name, PARAMETER_POINTER, sizeof(PVOID));
                printf("2");
                free(name);
//                printf("[debug] after creating parameter header\n");


                //* add the parameter to end of packet
                (*packetSize) += sizeof(param) + sizeof(PVOID);
                printf("[debug] before realloc (packetSize: %d)\n", *packetSize);
                *packet = (BYTE*)realloc(*packet, (*packetSize));
                printf("[debug] after realloc (%p)", *packet);
                if (*packet == NULL) {
                    printf("[debug] failed to realloc for size of %dB\n", (*packetSize));
                    return FALSE;
                }
                printf("4\n");
                size_t offset = sizeof(REG_EVENT) + etwHeader->totalAttributesSize;
                memcpy((*packet) + offset, &param, sizeof(param));
                memcpy((*packet) + offset + sizeof(param), (PVOID*)buffer, sizeof(PVOID));
                etwHeader->totalAttributesSize += sizeof(param) + sizeof(PVOID);
                etwHeader->attributeCount++;
                printf("[debug] end of pointer case (reg)\n");
                break;
            }
            case TDH_INTYPE_UINT32:
                wprintf(L"\t%ls: %d\n", propDesc.PropertyName, *(UINT32*)buffer);
                break;
            case TDH_INTYPE_UINT16:
                wprintf(L"\t%ls: %d\n", propDesc.PropertyName, *(UINT16*)buffer);
                break;
            case TDH_INTYPE_BOOLEAN:
                wprintf(L"\t%ls: %s\n", propDesc.PropertyName, *(BOOL*)buffer ? "TRUE" : "FALSE");
                break;
            case TDH_INTYPE_ANSISTRING: {
                wprintf(L"\t%ls: %s\n", propDesc.PropertyName, (char*)buffer);
                char* name = ConvertWideToAnsi((WCHAR*)propDesc.PropertyName);
                PARAMETER param = CreateEventParameterHead(name, PARAMETER_ANSISTRING, strlen((char*)buffer)+1);
                free(name);
//                printf("[debug] after creating parameter header\n");

                printf("strlen((char*)buffer)+1: %d\npropInfo.length: %d\n", strlen((char*)buffer)-1, propInfo.length);

                //* add the parameter to end of packet
                (*packetSize) += sizeof(param) + strlen((char*)buffer) +1;
                *packet = (BYTE*)realloc(*packet, (*packetSize));
                if (*packet == NULL) {
                    printf("[debug] failed to realloc for size of %dB\n", (*packetSize));
                    return FALSE;
                }
                size_t offset = sizeof(REG_EVENT) + etwHeader->totalAttributesSize;
                memcpy(*packet + offset, &param, sizeof(param));
                memcpy(*packet + offset + sizeof(param), (char*)buffer, strlen((char*)buffer)+1);
                etwHeader->totalAttributesSize += sizeof(param) + strlen((char*)buffer) +1;
                etwHeader->attributeCount++;
                break;
            }
        }
    }
    free(buffer);
    return TRUE;
}

// This is like a header preceding every parameter, directly after this comes the value
PARAMETER CreateEventParameterHead(LPCSTR name, DWORD type, size_t size) {
    PARAMETER param = {0};
    strncpy(param.name, name, sizeof(param.name)-1);
    param.name[sizeof(param.name) -1] = '\0';
    param.type = type;
    param.size = size;
    printf("[debug] parameter %s size: %d\n", param.name, param.size);
    return param;
}

size_t GetTelemetryPacketSize(DWORD type, size_t dynamicSize) {
    switch (type) {
        case TM_TYPE_ETW_FILE:
            return sizeof(TELEMETRY_HEADER) + sizeof(FILE_EVENT) + dynamicSize; 
        case TM_TYPE_ETW_REG:
            return sizeof(TELEMETRY_HEADER) + sizeof(REG_EVENT) + dynamicSize; 
    }
    return 0;
}

// dataSize is the size of all data coming after the telemetry header
TELEMETRY_HEADER GetTelemetryHeader(DWORD type, DWORD pid, size_t dataSize, time_t timeStamp) {
    TELEMETRY_HEADER header;
    header.pid = pid;
    header.type = type;
    header.dataSize = dataSize;
    header.timeStamp = timeStamp;
    return header;
}

int SendEtwTelemetryPacket(PEVENT_RECORD event, BYTE* dataPacket, size_t dataSize, DWORD type) {
    TELEMETRY_HEADER header = GetTelemetryHeader(type, event->EventHeader.ProcessId, dataSize, event->EventHeader.TimeStamp.QuadPart);
    BYTE* packet = (BYTE*)malloc(sizeof(header) + dataSize);
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), dataPacket, dataSize);

    DWORD bytesWritten;
    BOOL writeOk = WriteFile(hPipe, packet, sizeof(header) + dataSize, &bytesWritten, NULL);

    free(dataPacket);
    free(packet);
    
    if (writeOk) {
        return 0;
    }
    return GetLastError();
}