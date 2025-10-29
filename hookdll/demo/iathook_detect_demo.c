#include <windows.h>
#include <winternl.h>
#include <stdio.h>

int HookIatEntryByName(LPVOID moduleBase, LPCSTR funcName, LPCSTR dllName, FARPROC handler) {
  //* Parse PE header to find Import Address Table and change function address to point to handler
  PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)moduleBase;
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + dosHeaders->e_lfanew);
  if (ntHeaders->Signature != PE_SIGNATURE) {
      return -1;
  }

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)moduleBase);
	LPCSTR libraryName = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL; 
    
  while (importDescriptor->Name != 0) {
    libName = (LPCSTR)((DWORD_PTR)importDescriptor->Name + (DWORD_PTR)moduleBase);
    if (strcmp(libName, dllName) != 0) {
      break;
    }

    PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
    originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->OriginalFirstThunk);
    firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->FirstThunk);
        
    while (originalFirstThunk->u1.AddressOfData != 0) {
      //? do you need to check if originalFirstThunk or firstThunk is NULL?
      functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)moduleBase + originalFirstThunk->u1.AddressOfData);

      // skip null function entry
      if (firstThunk->u1.Function == 0) {
        originalFirstThunk++;
        firstThunk++;
        continue;
      }

      // replace address if its the one we want to hook
      if (strcmp(functionName->Name, funcToHook) == 0) {
        DWORD oldProtect;
        VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
        firstThunk->u1.Function = (DWORD_PTR)handler;
        return 0;
      }
      originalFirstThunk++;
      firstThunk++;
    }
    importDescriptor++;

  }
  return 1;
}

int MBW_Handler(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
  return MessageBoxA(hWnd, "Hooked!", "Hooked!", uType);
}

int main() {
  Sleep(1000);
  getchar();
  // apply iat hook to unhooked function
  HMODULE mainModuleBase = GetModuleHandle(NULL);
  int result = HookIatEntryByName(mainModuleBase, "MessageBoxW", "user32.dll");
  if (result != 0) {
    printf("Failed to hook MessageBoxW (return value: %d)\n", result);
    return result;
  }
  printf("Hooked MessageBoxW\n");
  MessageBoxW(NULL, L"test", L"test", MB_OK);
  // remove already hooked iat func
  HMODULE user32Base = GetModuleHandle("user32.dll");
  LPVOID MBA_address = GetProcAddress(user32Base, "MessageBoxA");
  result = HookIatEntryByName(mainModuleBase, "MessageBoxA", "user32.dll");
  if (result != 0) {
    printf("Failed to unhook MessageBoxA (return value: %d)\n", result);
    return result;
  }

  MessageBoxA(NULL, "test", "test", MB_OK);
  getchar();
  return 0;
}
