package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrust               = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust     = wintrust.NewProc("WinVerifyTrust")
	WTD_CHOICE_FILE        = uint32(1)
	WTD_UI_NONE            = uint32(2)
	WTD_REVOKE_NONE        = uint32(0)
	WTD_STATEACTION_VERIFY = uint32(1)
	WTD_STATEACTION_CLOSE  = uint32(2)
	WTD_SAFER_FLAG         = uint32(0x00000100)
)

type WINTRUST_FILE_INFO struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          windows.Handle
	pgKnownSubject *windows.GUID
}

type WINTRUST_DATA struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               uintptr
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

func IsSigned(path string) error {
	filePathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}
	// GUID for WINTRUST_ACTION_GENERIC_VERIFY_V2
	var WINTRUST_ACTION_GENERIC_VERIFY_V2 = windows.GUID{
		Data1: 0xaac56b,
		Data2: 0xcd44,
		Data3: 0x11d0,
		Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
	}
	fileInfo := WINTRUST_FILE_INFO{
		cbStruct:      uint32(unsafe.Sizeof(WINTRUST_FILE_INFO{})),
		pcwszFilePath: filePathPtr,
		hFile:         0,
	}

	data := WINTRUST_DATA{
		cbStruct:            uint32(unsafe.Sizeof(WINTRUST_DATA{})),
		dwUIChoice:          WTD_UI_NONE,
		fdwRevocationChecks: WTD_REVOKE_NONE,
		dwUnionChoice:       WTD_CHOICE_FILE,
		pFile:               uintptr(unsafe.Pointer(&fileInfo)),
		dwStateAction:       WTD_STATEACTION_VERIFY,
		dwProvFlags:         WTD_SAFER_FLAG,
	}

	// Call WinVerifyTrust
	ret, _, _ := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&WINTRUST_ACTION_GENERIC_VERIFY_V2)),
		uintptr(unsafe.Pointer(&data)),
	)

	// Close state handle
	data.dwStateAction = WTD_STATEACTION_CLOSE
	procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&WINTRUST_ACTION_GENERIC_VERIFY_V2)),
		uintptr(unsafe.Pointer(&data)),
	)

	if ret == 0 {
		return nil
	} else {
		return fmt.Errorf("WinVerifyTrust failed: 0x%x", ret)
	}
}

func main() {
	path := "C:\\Windows\\System32\\notepad.exe"
	err := IsSigned(path)
	if err != nil {
		fmt.Println("failed")
	} else {
		fmt.Println("succeeded")
	}
}
