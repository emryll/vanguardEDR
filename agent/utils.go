package main

//#include "memscan.h"
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

func RemoveSliceMember[T any](slice []T, index int) []T {
	return append(slice[:index], slice[index+1:]...)
}

// TODO: test
func TerminateProcess(pid int) error {
	hProcess, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hProcess)

	err = windows.TerminateProcess(hProcess, 1)
	if err != nil {
		return err
	}
	return nil
}

func IsSignatureValid(path string) (int, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("Get-AuthenticodeSignature -FilePath '%s' | Select-Object -ExpandProperty Status", path),
	)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return -1, fmt.Errorf("powershell error: %v, stderr: %s", err, stderr.String())
	}

	status := strings.TrimSpace(out.String())
	// Possible status values include: Valid, UnknownError, NotSigned, etc.
	if status == "Valid" {
		return 1, nil
	} else if status == "HashMismatch" {
		return 2, nil
	}
	return 0, nil
}

func GetProcessExecutable(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	// QueryFullProcessImageName with flag 0 for Win32 path format
	err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// remove all items in history which are < threshold
func Cleanup[H History](history []H, threshold int64) []H {
	// sort history in ascending order
	sort.Slice(history, func(i, j int) bool {
		return history[i].GetTime() < history[j].GetTime()
	})
	// find last item below or equal to timestamp threshold
	index := binarySearchExpired(history, threshold)
	return history[index:]
}

// find first index where timestamp > threshold
func binarySearchExpired[H History](history []H, threshold int64) int {
	left, right := 0, len(history)-1
	for left <= right {
		mid := left + (right-left)/2
		if history[mid].GetTime() >= threshold {
			right = mid + 1
		} else {
			left = mid - 1
		}
	}
	return right + 1
}

// ? In C, an union's memory footprint will be the size of the largest member, also, compilers
// ? will usually add padding to reach address divisible by 8(?). For example 4B after DWORD(32bits)
// Translate the telemetry C struct with unions to a golang struct, which std go methods fail to do
func ParseApiTelemetryPacket(rawData []byte) ApiCallData {
	var apiCall ApiCallData
	apiCall.ThreadId = binary.LittleEndian.Uint32(rawData[0:4])
	apiCall.DllName = ReadAnsiStringValue(rawData[4 : 4+60])
	apiCall.FuncName = ReadAnsiStringValue(rawData[64 : 64+60])
	apiCall.ArgCount = binary.LittleEndian.Uint32(rawData[64+60 : 64+60+4])
	argCount := 0
	if apiCall.ArgCount > 0 && apiCall.ArgCount <= MAX_API_ARGS {
		argCount = int(apiCall.ArgCount)
	} else {
		argCount = MAX_API_ARGS
	}

	// manual analysis of telemetry packet showed a 4 byte padding before first arg (align with 8)
	counter := 64 + 60 + 4
ArgLoop:
	for i := 0; i < argCount; i++ {
		// get the arg type which is first part of arg struct
		apiCall.Args = append(apiCall.Args, ApiArg{Type: int(binary.LittleEndian.Uint32(rawData[counter : counter+8]))})
		counter += 8 // 4 byte padding after 4 byte enum (API_ARGTYPE)
		fmt.Printf("arg type: %d\n", apiCall.Args[i].Type)
		switch apiCall.Args[i].Type {
		//? using copy because of [520]byte vs []byte type mismatch
		case API_ARG_TYPE_EMPTY:
			break ArgLoop
		case API_ARG_TYPE_DWORD:
			copy(apiCall.Args[i].RawData[:], rawData[counter:counter+4])
		case API_ARG_TYPE_ASTRING:
			copy(apiCall.Args[i].RawData[:], rawData[counter:counter+260])
		case API_ARG_TYPE_WSTRING:
			copy(apiCall.Args[i].RawData[:], rawData[counter:counter+520])
		case API_ARG_TYPE_BOOL:
			copy(apiCall.Args[i].RawData[:], rawData[counter:counter+4]) // BOOL is uint32
		case API_ARG_TYPE_PTR:
			copy(apiCall.Args[i].RawData[:], rawData[counter:counter+8])
		}
		counter += 520 // largest union member is wchar_t[260] which is 520 bytes
	}
	return apiCall
}

// interpret raw c ansi string as a go string
func ReadAnsiStringValue(data []byte) string {
	n := 0
	for ; n < len(data); n++ {
		if data[n] == 0 {
			break // null terminator
		}
	}
	return string(data[:n])
}

// interpret raw c wide string as a go string
func ReadWideStringValue(data []byte) string {
	u16s := make([]uint16, 0, len(data)/2)

	for i := 0; i < len(data); i += 2 {
		u16 := uint16(data[i]) | uint16(data[i+1])<<8
		if u16 == 0 {
			break // Null-terminator
		}
		u16s = append(u16s, u16)
	}

	return string(utf16.Decode(u16s))
}

// read raw DWORD (32-bit unsigned integer) as go uint32
func ReadDWORDValue(rawData []byte) uint32 {
	return binary.LittleEndian.Uint32(rawData)
}

// read raw 64-bit pointer memory address as integer value
func ReadPointerValue(rawData []byte) uint64 {
	return binary.LittleEndian.Uint64(rawData)
}

// read raw c BOOL (32-bit unsigned integer) as go boolean
func ReadBoolValue(rawData []byte) bool {
	return binary.LittleEndian.Uint32(rawData) == 1
}

// TODO: test this
func ParseFileTelemetryPacket(data []byte) FileEventData {
	var fileEvent FileEventData
	fileEvent.Path = ReadAnsiStringValue(data[0:260])
	fileEvent.Action = ReadDWORDValue(data[260:264])
	return fileEvent
}

// TODO: test this
func ParseRegTelemetryPacket(data []byte) RegEventData {
	var regEvent RegEventData
	regEvent.Path = ReadAnsiStringValue(data[0:260])
	regEvent.Value = ReadAnsiStringValue(data[260 : 260+260])
	return regEvent
}

// TODO: test this
func ParseTextTelemetryPacket(data []byte) TextCheckData {
	var textCheck TextCheckData
	textCheck.Result = ReadBoolValue(data[0:4])
	textCheck.Module = ReadAnsiStringValue(data[4 : 4+260])
	return textCheck
}

func ReadRemoteProcessMem(hProcess windows.Handle, address uintptr, size int) ([]byte, error) {
	buf := make([]byte, size)
	var bytesRead uintptr
	err := windows.ReadProcessMemory(hProcess, address, &buf[0], uintptr(size), &bytesRead)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func ConvertRemoteModules(cMods *C.REMOTE_MODULE, count C.size_t) ([]RemoteModule, error) {
	if cMods == nil || count == 0 {
		return nil, fmt.Errorf("empty input")
	}

	sizeMod := unsafe.Sizeof(C.REMOTE_MODULE{})
	sizeRegion := unsafe.Sizeof(C.MEMORY_REGION{})

	modules := make([]RemoteModule, int(count))

	for i := 0; i < int(count); i++ {
		// pointer to i-th REMOTE_MODULE
		cModPtr := (*C.REMOTE_MODULE)(unsafe.Pointer(uintptr(unsafe.Pointer(cMods)) + uintptr(i)*sizeMod))

		// Convert name to Go string, trimming trailing zeros
		nameBytes := C.GoBytes(unsafe.Pointer(&cModPtr.name[0]), C.int(MAX_PATH))
		nameStr := string(nameBytes)
		if idx := strings.IndexByte(nameStr, 0); idx >= 0 {
			nameStr = nameStr[:idx]
		}

		// Copy number of sections
		numSections := uint64(cModPtr.numSections)

		// Convert sections array to Go slice
		var sections []MemRegion
		if cModPtr.sections != nil && numSections > 0 {
			sections = make([]MemRegion, numSections)
			for j := 0; j < int(numSections); j++ {
				cSectionPtr := (*C.MEMORY_REGION)(unsafe.Pointer(uintptr(unsafe.Pointer(cModPtr.sections)) + uintptr(j)*sizeRegion))
				sections[j] = MemRegion{
					Address: unsafe.Pointer(cSectionPtr.address),
					Size:    uint64(cSectionPtr.size),
				}
			}
		}

		modules[i] = RemoteModule{
			Name:        [MAX_PATH]byte{}, // keep blank, we have string below
			NumSections: numSections,
			Sections:    sections,
		}

		// If you want to store the name string as well, you can add a NameStr field:
		// modules[i].NameStr = nameStr
		// Or if you want, copy string bytes into Name byte array:
		copy(modules[i].Name[:], []byte(nameStr))
	}

	return modules, nil
}

// this method will make new the main one and push current one to api.History
func (api *ApiCallData) PushNewEntry(new ApiCallData) {
	//* clear the history to avoid recursive duplication of history
	old := *api
	old.History = nil
	//* append to history copy of current one
	api.History = append(api.History, old)
	//* change timestamp and tid of current one to values of new one
	api.TimeStamp = new.TimeStamp
	api.ThreadId = new.ThreadId
}

// this method will add api to process' api call history, or update the entry if it exists
func (p *Process) PushToApiCallHistory(api ApiCallData) {
	call, exists := p.APICalls[api.FuncName]
	if exists {
		// call is a copy of the value
		call.PushNewEntry(api)
		p.APICalls[api.FuncName] = call
	} else {
		p.APICalls[api.FuncName] = api
	}
}

// ! this is kind of useless because you still need to type assert so you need A SECOND SWITCH
// ?^ you could maybe do it with a generic T method but I kept getting syntax error trying it
// generic function to interpret c arg from raw bytes.
func (arg ApiArg) Read() any {
	switch arg.Type {
	case API_ARG_TYPE_DWORD:
		return ReadDWORDValue(arg.RawData[:])
	case API_ARG_TYPE_ASTRING:
		return ReadAnsiStringValue(arg.RawData[:])
	case API_ARG_TYPE_WSTRING:
		return ReadWideStringValue(arg.RawData[:])
	case API_ARG_TYPE_BOOL:
		return ReadBoolValue(arg.RawData[:])
	case API_ARG_TYPE_PTR:
		return ReadPointerValue(arg.RawData[:])
	}
	return nil
}
