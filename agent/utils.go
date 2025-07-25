package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/fatih/color"
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

// remove all items in history which are older than timestamp threshold
func Cleanup[T History](history []T, threshold int64) []T {
	// sort history in ascending order
	sort.Slice(history, func(i, j int) bool {
		return history[i].GetTime() < history[j].GetTime()
	})
	// find last item below or equal to timestamp threshold
	index := binarySearchBelow(history, threshold)
	return history[index:]
}

// find last item <= threshold
func binarySearchBelow[T History](history []T, threshold int64) int {
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

// moves most recent to history and replaces most recent with specified item
func PushMostRecent[T History](current *T, new T) {
	old := *current
	old.HistoryPtr() = nil

	new.HistoryPtr() = append(*current.HistoryPtr(), old)
}

// translate the telemetry c struct with unions to golang struct, which std go methods fail to do
func ParseApiTelemetryPacket(rawData []byte) ApiCallData {
	var apiCall ApiCallData
	apiCall.ThreadId = binary.LittleEndian.Uint32(rawData[0:4])
	apiCall.DllName = ReadAnsiStringValue(rawData[4 : 64+4])
	apiCall.FuncId = binary.LittleEndian.Uint32(rawData[68 : 68+4])

	counter := 72
	for i := 0; i < MAX_API_ARGS; i++ {
		apiCall.Args = append(apiCall.Args, ApiArg{Type: binary.LittleEndian.Uint32(rawData[counter : counter+4])})
		counter += 8 // 4 byte padding after 4 byte enum
		switch apiCall.Args[i].Type {
		case API_ARG_TYPE_DWORD:
			apiCall.Args[i].RawData = rawData[counter : counter+4]
		case API_ARG_TYPE_ASTRING:
			apiCall.Args[i].RawData = rawData[counter : counter+260]
		case API_ARG_TYPE_WSTRING:
			apiCall.Args[i].RawData = rawData[counter : counter+520]
		case API_ARG_TYPE_BOOL:
			apiCall.Args[i].RawData = rawData[counter : counter+4] // BOOL is uint32
		case API_ARG_TYPE_PTR:
			apiCall.Args[i].RawData = rawData[counter : counter+8]
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
func ParseFileTelemetryPacket(data []byte) FILE_EVENT {
	var fileEvent FILE_EVENT
	fileEvent.Path = ReadAnsiStringValue(data[0:260])
	fileEvent.Action = ReadDWORDValue(data[260:264])
	return fileEvent
}

// TODO: test this
func ParseRegTelemetryPacket(data []byte) REG_EVENT {
	var regEvent REG_EVENT
	regEvent.Path = ReadAnsiStringValue(data[0:260])
	regEvent.Value = ReadAnsiStringValue(data[260 : 260+260])
	return regEvent
}

// TODO: test this
func ParseTextTelemetryPacket(data []byte) TEXT_CHECK {
	var textCheck TEXT_CHECK
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

func (r StdResult) Print() {
	switch r.Severity {
	case 0:
		green := color.New(color.FgGreen, color.Bold)
		green.Printf("[*] ")
		if r.Name == "" {
			fmt.Printf("%s ", r.Description) //text in white so its easier to read
			green.Printf("(+%d)\n", r.Score)
		} else {
			fmt.Printf("%s ", r.Name) //text in white so its easier to read
			green.Printf("(+%d)\n", r.Score)
			if r.Description != "" {
				green.Printf("\t[?] ")
				fmt.Printf("%s\n", r.Description)
			}
		}
	case 1:
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Printf("[*] ")
		if r.Name == "" {
			fmt.Printf("%s ", r.Description)
			yellow.Printf("(+%d)\n", r.Score)
		} else {
			fmt.Printf("%s ", r.Name)
			yellow.Printf("(+%d)\n", r.Score)
			if r.Description != "" {
				yellow.Printf("\t[?] ")
				fmt.Printf("%s\n", r.Description)
			}
		}
	case 2:
		red := color.New(color.FgRed)
		red.Printf("[*] ")
		if r.Name == "" {
			fmt.Printf("%s ", r.Description)
			red.Add(color.Bold)
			red.Printf("(+%d)\n", r.Score)
		} else {
			fmt.Printf("%s ", r.Name)
			red.Add(color.Bold)
			red.Printf("(+%d)\n", r.Score)
			if r.Description != "" {
				fmt.Printf("\t[?] %s\n", r.Description)
			}
		}
	default:
		color.Red("[!] Invalid severity value in YARA rule (%d), must be 0(low), 1(medium) or 2(high)", r.Severity)
		fmt.Printf("[*] ")
		if r.Name == "" {
			fmt.Printf("%s (+%d)\n", r.Description, r.Score)
		} else {
			fmt.Printf("%s (+%d)\n", r.Name, r.Score)
			if r.Description != "" {
				fmt.Printf("\t[?] %s\n", r.Description)
			}
		}
	}
	if len(r.Category) > 0 {
		fmt.Printf("\tCategory: ")
		for i, t := range r.Category {
			fmt.Printf("%s", t)
			if len(r.Category) > i+1 {
				fmt.Printf(", ")
			}
		}
		fmt.Printf("\n")
	}
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
