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
	"time"
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

// TODO: test
// remove all items in history which are older than timestamp threshold
func Cleanup[T any, H History[T]](history []H, threshold int64) []H {
	// sort history in ascending order
	sort.Slice(history, func(i, j int) bool {
		return history[i].GetTime() < history[j].GetTime()
	})
	// find last item below or equal to timestamp threshold
	index := binarySearchBelow(history, threshold)
	return history[index:]
}

// find last item <= threshold
func binarySearchBelow[T any, H History[T]](history []H, threshold int64) int {
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

// This method will log telemetry packet to file on disk (logFile), add it to process history,
// and print it out if printLog is enabled. It will also launch further action if needed
func (header TelemetryHeader) Log(dataBuf []byte) {
	t := time.Unix(header.TimeStamp, 0)
	formatted := t.Format("15:04:05")

	switch header.Type {
	case TM_TYPE_EMPTY_VALUE:
		return
	case TM_TYPE_API_CALL:
		head := fmt.Sprintf("\n\n[%s] PID: %d, new API call\n", formatted, header.Pid)
		logFile.WriteString(head)
		if printLog {
			fmt.Printf(head)
		}

		//* Parse packet and add to process' API call history
		apiCall := ParseApiTelemetryPacket(dataBuf)
		apiCall.TimeStamp = header.TimeStamp
		mu.Lock()
		processes[int(header.Pid)].PushToApiCallHistory(apiCall)
		mu.Unlock()

		api := fmt.Sprintf("\t[TID: %d] %s!%s:\n", apiCall.ThreadId, apiCall.DllName, apiCall.FuncName)
		logFile.WriteString(api)
		if printLog {
			fmt.Printf(api)
		}
		//* Log the args
		for i, arg := range apiCall.Args {
			var line string
			switch arg.Type {
			case API_ARG_TYPE_EMPTY:
				continue
			case API_ARG_TYPE_DWORD:
				line = fmt.Sprintf("\tArg #%d (DWORD): %d\n", i, arg.Read())
			case API_ARG_TYPE_ASTRING:
				line = fmt.Sprintf("\tArg #%d (ASTRING): %s\n", i, arg.Read())
			case API_ARG_TYPE_WSTRING:
				line = fmt.Sprintf("\tArg #%d (WSTRING): %s\n", i, arg.Read())
			case API_ARG_TYPE_PTR:
				line = fmt.Sprintf("\tArg #%d (LPVOID): 0x%X\n", i, arg.Read())
			case API_ARG_TYPE_BOOL:
				bval := arg.Read().(bool) //? ^probably need to do this cast with all of them
				if bval {
					line = fmt.Sprintf("\tArg #%d (BOOL): TRUE\n", i)
				} else {
					line = fmt.Sprintf("\tArg #%d (BOOL): FALSE\n", i)
				}
			}
			logFile.WriteString(line)
			if printLog {
				fmt.Printf(line)
			}
		}
	case TM_TYPE_TEXT_INTEGRITY: //TODO: maybe only log hash mismatches
		var line string
		head := fmt.Sprintf("\n\n[%s] PID: %d, new .text integrity check\n", formatted, header.Pid)
		logFile.WriteString(head)

		//* Parse and log result of check
		textCheck := ParseTextTelemetryPacket(dataBuf)
		if textCheck.Result { // true means the integrity remains, its fine
			line = fmt.Sprintf("\tModule \"%s\" integrity: TRUE\n", textCheck.Module)
		} else { // hash mismatch
			line = fmt.Sprintf("\tModule \"%s\" integrity: FALSE\n", textCheck.Module)
			go func() { // goroutine so memscan does not block execution
				results, err := MemoryScanEx(header.Pid, scanner)
				if err != nil {
					errMsg := fmt.Sprintf("\n[!] Failed to launch MemoryScanEx on process %d: %v\n", header.Pid, err)
					logFile.WriteString(errMsg)
					if printLog {
						color.Red(errMsg)
					} else if results.TotalScore > 0 {
						go results.Log("MemoryScanEx", header.Pid) // goroutine to not block execution, self-explanatory func
					}
				}
			}()
		}
		logFile.WriteString(line)
		if printLog {
			fmt.Printf(line)
		}

		//TODO: case TM_TYPE_FILE_EVENT:
		//TODO: case TM_TYPE_REG_EVENT:
	}
	//* Add a line after the log
	logFile.WriteString("\n")
	if printLog {
		fmt.Printf("\n")
	}
}

// Process and log results. Launch further actions or alerts if needed
func (r Results) Log(scanName string, pid int) {
	head := fmt.Sprintf("\n\nGot %d total score from %s (%d matches)\n", r.TotalScore, scanName, len(r.Matches))
	logFile.WriteString(head)
	if printLog {
		fmt.Printf(head)
	}

	mu.Lock()
	processes[pid].YaraScore += r.TotalScore
	processes[pid].TotalScore += r.TotalScore
	mu.Unlock()
	//TODO: check if score exceeds thresholds, make a function for this

	//TODO: if m.Severity is severe, trigger an alert
	for _, m := range r.Matches {
		t := time.Unix(m.TimeStamp, 0)
		formatted := t.Format("15:04:05")

		var name string
		if m.Name == "" {
			name = m.Description
		} else {
			name = m.Name
		}
		match := fmt.Sprintf("[%s] %s (+%d)\n", formatted, name, m.Score)
		logFile.WriteString(match)
		if m.Description != "" {
			desc := fmt.Sprintf("\t[?] %s\n", m.Description)
			logFile.WriteString(desc)
		}
		if len(m.Category) > 0 {
			categories := "\tCategory: "
			for i, c := range m.Category {
				categories += c
				if len(m.Category) > i+1 {
					categories += ", "
				}
			}
			categories += "\n"
			logFile.WriteString(categories)
		}
		//* update process' history
		mu.Lock()
		_, exists := processes[pid].PatternMatches[name]
		if exists {
			processes[pid].PatternMatches[name].Count++
		} else {
			processes[pid].PatternMatches[name] = m
		}
		mu.Unlock()
	}
	logFile.WriteString("\n\n")
}
