package main

//#include <windows.h>
//#include "memscan.h"
import "C"

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(hProcess)

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	// flag 0 for Win32 path format
	err = windows.QueryFullProcessImageName(hProcess, 0, &buf[0], &size)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// remove all items in history which are < threshold
func Cleanup[H History[T], T any](history []H, threshold int64) []H {
	// sort history in ascending order
	sort.Slice(history, func(i, j int) bool {
		return history[i].GetTime() < history[j].GetTime()
	})
	// find last item below or equal to timestamp threshold
	index := binarySearchExpired(history, threshold)
	return history[index:]
}

// find first index where timestamp > threshold
func binarySearchExpired[H History[T], T any](history []H, threshold int64) int {
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
func ParseApiTelemetryPacket(rawData []byte, timestamp int64) ApiCallData {
	var apiCall ApiCallData
	apiCall.TimeStamp = timestamp
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

func ParseTextTelemetryPacket(data []byte) TextCheckData {
	var textCheck TextCheckData
	textCheck.Result = ReadBoolValue(data[0:4])
	textCheck.Module = ReadAnsiStringValue(data[4 : 4+260])
	return textCheck
}

func ParseIatTelemetryPacket(data []byte) []IatIntegrityData {
	var iatMismatches []IatIntegrityData
	packetSize := 64 + 8 // char[64] + LPVOID
	for counter := 0; counter <= (len(data) - packetSize); counter += packetSize {
		fn := ReadAnsiStringValue(data[counter : counter+64])
		addr := ReadPointerValue(data[counter+64 : counter+64+8])
		iatMismatches = append(iatMismatches, IatIntegrityData{FuncName: fn, Address: addr})
	}
	return iatMismatches
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

func SortMagic() {
	// sort by descending length
	sort.Slice(magicToType, func(i, j int) bool {
		return len(magicToType[i].Bytes) > len(magicToType[j].Bytes)
	})
}

func GetMagic(path string, maxLen int) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "Unknown", err
	}
	defer file.Close()

	buf := make([]byte, maxLen)
	_, err = file.Read(buf)
	if err != nil {
		return "Unknown", err
	}

	// check if magic is found in list
	for _, magic := range magicToType {
		if len(buf) >= len(magic.Bytes) && bytes.Equal(buf[:len(magic.Bytes)], magic.Bytes) {
			return magic.Type, nil
		}
	}
	return "Unknown", nil
}

func GetMimeType(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil {
		return "", err
	}

	mimeType := http.DetectContentType(buffer[:n])
	return mimeType, nil
}

func ComputeFileSha256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	return fmt.Sprintf("%x", hash), nil
}

func GetEntropy(data []byte) float64 {
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	totalBytes := len(data)
	probs := make(map[byte]float64)
	for b, f := range freq {
		probs[b] = float64(f) / float64(totalBytes)
	}

	entropy := 0.0
	for _, p := range probs {
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func GetEntropyOfFile(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0.0, err
	}
	return GetEntropy(data), nil
}

func runPowerShell(command string) (string, error) {
	cmd := exec.Command("powershell", "-Command", command)
	// Run the command and capture combined output (stdout + stderr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error running PowerShell command: %v, output: %s", err, string(output))
	}
	return string(output), nil
}

func getAlternateDataStreams(filePath string) ([]string, error) {
	cmd := fmt.Sprintf("Get-Item -Path \"%s\" -Stream *", filePath)
	output, err := runPowerShell(cmd)
	if err != nil {
		return nil, err
	}

	// Split the output by line and parse the stream names
	var streams []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Look for the "Stream" field in the output
		if strings.Contains(line, "Stream") {
			// Extract the stream name by splitting the line
			parts := strings.Fields(line)
			if len(parts) > 1 {
				streams = append(streams, parts[2])
			}
		}
	}

	return streams, nil
}

func hasPeMagic(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	magic := make([]byte, 2)
	_, err = file.Read(magic)
	if err != nil {
		return false, err
	}

	if bytes.Equal(magic, []byte{'M', 'Z'}) {
		return true, nil
	}
	return false, nil
}

func hasExecutableExtension(path string) bool {
	executableExtensions := map[string]bool{
		".exe":  true,
		".dll":  true,
		".scr":  true,
		".sys":  true,
		".py":   true,
		".pyc":  true,
		".com":  true,
		".bat":  true,
		".vbs":  true,
		".vbe":  true,
		".lnk":  true,
		".msi":  true,
		".msp":  true,
		".cmd":  true,
		".ps1":  true,
		".psm1": true,
		".appx": true,
		".reg":  true,
		".js":   true,
		".ws":   true,
	}
	ext := strings.ToLower(filepath.Ext(path))
	return executableExtensions[ext]
}

func readMotwZoneId(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var (
		lines  []string
		zoneId int
	)
	reader := bufio.NewScanner(file)
	for reader.Scan() {
		lines = append(lines, reader.Text())
	}
	if err = reader.Err(); err != nil {
		return 0, err
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "ZoneId=") {
			_, err = fmt.Sscanf(line, "ZoneId=%d", &zoneId)
			if err != nil {
				return 0, err
			}
			return zoneId, nil
		}
	}
	return -1, nil
}

func (r HashLookup) Print() {
	switch r.Status {
	case "ok":
		red.Log("[*] ")
		white.Log("Hash found in malwarebazaar database!")
		for _, d := range r.Data {
			white.Log("\n")
			white.Log("\tLink: https://bazaar.abuse.ch/sample/%s\n", r.Sha256)
			if d.Signature != "" && d.Signature != "null" {
				white.Log("\tSignature: %s\n", d.Signature)
			}
			for _, rule := range d.YaraRules {
				white.Log("\n\tYara rule:")
				white.Log("\t\tName: %s\n", rule.Name)
				if rule.Description != "" && rule.Description != "null" {
					white.Log("\t\tDescription: %s\n", rule.Description)
				}
			}
		}

	case "hash_not_found":
		green.Log("[*] Hash not found in malwarebazaar database")
	}
}

func (r HashLookup) IsEmpty() bool {
	if r.Status != "ok" && r.Status != "hash_not_found" && len(r.Data) == 0 {
		return true
	}
	return false
}

func RegisterProcess(pid int, path string) {
	_, exists := processes[pid]
	if exists {
		return
	}

	signedStatus, err := IsSignatureValid(path)
	if err != nil {
		red.Log("\n[!] Failed to get authenticode signature of %s!\n", path)
		white.Log("\tError: %v\n", err)
	}

	var signed bool
	switch signedStatus {
	case IS_UNSIGNED:
		signed = false
	case HAS_SIGNATURE:
		signed = true
	case HASH_MISMATCH:
		red.Log("\n[!] Hash mismatch on %s!!\n", path)
		TerminateProcess(pid)
	}

	processes[pid] = &Process{
		Path:           path,
		IsSigned:       signed,
		APICalls:       make(map[string]ApiCallData),
		FileEvents:     make(map[string]FileEventData),
		RegEvents:      make(map[string]RegEventData),
		PatternMatches: make(map[string]*StdResult),
	}

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err == nil {
		if C.IsProcessElevated(C.HANDLE(hProcess)) == C.TRUE {
			processes[pid].IsElevated = true
		}

		integrity := C.GetProcessIntegrityLevel(C.HANDLE(hProcess))
		if integrity != C.DWORD(0) {
			processes[pid].Integrity = uint32(integrity)
		}

		ppid := C.GetParentPid(C.HANDLE(hProcess))
		if ppid != C.DWORD(0) {
			processes[pid].ParentPid = int(ppid)
			parentPath, err := GetProcessExecutable(uint32(ppid))
			if err != nil {
				red.Log("Failed to get process path of process %d (parent of %d)\n", ppid, pid)
			} else {
				processes[pid].ParentPath = parentPath
			}
		}
		windows.CloseHandle(hProcess)
	}
	go StaticScan(pid, false) // no print
}

func (pattern BehaviorPattern) GetStdResult(bonus int) StdResult {
	match := StdResult{
		Name:        pattern.Name,
		Description: pattern.Description,
		TimeStamp:   time.Now().Unix(),
		Severity:    pattern.Severity,
		Score:       pattern.Score + bonus,
		Category:    pattern.Category,
	}

	if match.Name == "" { // make sure name has a value, to not mess up logic
		if match.Description != "" {
			match.Name = match.Description
		} else { // fallback, use first api as name
			match.Name = pattern.Components[0].GetDefaultName()
		}
	}

	return match
}
