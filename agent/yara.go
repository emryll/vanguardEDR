package main

//#include "memscan.h"
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	yara "github.com/VirusTotal/yara-x"
	"github.com/fatih/color"
	"golang.org/x/sys/windows"
)

func LoadYaraRulesFromFolder(path string) (*yara.Rules, *yara.Scanner, error) {
	var dir string
	if path == "" {
		dir = DEFAULT_RULE_DIR
	} else {
		dir = path
	}
	c, err := yara.NewCompiler()
	if err != nil || c == nil {
		color.Red("[!] Failed to create YARA compiler!\n\tError: %v", err)
		return nil, nil, err
	}
	err = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			color.Red("[!] Failed to read %s\n\tError: %v", p, err)
			return nil // skip file, continue
		}

		if !info.IsDir() && filepath.Ext(p) == ".yara" {
			data, err := os.ReadFile(p)
			if err != nil {
				color.Red("[!] Failed to read %s\n\tError: %v", p, err)
				return nil // skip file, continue
			}

			err = c.AddSource(string(data))
			if err != nil {
				color.Red("[!] Failed to add source!\n\tError: %v")
				return err
			}

		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	rules := c.Build()
	scanner := yara.NewScanner(rules)
	c.Destroy()

	return rules, scanner, nil
}

func YaraScanFile(scanner *yara.Scanner, path string) ([]StdResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result, err := scanner.Scan(data)
	if err != nil {
		return nil, err
	}
	matches := result.MatchingRules()
	results := getResultsFromRules(matches)

	return results, nil
}

func getResultsFromRules(matches []*yara.Rule) []StdResult {
	var results []StdResult
	for _, match := range matches {
		id := match.Identifier()
		metadata := match.Metadata()
		name := fmt.Sprintf("Yara match: %s", id)
		var (
			score int64
			sev   int64
			desc  string
		)
		for _, md := range metadata {
			t := strings.ToLower(md.Identifier())
			switch t {
			case "score":
				score = md.Value().(int64)
			case "severity":
				sev = md.Value().(int64)
			case "description", "desc":
				desc = md.Value().(string)
			}
		}
		results = append(results, StdResult{Name: name, Description: desc, Score: int(score), Severity: int(sev)})
	}
	return results
}

// performs YARA-X scan on all RWX regions of remote process
func ScanRWXMemory(hProcess windows.Handle, scanner *yara.Scanner) ([]StdResult, error) {
	var (
		numRegions C.size_t
		results    []StdResult
	)
	// get rwx memory regions locations and turn c struct array into go slice
	rwxRegions := C.GetRWXMemory(C.HANDLE(unsafe.Pointer(hProcess)), &numRegions)
	regions := unsafe.Slice((*MemRegion)(unsafe.Pointer(rwxRegions)), int(numRegions))

	// read and scan the rwx memory regions
	for _, r := range regions {
		data, err := ReadRemoteProcessMem(hProcess, uintptr(r.Address), int(r.Size))
		if err != nil {
			return results, err
		}
		result, err := scanner.Scan(data)
		if err != nil {
			return results, err
		}
		m := result.MatchingRules()
		matches := getResultsFromRules(m)
		results = append(results, matches...)
	}
	C.free(unsafe.Pointer(rwxRegions))
	return results, nil
}

// TODO: test
func ScanMainModuleText(hProcess windows.Handle, scanner *yara.Scanner) ([]StdResult, error) {
	var size C.size_t
	buf := C.GetModuleText(C.HANDLE(unsafe.Pointer(hProcess)), &size)
	if buf == nil {
		return nil, fmt.Errorf("Failed to get module .text section")
	}
	// convert to []byte
	buffer := C.GoBytes(unsafe.Pointer(buf), C.int(size))
	result, err := scanner.Scan(buffer)
	if err != nil {
		return nil, err
	}
	C.free(unsafe.Pointer(buf))
	m := result.MatchingRules()
	return getResultsFromRules(m), nil
}

func BasicMemoryScan(pid uint32, scanner *yara.Scanner) ([]StdResult, error) {
	fmt.Printf("\n[i] Performing basic memory scan on process %d...\n", pid)
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, fmt.Errorf("Failed to open process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	var results []StdResult
	rwxResults, err := ScanRWXMemory(hProcess, scanner)
	if err != nil {
		color.Red("\n[ERROR] Failed to scan RWX memory of process %d: %v", pid, err)
	} else {
		fmt.Printf("\n[*] Scanned RWX memory of process %d\n", pid)
		results = append(results, rwxResults...)
	}
	textResults, err := ScanMainModuleText(hProcess, scanner)
	if err != nil {
		color.Red("\n[ERROR] Failed to scan main module's .text section of process %d: %v", pid, err)
	} else {
		fmt.Printf("\n[*] Scanned main module's .text section of process %d\n", pid)
		results = append(results, textResults...)
	}
	return results, nil
}

func MemoryScanEx(pid uint32, scanner *yara.Scanner) ([]StdResult, error) {
	fmt.Printf("\n[i] Performing full memory scan on process %d...\n", pid)
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, fmt.Errorf("Failed to open process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	var (
		results    []StdResult
		numModules C.size_t
	)
	mods := C.GetAllSectionsOfProcess(C.HANDLE(unsafe.Pointer(hProcess)), &numModules)
	if mods == nil || numModules == 0 {
		color.Red("[ERROR] Failed to get sections of process %d", pid)
		return nil, fmt.Errorf("Failed to get sections")
	}
	// turn into go struct slice
	defer C.FreeRemoteModuleArray(mods, numModules)
	//modules := unsafe.Slice((*RemoteModule)(unsafe.Pointer(mods)), int(numModules))
	modules, err := ConvertRemoteModules(mods, numModules)
	if err != nil {
		return nil, err
	}

	for _, module := range modules {
		fmt.Printf("[i] Scanning %s...\n", module.GetName())
		fmt.Printf("len sections: %d (%d)\n", len(module.Sections), module.NumSections)
		for i := 0; i < int(module.NumSections); i++ {
			fmt.Printf("section %d size: %d (0x%p)\n", i, module.Sections[i].Size, module.Sections[i].Address)
			buf, err := ReadRemoteProcessMem(hProcess, uintptr(module.Sections[i].Address), int(module.Sections[i].Size))
			if err != nil {
				color.Red("[!] Failed to read section at 0x%p within process %d: %v", module.Sections[i].Address, pid, err)
				continue
			}
			result, err := scanner.Scan(buf)
			if err != nil {
				color.Red("[!] Failed to scan buffer of memory(%dB): %v", len(buf), err)
				continue
			}
			m := result.MatchingRules()
			results = append(results, getResultsFromRules(m)...)
		}
	}
	return results, nil
}

func FullMemoryScan(pid uint32, scanner *yara.Scanner) ([]StdResult, error) {
	fmt.Printf("\n[i] Performing full memory scan on process %d...\n", pid)
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, fmt.Errorf("Failed to open process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	var (
		results    []StdResult
		numRegions C.size_t
	)
	cregions := C.GetAllMemoryRegions(C.HANDLE(unsafe.Pointer(hProcess)), &numRegions)
	if cregions == nil || numRegions == 0 {
		return nil, fmt.Errorf("Failed to get memory regions of process: %v", windows.GetLastError())
	}
	regions := unsafe.Slice((*MemRegion)(unsafe.Pointer(cregions)), int(numRegions))

	for i, region := range regions {
		buf, err := ReadRemoteProcessMem(hProcess, uintptr(region.Address), int(region.Size))
		if err != nil {
			color.Red("[!] Failed to read memory region at 0x%p: %v", region.Address, err)
			continue
		}
		result, err := scanner.Scan(buf)
		if err != nil {
			color.Red("[!] Failed to scan buffer (%dB): %v", len(buf), err)
			continue
		}
		results = append(results, getResultsFromRules(result.MatchingRules())...)
	}
	C.free(unsafe.Pointer(cregions))
	return results, nil
}
