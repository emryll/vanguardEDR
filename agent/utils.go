package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"sort"
	"strings"

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
	// Open process with PROCESS_QUERY_LIMITED_INFORMATION (0x1000) right
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

func Cleanup[T History](history []T, threshold int64) []T {
	// sort history
	sort.Slice(history, func(i, j int) bool {
		return history[i].GetTime() < history[j].GetTime()
	})
	// find item closest to timestamp threshold
	index := binarySearch(history, threshold)
	return history[index:]
}

// find first item <= threshold
func binarySearch[T History](history []T, threshold int64) int {
	left, right := 0, len(history)-1
	for left <= right {
		mid := left + (right-left)/2
		if history[mid].GetTime() >= threshold {
			right = mid - 1
		} else {
			left = mid + 1
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
