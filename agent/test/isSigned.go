package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

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

func GetProcessExecutable(pid int) (string, error) {
	// Open process with PROCESS_QUERY_LIMITED_INFORMATION (0x1000) right
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
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

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Not enough args: Usage: %s <pid>\n", os.Args[0])
		return
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}
	path, err := GetProcessExecutable(pid)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}
	fmt.Printf("Process %d has path %s\n", pid, path)

	r, err := IsSignatureValid(path)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}
	switch r {
	case 0:
		fmt.Printf("%s is not signed", path)
	case 1:
		fmt.Printf("%s is signed", path)
	case 2:
		fmt.Printf("%s has a hash mismatch!", path)
	}
}
