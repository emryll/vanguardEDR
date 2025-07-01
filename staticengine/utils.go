package main

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

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
		fmt.Println(line)
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
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err = scanner.Err(); err != nil {
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

func (r StaticResult) Print() {
	switch r.Severity {
	case 0:
		green := color.New(color.FgGreen, color.Bold)
		color.Green("\t[*] %s (", r.Description)
		green.Printf("+%d", r.Score)
		color.Green(")")
	case 1:
		yellow := color.New(color.FgYellow, color.Bold)
		color.Yellow("\t[*] %s (", r.Description)
		yellow.Printf("+%d", r.Score)
		color.Yellow(")")
	case 2:
		red := color.New(color.FgRed, color.Bold)
		color.Red("\t[*] %s (", r.Description)
		red.Printf("+%d", r.Score)
		color.Red(")")
	}
}
