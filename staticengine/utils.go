package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
		green.Printf("[*] ")
		if r.Name == "" {
			fmt.Printf("%s ", r.Description) //text in white so its easier to read
			green.Printf("(+%d)\n", r.Score)
		} else {
			fmt.Printf("%s ", r.Name) //text in white so its easier to read
			green.Printf("(+%d)\n", r.Score)
			if r.Description != "" {
				fmt.Printf("\t[?] %s\n", r.Description)
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
				fmt.Printf("\t[?] %s\n", r.Description)
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

func GetEntropyOfFile(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0.0, err
	}
	return GetEntropy(data), nil
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
	if status == "Valid" {
		return 1, nil
	} else if status == "HashMismatch" {
		return 2, nil
	}
	return 0, nil
}

/*func CheckMagic() {

}*/

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

type Magic struct {
	Bytes []byte
	Type  string
}

var magicToType = []Magic{
	{[]byte{0x4D, 0x5A}, "DOS MZ / PE File (.exe, .dll, ++)"},
	{[]byte{0x5A, 0x4D}, "DOS ZM legacy executable (.exe)"},
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, "ELF Executable"},
	{[]byte{0x25, 0x50, 0x44, 0x46}, "Zip archive"},
	{[]byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, "SQLite Database"},
	{[]byte{0x00, 0x00, 0x01, 0x00}, "Icon file"},
	{[]byte{0x1F, 0x9D}, "tar archive (Lempel-Ziv-Welch algorithm)"},
	{[]byte{0x1F, 0xA0}, "tar archive (LZH algorithm)"},
	{[]byte{0x2D, 0x6C, 0x68, 0x30, 0x2D}, "Lempel Ziv Huffman archive (method 0, no compression)"},
	{[]byte{0x2D, 0x6C, 0x68, 0x35, 0x2D}, "Lempel Ziv Huffman archive (method 5)"},
	{[]byte{0x42, 0x5A, 0x68}, "Bzip2 archive"},
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, "GIF file"},
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, "GIF file"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xDB}, "jpg or jpeg"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xEE}, "jpg or jpeg"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xE0}, "jpg or jpeg"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}, "jpg or jpeg"},
	{[]byte{0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A}, "JPEG 2000 format"},
	{[]byte{0xFF, 0x4F, 0xFF, 0x51}, "JPEG 2000 format"},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, "zip file format"},
	{[]byte{0x50, 0x4B, 0x05, 0x06}, "zip file format(empty archive)"},
	{[]byte{0x50, 0x4B, 0x07, 0x08}, "zip file format(spanned archive)"},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, "Roshal ARchive (RAR), >v1.50"},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, "Roshal ARchive (RAR), >v5.00"},
	{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "Portable Network Graphics (PNG) format"},
	{[]byte{0xEF, 0xBB, 0xBF}, "UTF-8 byte order mark (.txt, ++)"},
	{[]byte{0xFF, 0xFE}, "UTF-16LE byte order mark (.txt, ++)"},
	{[]byte{0xFE, 0xFF}, "UTF-16BE byte order mark (.txt, ++)"},
	{[]byte{0xFF, 0xFE, 0x00, 0x00}, "UTF-32LE byte order mark (.txt, ++)"},
	{[]byte{0x00, 0x00, 0xFE, 0xFF}, "UTF-32BE byte order mark (.txt, ++)"},
	{[]byte{0xFE, 0xED, 0xFA, 0xCE}, "Mach-O executable (32-bit)"},
	{[]byte{0xFE, 0xED, 0xFA, 0xCF}, "Mach-O executable (64-bit)"},
	{[]byte{0xCE, 0xFA, 0xED, 0xFE}, "Mach-O executable (reverse-order, 32-bit)"},
	{[]byte{0xCF, 0xFA, 0xED, 0xFE}, "Mach-O executable (reverse-order, 64-bit)"},
	{[]byte{0x25, 0x21, 0x50, 0x53}, "PostScript Document"},
	{[]byte{0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x2D, 0x33, 0x2E, 0x30, 0x20, 0x45, 0x50, 0x53, 0x46, 0x2D, 0x33, 0x2E, 0x30}, "Encapsulated PostScript v3.0"},
	{[]byte{0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x2D, 0x33, 0x2E, 0x31, 0x20, 0x45, 0x50, 0x53, 0x46, 0x2D, 0x33, 0x2E, 0x30}, "Encapsulated PostScript v3.1"},
	{[]byte{0x25, 0x50, 0x44, 0x46, 0x2D}, "PDF Document"},
	{[]byte{0x43, 0x44, 0x30, 0x30, 0x31}, "ISO9660 CD/DVD image file"},
	{[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "Compound File Binary Format (Microsoft Office)"},
	{[]byte{0x43, 0x72, 0x32, 0x34}, "Google Chrome extension or packaged app"},
	{[]byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30}, "tar archive"},
	{[]byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00}, "tar archive"},
	{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7-Zip archive"},
	{[]byte{0x1F, 0x8B}, "GZIP compressed file"},
	{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "XZ compression utility using LZMA2 compression"},
	{[]byte{0x00, 0x61, 0x73, 0x6D}, "WebAssembly binary format"},
	{[]byte{0x49, 0x73, 0x5A, 0x21}, "Compressed ISO image"},
	//TODO: add audio formats
	//TODO: add more executable types
	//TODO: lnk and other common malicious initial vector file types
}

func SortMagic() {
	// sort by descending length
	sort.Slice(magicToType, func(i, j int) bool {
		return len(magicToType[i].Bytes) > len(magicToType[j].Bytes)
	})
}

func GetLongestMagic() int {
	maxMagicLen := 0
	for _, b := range magicToType {
		if len(b.Bytes) > maxMagicLen {
			maxMagicLen = len(b.Bytes)
		}
	}
	return maxMagicLen
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

func (r HashLookup) Print() {
	switch r.Status {
	case "ok":
		red := color.New(color.FgRed)
		red.Printf("[*] ")
		fmt.Println("Hash found in malwarebazaar database!")
		for _, d := range r.Data {
			fmt.Printf("\n")
			fmt.Printf("\tLink: https://bazaar.abuse.ch/sample/%s\n", r.Sha256)
			if d.Signature != "" && d.Signature != "null" {
				fmt.Printf("\tSignature: %s\n", d.Signature)
			}
			for _, rule := range d.YaraRules {
				fmt.Println("\n\tYara rule:")
				fmt.Printf("\t\tName: %s\n", rule.Name)
				if rule.Description != "" && rule.Description != "null" {
					fmt.Printf("\t\tDescription: %s\n", rule.Description)
				}
			}
			fmt.Printf("\n")
		}

	case "hash_not_found":
		green := color.New(color.FgGreen)
		green.Printf("[*] ")
		fmt.Println("Hash not found in malwarebazaar database")
		fmt.Printf("\n")
	}
}
