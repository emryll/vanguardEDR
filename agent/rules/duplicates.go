package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run script.go filename")
		return
	}

	filename := os.Args[1]
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Regex to extract value after "name": possibly with spaces and quotes
	re := regexp.MustCompile(`"name"\s*:\s*"(.*?)"`)

	counts := make(map[string]int)
	lines := make(map[string][]int)

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.Contains(line, `"name":`) {
			match := re.FindStringSubmatch(line)
			if len(match) == 2 {
				nameValue := match[1]
				counts[nameValue]++
				lines[nameValue] = append(lines[nameValue], lineNumber)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	for name, count := range counts {
		if count > 1 {
			fmt.Printf("String: %q appears %d times at lines %v\n", name, count, lines[name])
		}
	}
}
