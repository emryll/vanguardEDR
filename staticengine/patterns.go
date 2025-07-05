package main

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"os"
	"path/filepath"
	"strings"
)

var (
	apiPatterns               []ApiPattern
	maliciousApis             map[string]MalApi
	DEFAULT_PATTERN_DIR       = "./rules"
	DEFAULT_PATTERN_FILENAME  = "apipatterns.json"
	DEFAULT_FUNCLIST_FILENAME = "malapi.json"
	MAX_INDIVIDUAL_FN_SCORE   = 20
	MAX_PATTERN_SCORE         = 60
	LOW_FN_DEFAULT_SCORE      = 1
	MEDIUM_FN_DEFAULT_SCORE   = 3
	HIGH_FN_DEFAULT_SCORE     = 6
)

// json file with each pattern like so: "component1" { "func1", "func2" } "component2" {...} ...
// severity is low || medium || high and only affects color. score is actual score
func LoadApiPatternsFromDisk(path string) ([]ApiPattern, error) {
	var (
		patterns []ApiPattern
		filePath string
		dirPath  string
	)
	if path == "" {
		dirPath = DEFAULT_PATTERN_DIR
	} else {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			dirPath = path
		} else {
			filePath = path
		}
	}
	if dirPath == "" {
		var p []ApiPattern
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(data, &p)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, p...)
	} else {
		count := 0
		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err // Skip files/dirs that cause an error
			}

			if !info.IsDir() && strings.HasSuffix(info.Name(), ".pattern") {
				var p []ApiPattern
				data, err := os.ReadFile(path)
				if err != nil {
					color.Red("\n[!] Failed to read %s!\n\tError: %v", path, err)
					return nil // skip file
				}
				err = json.Unmarshal(data, &p)
				if err != nil {
					color.Red("\n[!] Failed to unmarshal %s!\n\tError: %v", path, err)
					return nil
				}
				patterns = append(patterns, p...)
				count++
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("Walk failed: %v", err)
		}
		fmt.Printf("[i] Found %d API pattern files\n", count)
	}
	return patterns, nil
}

// json file with each function like so: "function", "severity", "score"
// severity is low || medium || high and only affects color. score is actual score
func LoadMaliciousApiListFromDisk(path string) (map[string]MalApi, error) {
	var filePath string
	if path == "" {
		filePath = filepath.Join(DEFAULT_PATTERN_DIR, DEFAULT_FUNCLIST_FILENAME)
	} else {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			filePath = filepath.Join(path, "malapi.json")
		} else {
			filePath = path
		}
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var (
		list   []MalApi
		malapi = make(map[string]MalApi)
	)
	err = json.Unmarshal(data, &list)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal JSON: %v", err)
	}
	for _, m := range list {
		if m.Score == 0 {
			switch m.Severity {
			case 0:
				m.Score = LOW_FN_DEFAULT_SCORE
			case 1:
				m.Score = MEDIUM_FN_DEFAULT_SCORE
			case 2:
				m.Score = HIGH_FN_DEFAULT_SCORE
			}
		}
		malapi[m.Name] = m
	}
	return malapi, nil
}

func CheckApiPatterns(imports map[string]bool) ([]StaticResult, int) {
	var (
		results []StaticResult
		total   = 0
	)
	for _, pattern := range apiPatterns {
		match := false
		// iterate each component of pattern
		for _, call := range pattern.ApiCalls {
			// check each possible func for that component
			for _, fn := range call {
				_, exists := imports[fn]
				if !exists { // not a match, move on to next one
					match = false
					continue
				}
				match = true
				break
			}
			if !match { // if one of components is missing, pattern does not match
				break
			}
		}
		if match {
			desc := fmt.Sprintf("Imports match malicious API pattern: %s", pattern.Name)
			results = append(results, StaticResult{Description: desc, Score: pattern.Score, Severity: pattern.Severity, Tag: "Pattern"})
			total += pattern.Score
		}
	}
	if total > MAX_PATTERN_SCORE {
		total = MAX_PATTERN_SCORE
	}
	return results, total
}
