package main

import (
	"fmt"
	"path/filepath"
)

var (
	apiPatterns               map[string]ApiPattern
	maliciousApis             map[string]int
	DEFAULT_PATTERN_DIR       = ".\\rules"
	DEFAULT_PATTERN_FILENAME  = "apipatterns.json"
	DEFAULT_FUNCLIST_FILENAME = "malapi.json"
	MAX_INDIVIDUAL_FN_SCORE   = 20
)

// TODO: use ints for memory efficiency and faster comparison?
type ApiFuncs struct {
	Funcs []string //  use ids instead with bit manipulation for memory efficiency
}

// TODO change name to id
type ApiPattern struct {
	Name     string     `json:"name"`
	ApiCalls []ApiFuncs `json:"api_calls"` // lets you define all possible options, so can do both kernel32 and nt
	Severity int        `json:"severity"`  // 0, 1, 2
	Score    int        `json:"score"`
}

// json file with each pattern like so: "component1" { "func1", "func2" } "component2" {...} ...
// severity is low || medium || high and only affects color. score is actual score
func LoadApiPatternsFromDisk(path string) error {
	var filePath string
	if path == "" {
		filePath = filepath.Join(DEFAULT_PATTERN_DIR, DEFAULT_PATTERN_FILENAME)
	} else {
		//TODO: check if its relative or full path
		filePath = path
	}
	//TODO: attempt to open file
}

type MalApi struct {
	Name     string `json:"name"`
	Severity int    `json:"severity"`
	Score    int    `json:"score"`
}

// json file with each function like so: "function", "severity", "score"
// severity is low || medium || high and only affects color. score is actual score
func LoadMaliciousApiListFromDisk() error {
	//TODO
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
			for _, fn := range call.Funcs {
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
			desc := fmt.Sprintf("Imports match malicious API pattern: %s", pattern.Name)
			results = append(results, StaticResult{Description: desc, Score: pattern.Severity})
			total += pattern.Severity
		}
	}
	return results, total
}
