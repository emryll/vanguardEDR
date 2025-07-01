package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	yara "github.com/VirusTotal/yara-x/go"
	"github.com/fatih/color"
)

func LoadYaraRulesFromFolder(path string) (*yara.Rules, *yara.Scanner, error) {
	var dir string
	if path == "" {
		dir = DEFAULT_PATTERN_DIR
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

func YaraScanFile(scanner *yara.Scanner, path string) ([]StaticResult, error) {
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

func getResultsFromRules(matches []*yara.Rule) []StaticResult {
	var results []StaticResult
	for _, match := range matches {
		id := match.Identifier()
		metadata := match.Metadata()
		desc := fmt.Sprintf("Yara match: %s", id)
		var (
			score int64
			sev   int64
		)
		for _, md := range metadata {
			t := strings.ToLower(md.Identifier())
			switch t {
			case "score":
				score = md.Value().(int64)
			case "severity":
				sev = md.Value().(int64)
			}
		}
		results = append(results, StaticResult{Description: desc, Score: int(score), Severity: int(sev)})
	}
	return results
}
