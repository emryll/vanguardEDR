package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// returns names of each pattern match and adds them to pattern match history of process
func (p *Process) CheckApiPatterns() Result {
	var matches Result
	for _, pattern := range apiPatterns {
		var ( // describe current pattern
			match      = false
			startTimes []int64
		)
		//* iterate each component of pattern
		for i, call := range pattern.ApiCalls {
			//* check each possible func for that component //TODO: use bitwise & and ids
			for _, fn := range call {
				//TODO: make timerange check seperate function so its not so ugly
				//* does it exist in api call history?
				api, exists := p.APICalls[fn]
				if !exists { // not a match, move on to next one
					match = false
					continue
				}
				//* check if its within timeframe
				if i == 0 { //save possible timeframes for first component of pattern
					startTimes = append(startTimes, api.TimeStamp)
					for _, oldCall := range api.History {
						startTimes = append(startTimes, oldCall.TimeStamp)
					}
				} else {
					for i, start := range startTimes {
						found := false
						// Check if latest call is within specified timerange
						if start-api.TimeStamp <= int64(pattern.TimeRange) {
							found = true
							continue
						}
						// Check older calls
						for _, oldCall := range api.History {
							if start-oldCall.TimeStamp <= int64(pattern.TimeRange) {
								found = true
								break
							}
						}
						if !found { // no call matches timerange
							startTimes = RemoveSliceMember(startTimes, i)
						}
					}
				}
				match = true
				break
			}
			if !match { // if one of components is missing, pattern does not match
				break
			}
		}
		if match {
			matchResult := StdResult{
				Name:        pattern.Name,
				Description: pattern.Description,
				TimeStamp:   time.Now().Unix(),
				Severity:    pattern.Severity,
				Score:       pattern.Score,
				Category:    pattern.Category,
			}
			if matchResult.Name == "" { // make sure name has a value, to not mess up logic
				if matchResult.Description != "" {
					matchResult.Name = matchResult.Description
				} else { // fallback, use first api as name
					matchResult.Name = pattern.ApiCalls[0][0]
				}
			}
			matches.TotalScore += matchResult.Score
			matches.Results = append(matches.Results, matchResult)

			// check if pattern match already registered, add if not
			value, exists := p.PatternMatches[matchResult.Name]
			if exists {
				// check if it was just added, in order to avoid duplicates
				if matchResult.TimeStamp-value.TimeStamp <= TM_HISTORY_CLEANUP_INTERVAL {
					continue
				}
				//? value is a copy, thats why it cant be used
				mu.Lock()
				p.PatternMatches[matchResult.Name].Count++
				p.PatternMatches[matchResult.Name].TimeStamp = matchResult.TimeStamp
				mu.Unlock()
			} else {
				mu.Lock()
				p.PatternMatches[matchResult.Name] = &matchResult
				//? should you increment score on duplicates or not? be consistent
				p.TotalScore += matchResult.Score
				mu.Unlock()
			}
		}
	}
	return matches
}

// returns names of each pattern match and adds them to pattern match history of process
func CheckStaticApiPatterns(imports map[string]bool) Result {
	var matches Result
Patterns:
	for _, pattern := range apiPatterns {
		var match bool
		//* iterate each component of pattern
		for _, call := range pattern.ApiCalls {
			//* check each possible func for that component //TODO: use bitwise & and ids
			for _, fn := range call {
				if imports[fn] {
					match = true
					break
				}
			}
			if !match { // if one of components is missing, pattern does not match
				continue Patterns
			}
		}
		matchResult := StdResult{
			Name:        pattern.Name,
			Description: pattern.Description,
			TimeStamp:   time.Now().Unix(),
			Severity:    pattern.Severity,
			Score:       pattern.Score,
			Category:    pattern.Category,
		}
		if matchResult.Name == "" { // make sure name has a value, to not mess up logic
			if matchResult.Description != "" {
				matchResult.Name = matchResult.Description
			} else { // fallback, use first api as name
				matchResult.Name = pattern.ApiCalls[0][0]
			}
		}
		matches.TotalScore += matchResult.Score
		matches.Results = append(matches.Results, matchResult)
	}
	return matches
}

//TODO:
/*
func (p *Process) CheckFileBehaviorPatterns() Result {
	var results Result
	for _, pattern := range filePatterns {
		event, exists := p.FileEvents[pattern.Name]
		if !exists { // current pattern does not match
			continue
		}
		var match PatternResult
		match.Name = pattern.Name
		match.Severity = pattern.Severity
		match.TimeStamp = time.Now().Unix()
		match.Count = 0
		entry, exists := p.PatternMatches[pattern.Name]
		if !exists {
			p.PatternMatches[pattern.Name] = match
		} else {
			// avoid registering same behavior events multiple times
			if match.TimeStamp-entry.TimeStamp <= TM_HISTORY_CLEANUP_INTERVAL {
				continue
			}
			entry.TimeStamp = match.TimeStamp
			entry.Count++
		}
		results.TotalScore += match.Severity
		results.Results = append(results.Results, match)
	}
	return results
}*/

//TODO:
/*
func (p *Process) CheckRegBehaviorPatterns() Result {
	var results Result
	for _, pattern := range regPatterns {
		event, exists := p.RegEvents[pattern.Name]
		if !exists { // current pattern does not match
			continue
		}
		var match StdResult
		match.Name 		  = pattern.Name
		match.Description = pattern.Description
		match.Severity 	  = pattern.Severity
		match.TimeStamp   = time.Now().Unix()
		match.Count 	  = 0
		entry, exists := p.PatternMatches[pattern.Name]
		if !exists {
			p.PatternMatches[pattern.Name] = match
		} else {
			if match.TimeStamp-entry.TimeStamp <= TM_HISTORY_CLEANUP_INTERVAL {
				continue
			}
			entry.TimeStamp = match.TimeStamp
			entry.Count++
		}
		results.TotalScore += match.Severity
		results.Results = append(results.Results, match)
	} return results
}*/

// handle all cleaning of telemetry history, concurrently w/ worker pool of 10 goroutines
func HistoryCleaner(wg *sync.WaitGroup, terminate chan struct{}) {
	defer wg.Done()
	cleanup := time.NewTicker(time.Duration(TM_HISTORY_CLEANUP_INTERVAL) * time.Second)
	defer cleanup.Stop()

	tasks := make(chan *Process)
	numWorkers := 10
	go func() {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go HistoryCleanup(wg, tasks)
		}
	}()
	for {
		select {
		case <-terminate:
			close(tasks)
			return
		case <-cleanup.C:
			for _, process := range processes {
				tasks <- process
			}
		}
	}
}

// worker function for history cleanup mechanism
func HistoryCleanup(wg *sync.WaitGroup, tasks chan *Process) {
	defer wg.Done()
	for {
		select {
		case task := <-tasks:
			threshold := time.Now().Unix() - TM_HISTORY_CLEANUP_INTERVAL
			// fn is a copy. in the future make these entries *ApiCallData
			for _, fn := range task.APICalls {
				newHistory := Cleanup(fn.History, threshold) // utils.go
				fn.History = newHistory
				task.ApiMu.Lock()
				task.APICalls[fn.FuncName] = fn
				task.ApiMu.Unlock()
			}
			/*threshold := time.Now().Unix() - TM_HISTORY_CLEANUP_INTERVAL
			for _, v := range task.FileEvents{
				Cleanup(v, threshold)
			}
			threshold := time.Now().Unix() - TM_HISTORY_CLEANUP_INTERVAL
			for _, v := range task.RegEvents {
				Cleanup(v, threshold)
			}*/
		}
	}
}

// json file with each function like so: "function", "severity", "score"
// severity is low || medium || high and only affects color. score is actual score
func LoadMaliciousApiListFromDisk(path string) (map[string]MalApi, error) {
	var filePath string
	if path == "" {
		filePath = filepath.Join(DEFAULT_RULE_DIR, DEFAULT_FUNCLIST_FILENAME)
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

// json file with each pattern like so: "component1" { "func1", "func2" } "component2" {...} ...
// severity is low || medium || high and only affects color. score is actual score
func LoadApiPatternsFromDisk(path string) ([]ApiPattern, error) {
	var (
		patterns []ApiPattern
		filePath string
		dirPath  string
	)
	if path == "" {
		dirPath = DEFAULT_RULE_DIR
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
	} else { // if its a custom path, walk it to find all .pattern files
		count := 0
		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err // Skip files/dirs that cause an error
			}

			if !info.IsDir() && strings.HasSuffix(info.Name(), API_PATTERN_EXTENSION) {
				var p []ApiPattern
				data, err := os.ReadFile(path)
				if err != nil {
					red.Log("\n[!] Failed to read %s!\n", path)
					white.Log("\tError: %v\n", err)
					return nil // skip file
				}
				err = json.Unmarshal(data, &p)
				if err != nil {
					red.Log("\n[!] Failed to unmarshal %s!\n", path)
					white.Log("\tError: %v\n", err)
					return nil
				}
				patterns = append(patterns, p...)
				count++
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("Directory walk failed: %v", err)
		}
		white.Log("[i] Found %d API pattern files, for a total of %d patterns\n", count, len(patterns))
	}
	return patterns, nil
}

//TODO: load file patterns
//TODO: load reg patterns
