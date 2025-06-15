package main

//TODO: read from external json file
var apiPatterns = []ApiPattern{
	{Name: "Classic process injection (kernel32)",
		ApiCalls:  []string{"OpenProcess", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"},
		TimeRange: 30},
	{Name: "Classic process injection (ntdll)",
	},
	{Name: "Token impersonation (privesc)",
	},
	{Name: "Classic DLL injection (kernel32)",
	},
	{Name: "Classic DLL injection (ntdll)",
	},
}

//TODO: read from external json file
var filePatterns = []FilePattern{
	{ Name: "",},
}

//TODO: read from external json file
var regPatterns = []RegPattern {
	{Name: "",},
}

// returns names of each pattern match
func (p *Process) CheckApiPatterns() []Result {
	var matches []Result
	for _, pattern := range apiPatterns {
		var (
			match = false
			matchResult PatternResult
			startTimes []int64
		)
		// iterate each component of pattern 
		for i, call := range pattern.ApiCalls {
			// check each possible func for that component //TODO: use bitwise &
			for _, fn := range call.Funcs {
				//TODO: make timerange check seperate function so its not so ugly
				api, exists := p.APICalls[fn]
				if !exists { // not a match, move on to next one
					match = false
					continue
				}
				//* check if its within timeframe
				if i == 0 { //save timeframes for first part of pattern
					startTimes = append(startTimes, p.APICalls[fn].TimeStamp)
					for _, oldCall := range p.APICalls[fn].Others {
						startTimes = append(startTimes, oldCall.TimeStamp)
					}
				} else {
					for i, start := range startTimes {
						found := false
						// Check if latest call is within specified timerange
						if start - p.APICalls[fn].TimeStamp <= pattern.TimeRange {
							found = true
							continue
						}
						// Check older calls
						for _, oldCall := range p.APICalls[fn].Others {
							if start - oldCall.TimeStamp <= pattern.TimeRange {
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
			if !match { // if one of calls is missing, pattern does not match
				break
			}
		}
		if match {
			matchResult.TimeStamp = time.Now().Unix()
			matchResult.Severity = pattern.Severity
			matchResult.Name = pattern.Name
			matches.TotalScore += matchResult.TotalScore
			p.TotalScore += matchResult.TotalScore
			matches.Results = append(matches.Results, matchResult)
			// check if pattern match already registered, add if not
			value, exists := p.PatternMatches[matchResult.Name]
			if exists {
				if matchResult.TimeStamp - value.TimeStamp <= TM_HISTORY_CLEANUP_INTERVAL {
					continue
				}
				value.Count++
				value.TimeStamp = matchResult.TimeStamp
			} else {
				p.PatternMatches[matchResult.Name] = matchResult
			}
		}
	}
	p.PatternMatches = append(p.PatternMatches, matches...)
	return matches
}

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
			if match.TimeStamp - entry.TimeStamp <= TM_HISTORY_CLEANUP_INTERVAL {
				continue
			}
			entry.TimeStamp = match.TimeStamp
			entry.Count++;
		}
		results.TotalScore += match.Severity
		results.Results = append(results.Results, match)
	}
	return results
}

func (p *Process) CheckRegBehaviorPatterns() Result {
	var results Result
	for _, pattern := range regPatterns {
		event, exists := p.RegEvents[pattern.Name]
		if !exists { // current pattern does not match
			continue
		}
		var match PatternResult
		match.Name = pattern.NameapiPatterns
		match.Severity = pattern.Severity
		match.TimeStamp = time.Now().Unix()
		match.Count = 0
		entry, exists := p.PatternMatches[pattern.Name]
		if !exists {
			p.PatternMatches[pattern.Name] = match
		} else {
			if match.TimeStamp - entry.TimeStamp <= TM_HISTORY_CLEANUP_INTERVAL {
				continue
			}
			entry.TimeStamp = match.TimeStamp
			entry.Count++
		}
		results.TotalScore += match.Severity
		results.Results = append(results.Results, match)
	}
	return results
}

func HistoryCleaner(wg *sync.WaitGroup, terminate chan struct{}) {
	defer wg.Done()
	cleanup := time.NewTicker(time.Duration(TM_HISTORY_CLEANUP_INTERVAL)*time.Second)
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
			for pid, process := range processes {
				tasks <- &process
			}
		}
	}
}

func HistoryCleanup(wg *sync.WaitGroup, tasks chan *Process)
	defer wg.Done()
	for {
		select {
		case task := <-tasks {
			threshold := time.Now().Unix() - TM_HISTORY_CLEANUP_INTERVAL
			for _, fn := range task.APICalls {
				Cleanup(fn.History, threshold)
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