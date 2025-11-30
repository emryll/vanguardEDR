package main

import (
	"path/filepath"

	"honnef.co/go/tools/pattern"
)

// This is the function you should call to trigger a behavioral scan for a process.
// It will go through each pattern and check if it matches telemetry history.
// Before running this, BehaviorPatterns global list must be loaded (should happen at start-up) 
func (p *Process) CheckBehaviorPatterns() Result {
	var matches Result
Patterns:
	for _, pattern := range BehaviorPatterns {
		//* first check universal conditions
		if !pattern.UniversalConditions.Check(p) {
			continue
		}

		var (
			startTimes []int64
			bonus = 0
		)

		//* check each component
		for i, component := range pattern.Components {
			result := component.IsMatch(p)
			if !result.Match {
				// if its not a required component
				if !component.IsRequired() {
					continue
				}
				continue Patterns
			}

			if !component.TimeMatters || pattern.TimeRange == 0 {
				// if it was a bonus component, add to score
				bonus += component.GetBonus() // this will be 0 if its required
				continue
			}

			// on the first one, save the times to create a timeline
			if i == 0 {
				startTimes = append(startTimes, result.TimeStamps)
			} else {
				startTimes = CheckTimeline(startTimes, result.TimeStamps, pattern.TimeRange)
				if len(startTimes) == 0 {
					continue Patterns
				}
			}
			// if its not a bonus component, bonus will be 0.
			bonus += component.Bonus
		}

		// since it got this far, it is a match
		match := pattern.GetStdResult(bonus)
		matches.TotalScore += match.Score
		matches.Results = append(matches.Results, match)
	}
	return matches
}

// Method to implement Component interface.
// This tells if the component matched, and returns the timestamp options.
func (c ApiComponent) IsMatch(p *Process) ComponentMatch {
	var result ComponentMatch
	if c.UniversalOverride != nil && !c.UniversalOverride.Check(p) {
		return result // false
	}

	//* first check if any of these apis exist in history
Options:
	for _, fn := range c.Options {
		api, exists := p.APICalls[fn]
		if !exists {
			continue
		}
		//* now check that the defined conditions apply to this api
		for _, condition := range c.Conditions {
			if !condition.Check(p, api) {
				continue Options
			}
		}
		//? collect timestamps so you can check if any align in the timeline of other components
		result.TimeStamps = append(result.TimeStamps, api.TimeStamp)
		for _, a := range api.History {
			result.TimeStamps = append(result.TimeStamps, a.TimeStamp)
		}
		result.Match = true
	}
	return result
}

// Method to implement Component interface. 
// This tells if the component matched, and returns the timestamp options.
func (c FileComponent) IsMatch(p *Process) ComponentMatch {
	var result ComponentMatch
	if c.UniversalOverride != nil && !c.UniversalOverride.Check(p) {
		return result // false
	}

	var PathFound bool
	if len(c.)
}

// Method to implement Component interface. 
// This tells if the component matched, and returns the timestamp options.
func (c RegComponent) IsMatch(p *Process) ComponentMatch {
	//TODO:
}

func (u UniversalConditions) Check(p *Process) bool {
	//? to check if remote thread is running this, you need to get tid
	var wantedParentFound bool
	//? parent needs to be one of these
	if len(u.Parent) == 0 {
		wantedParentFound = true
	}
	for _, parent := range u.Parent {
		if p.ParentPath == parent || filepath.Base(p.ParentPath) == parent {
			wantedParentFound = true
			break
		}
	}
	if !wantedParentFound {
		return false
	}

	//? parent cant be any of these
	for _, parent := range u.ParentNot {
		if p.ParentPath == parent || filepath.Base(p.ParentPath) == parent {
			return false
		}
	}

	//? check process filter
	if !u.Process.Check(p, nil) {
		return false
	}

	//? session id must be one of these
	for _, id := range u.SessionId {

	}

	//? session id cant be one of these
	for _, id := range u.SessionIdNot {

	}

	for _, user := range u.User {

	}

	for _, user := range u.UserNot {

	}

	return true
}

// Method to implement Condition interface. Returns true if it passed filter
func (f ProcessFilter) Check(p *Process, event interface{}) bool {
	//? Process structure provides everything necessary
	var nameFound bool
	if len(f.Name) == 0 {
		nameFound = true
	}
	for _, name := range f.Name {
		if name == filepath.Base(p.Path) || name == p.Path {
			nameFound = true
			break
		}
	}
	if !nameFound {
		return false
	}

	for _, name := range f.NameNot {
		if name == filepath.Base(p.Path) || name == p.Path {
			return false
		}
	}

	var pathFound bool
	if len(f.Path) == 0 {
		pathFound = true
	}
	for _, dir := range f.Path {
		if dir == filepath.Dir(p.Path) || dir == p.Path {
			pathFound = true
			break
		}
	}
	if !pathFound {
		return false
	}
	for _, dir := range f.Path {
		if dir == filepath.Dir(p.Path) || dir == p.Path {
			return false
		}
	}

	// if issigned is false, either is fine
	if f.IsSigned && !p.IsSigned {
		return false
	}

	if f.IsElevated && !p.IsElevated {
		return false
	}
	return true
}

// Method to implement Condition interface. Returns true if it passed filter
func (f FileFilter) Check(p *Process, event interface{}) bool {
	//? only filepath is needed
	fileEvent := event.(FileEventData)
	var foundName bool
	if len(f.Name) == 0 {
		foundName = true
	}

	//TODO: update for new nested directory design

	for _, name := range f.Name {
		if name == filepath.Base(fileEvent.Path) || name == fileEvent.Path {
			foundName = true
			break
		}
	}
	if !foundName {
		return false
	}

	for _, name := range f.NameNot {
		if name == filepath.Base(fileEvent.Path) || name == fileEvent.Path {
			return false
		}
	}

	var foundPath bool
	if len(f.Path) == 0 {
		foundPath = true
	}
	for _, path := range f.Path {
		if path == filepath.Dir(fileEvent.Path) || path == fileEvent.Path {
			foundPath = true
			break
		}
	}
	if !foundPath {
		return false
	}

	for _, path := range f.PathNot {
		if path == filepath.Base(fileEvent.Path) || path == fileEvent.Path {
			return false
		}
	}

	var foundExt bool
	if len(f.Extension) == 0 {
		foundExt = true
	}
	for _, ext := range f.Extension {
		if ext == filepath.Ext(fileEvent.Path) {
			foundExt = true
			break
		}
	}
	if !foundExt {
		return false
	}

	for _, ext := range f.ExtNot {
		if ext == filepath.Base(fileEvent.Path) {
			return false
		}
	}

	//TODO: check if magic matches extension

	return true
}

// Method to implement Condition interface. Returns true if it passed filter
func (f AllocFilter) Check(p *Process, event interface{}) bool {
	//? memory allocation apis should save protection, allocation type and size
	apiCall := event.(ApiCallData)
	var (
		size 	 	 uint64
		sizeFound    bool
		allocType    uint32
		typeFound    bool
		protection   uint32
		protectFound bool
	)
	for _, arg := range apiCall.args {
		switch arg.Name {
		case "Size", "SizeOfAlloc", "AllocSize":
			size = binary.LittleEndian.Uint64(arg.RawData)
			sizeFound = true
		case "Type", "AllocType", "AllocationType":
			allocType = ReadDWORDValue(arg.RawData)
			typeFound = true
		case "Protection":
			protection = ReadDWORDValue(arg.RawData)
			protectFound = true
		}
	}

	if sizeFound && (f.sizeMin > size || f.sizeMax < size) {
		return false
	}

	if protectFound {
		var isCorrectProtection bool
		if len(f.Protection) == 0 {
			isCorrectProtection = true
		}
		for _, p := range f.Protection {
			if protect & p != 0 {
				isCorrectProtection = true
				break
			}
		}
		if !isCorrectProtection {
			return false
		}
	
		for _, p := range f.ProtectionNot {
			if protect & p != 0 {
				return false
			}
		}
	}

	if typeFound && f.IsImageSection && (allocType & MEM_IMAGE) != 0 {
		return false
	}
}

// Method to implement Condition interface. Returns true if it passed filter
func (f ProtectFilter) Check(p *Process, event interface{}) bool {
	//? memory protection apis should save old protection and new protection
	apiCall := event.(ApiCallData)
	var (
		oldFound bool
		newFound bool
		oldProtect uint32
		newProtect uint32
	)

	for _, arg := range apiCall.args {
		switch arg.Name {
		case "OldProtect":
			oldProtect = ReadDWORDValue(arg.RawData)
			oldFound = true
		case "NewProtect":
			newProtect = ReadDWORDValue(arg.RawData)
			newFound = true
		}
	}

	if oldFound {
		var found bool
		for _, p := range f.OldProtection {
			if protect & p != 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		//TODO: OldProtectionNot
	}

	if newFound {
		var found bool
		for _, p := range f.NewProtection {
			if protect & p != 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		//TODO: NewProtectionNot
	}
}

// Method to implement Condition interface. Returns true if it passed filter
func (f HandleFilter) Check(p *Process, event interface{}) bool {
	//? only desired access is needed, but likely also target pid
	apiCall := event.(ApiCallData)
	var (
		pathFound bool
		accessFound bool
		targetPath string
		desiredAccess uint32
	)

	for _, arg := range apiCall.args {
		switch arg.Name {
		case "TargetPath", "Path":
			targetPath = ReadAnsiStringValue(arg.RawData)
			pathFound = true
		case "TargetPid", "Pid":
			pid := ReadDWORDValue(arg.RawData)
			path, err := GetProcessExecutable(pid)
			if err != nil {
				red.Log("\n[!] Failed to get path of process %d\n\tError: %v\n", pid, err)
			} else {
				targetPath = path
				pathFound = true
			}
		case "DesiredAccess":
			desiredAccess = ReadDWORDValue(arg.RawData)
			accessFound
		}
	}

	if pathFound {
		var found bool
		if len(f.TargetPath) == 0 {
			found = true
		}
		for _, path := range f.TargetPath {
			
		}
		if !found {
			return false
		}
	}

	if accessFound {

	}
}

// Method to implement Condition interface. Returns true if it passed filter
func (f PTCreationFilter) Check(p *Process, event interface{}) bool {
	//? only creation flags are needed
}

// This function will iterate through startTimes and check if any timeOptions fit into it.
// If none fit, this timeline is not possible and will be removed. The possible timelines are returned
func CheckTimeline(startTimes []int64, timeOptions []int64, timeRange int64) []int64 {
Timelines:
	for i, start := range startTimes {
		for _, time := range timeOptions {
			if start - time <= timeRange {
				// this one is valid
				continue Timelines
			}
		}
		// no option fits the timeline
		startTimes = RemoveSliceMember(startTimes, i)
	}		
	return startTimes
}