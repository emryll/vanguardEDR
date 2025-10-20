package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Binject/debug/pe"
	"github.com/fatih/color"
)

// Perform static scan on a file, either by PID or filepath
// Errors will be logged in the function, not returned. It is intended
func StaticScan[T int | string](target T, print bool) {
	var (
		path string
		pid  = 0
	)
	// check if target is path or pid and handle it
	switch v := any(target).(type) {
	case int:
		exe, err := GetProcessExecutable(uint32(v))
		if err != nil {
			color.Red("\n[!] Failed to find executable path of process %d!", v)
			fmt.Printf("\tError: %v\n", err)
		}
		path = exe
		//? only save pid if its a tracked process, for purpose of adding results to process object
		if _, exists := processes[v]; exists {
			pid = v
		}
	case string:
		path = v
	}

	// check if path is valid
	if _, err := os.Stat(path); err != nil {
		color.Red("\n[!] %s could not be found, ensure the path is correct", path)
		fmt.Printf("\tError: %v\n", err)
		return
	}

	//? By this time, yara rules must be loaded (scanner usable),
	//? api patterns loaded and malapi list loaded

	var (
		total           = 0
		isPe            = false
		file            *pe.File
		results         = []StdResult{}
		importedFuncs   = []StdResult{}
		importPatterns  = []StdResult{}
		malimpResults   = []StdResult{}
		proxyDllResults = []StdResult{}
		sectionResults  = []StdResult{}
		yaraResults     = []StdResult{}
		malScore        = 0
		proxyScore      = 0
		sectionScore    = 0
		err             error
	)

	// magicToType was sorted by length in main(), largest first
	maxMagicLen := len(magicToType[0].Bytes)
	magic, err := GetMagic(path, maxMagicLen)
	if err != nil {
		color.Red("\n[!] Failed to read magic bytes of %s!", path)
		fmt.Printf("\tError: %v\n", err)
	}

	mbAuthKey := os.Getenv("MALWAREBAZAAR_KEY")
	if mbAuthKey == "" {
		color.Red("\n[!] Failed to get malwarebazaar API auth key")
		fmt.Println("\tSet MALWAREBAZAAR_KEY environment variable to your API key")
		fmt.Println("\tGet one for free at https://auth.abuse.ch/user/me")
	}

	//* yara scan
	if scanner != nil {
		yaraResults, err = YaraScanFile(scanner, path)
		if err != nil {
			color.Red("\n[!] Failed to perform YARA scan on file!\n\tError: %v", err)
		}
		for _, match := range yaraResults {
			// this is fine even when target is path, because pid variable will be 0,
			// and process 0 is obviously, not going to be tracked. Nothing will happen
			//* log
			if _, matchExists := processes[pid].PatternMatches["STATIC:"+match.Name]; !matchExists {
				mu.Lock()
				processes[pid].PatternMatches["STATIC:"+match.Name] = &match
				processes[pid].StaticScore += match.Score
				processes[pid].TotalScore += match.Score
				mu.Unlock()
			}
			total += match.Score
		}
	}

	if isPe {
		file, err = pe.Open(path)
		if err != nil {
			color.Red("[!] Failed to open %s: %v", path, err)
			return
		}
		defer file.Close()

		if len(apiPatterns) > 0 || len(malapi) > 0 {
			malimpResults, malScore, err = CheckForMaliciousImports(path, file)
			if err != nil {
				color.Red("[!] Failed to check imports!\n\tError: %v", err)
			}
			results = append(results, malimpResults...)
			total += malScore
			//* log
			for _, match := range malimpResults {
				if _, matchExists := processes[pid].PatternMatches["STATIC:"+match.Name]; !matchExists {
					mu.Lock()
					processes[pid].PatternMatches["STATIC:"+match.Name] = &match
					processes[pid].StaticScore += match.Score
					processes[pid].TotalScore += match.Score
					mu.Unlock()
				}
			}
		}
		// this is just to print results in a structured way
		if len(malimpResults) > 0 {
			for _, r := range malimpResults {
				switch r.Tag {
				case "Import":
					importedFuncs = append(importedFuncs, r)
				case "Pattern":
					importPatterns = append(importPatterns, r)
				}
			}
		}

		proxyDllResults, proxyScore, err = CheckForProxyDll(path, file)
		if err != nil {
			color.Red("[!] Failed to check if %s is a proxy DLL!\n\tError: %v", err)
		}
		results = append(results, proxyDllResults...)
		total += proxyScore
		//* log
		for _, match := range proxyDllResults {
			if _, matchExists := processes[pid].PatternMatches["STATIC:"+match.Name]; !matchExists {
				mu.Lock()
				processes[pid].PatternMatches["STATIC:"+match.Name] = &match
				processes[pid].StaticScore += match.Score
				processes[pid].TotalScore += match.Score
				mu.Unlock()
			}
		}
	}

	streamResults, streamScore, err := CheckStreams(path)
	if err != nil {
		color.Red("[!] Failed to check alternative data streams!\n\tError: %v", err)
	}
	results = append(results, streamResults...)
	total += streamScore
	//* log
	for _, match := range streamResults {
		if _, matchExists := processes[pid].PatternMatches["STATIC:"+match.Name]; !matchExists {
			mu.Lock()
			processes[pid].PatternMatches["STATIC:"+match.Name] = &match
			processes[pid].StaticScore += match.Score
			processes[pid].TotalScore += match.Score
			mu.Unlock()
		}
	}

	if isPe {
		sectionResults, sectionScore, err = CheckSections(file)
		if err != nil {
			color.Red("[!] Failed to check sections\n\tError: %v", err)
		}
		results = append(results, sectionResults...)
		total += sectionScore
		//* log
		for _, match := range sectionResults {
			if _, matchExists := processes[pid].PatternMatches["STATIC:"+match.Name]; !matchExists {
				mu.Lock()
				processes[pid].PatternMatches["STATIC:"+match.Name] = &match
				processes[pid].StaticScore += match.Score
				processes[pid].TotalScore += match.Score
				mu.Unlock()
			}
		}
	}

	//* make sure score doesnt exceed maximum
	if total > MAX_STATIC_SCORE {
		total = MAX_STATIC_SCORE
	}
	if processes[pid].StaticScore > MAX_STATIC_SCORE {
		processes[pid].ScoreMu.Lock()
		processes[pid].StaticScore = MAX_STATIC_SCORE
		processes[pid].ScoreMu.Unlock()
	}
	if processes[pid].TotalScore > MAX_PROCESS_SCORE {
		processes[pid].ScoreMu.Lock()
		processes[pid].TotalScore = MAX_PROCESS_SCORE
		processes[pid].ScoreMu.Unlock()
	}

	if pid > 0 {
		processes[pid].StaticScanDone = true
	}

	if print {
		//* portray results
		stars := "***************************************************************************"
		fmt.Printf("\n%s\n", stars)
		if len(yaraResults) > 0 {
			//* less important yara rules
			fmt.Println("\t\t{ YARA-X pattern matches }")
			for _, match := range yaraResults {
				match.Print()
			}
			fmt.Printf("\n%s\n", stars)
		}

		//* imported funcs
		if len(importedFuncs) > 0 {
			fmt.Println("\n\t\t{ Suspicious imported functions }")
			for _, fn := range importedFuncs {
				fn.Print()
			}
			fmt.Printf("\n%s\n", stars)
		}

		//* api patterns
		if len(importPatterns) > 0 {
			fmt.Println("\n\t\t{ Suspicious function patterns }")
			for _, pattern := range importPatterns {
				pattern.Print()
			}
			fmt.Printf("\n%s\n", stars)
		}

		//* streams
		if streamScore > 0 {
			fmt.Println("\n\t\t{ Alternative data streams }")
			for _, stream := range streamResults {
				stream.Print()
			}
			fmt.Printf("\n%s\n", stars)
		}

		//* proxy dll
		if proxyScore > 0 {
			fmt.Println("\n\t\t{ Proxy DLL analysis }")
			for _, result := range proxyDllResults {
				result.Print()
			}
			fmt.Printf("\n%s\n", stars)
		}
		//TODO critical yara rules
		var hl HashLookup
		if mbAuthKey != "" {
			hl, err = LookupFileHash(path, mbAuthKey)
			if err != nil {
				color.Red("\n[!] Failed to lookup file hash: %v", err)
			} else {
				if !hl.IsEmpty() {
					fmt.Println("\n\t\t{ Hash lookup }")
					hl.Print()
					fmt.Printf("\n%s\n", stars)
				}
			}
		}

		//* magic
		fmt.Printf("\n\tMagic bytes: %s\n", magic)

		//* mime type
		mime, err := GetMimeType(path)
		if err != nil {
			color.Red("[!] Failed to get MIME type!\n\tError: %v", err)
		} else {
			fmt.Printf("\tMIME type: %s\n", mime)
		}

		baseName := filepath.Base(path)

		//* check digital cert
		r, err := IsSignatureValid(path)
		if err != nil {
			color.Red("\n[!] Failed to check digital certificate!\n\tError: %v", err)
		} else {
			switch r {
			case 0:
				fmt.Printf("\t%s does not have digital certificate\n\n", baseName)
			case 1:
				color.Green("\t%s has a valid digital certificate\n", baseName)
			case 2:
				color.Red("\t%s has a hash mismatch in digital certificate, indicating tampering!\n", baseName)
			}
		}

		//* total score
		yellow := color.New(color.FgYellow, color.Bold)
		switch {
		case total < 30:
			green := color.New(color.FgGreen)
			green.Printf("\t[*] ")
			fmt.Printf("Total score from static analysis of %s:\n", baseName)
			yellow.Printf("\t\t\t%d", total)
			color.Green("/100, looks quite normal.")
		case total < 50:
			yellow.Printf("\t[*] ")
			fmt.Printf("Total score from static analysis of %s:\n", baseName)
			yellow.Printf("\t\t\t%d", total)
			color.Yellow("/100, moderately suspicious...")
		case total < 70:
			yellow.Printf("\t[*] ")
			fmt.Printf("Total score from static analysis of %s:\n", baseName)
			yellow.Printf("\t\t\t%d", total)
			color.Yellow("/100, looks quite suspicious!")
		case total >= 70:
			red := color.New(color.FgRed, color.Bold)
			red.Printf("\t[*] ")
			fmt.Printf("Total score from static analysis of %s:\n", baseName)
			yellow.Printf("\t\t\t%d", total)
			red.Printf("/100, looks ")
			red.Printf("very suspicious!\n")
		}
	}
}

func LookupFileHash(path string, authKey string) (HashLookup, error) {
	hash, err := ComputeFileSha256(path)
	if err != nil {
		return HashLookup{}, err
	}

	result, err := LookupSha256Hash(hash, authKey)
	if err != nil {
		return HashLookup{}, err
	}

	return result, nil
}

func LookupSha256Hash(hash string, authKey string) (HashLookup, error) {
	/*hash, err := ComputeFileSha256(path)
	if err != nil {
		return false, err
	}*/
	form := url.Values{}
	form.Set("query", "get_info")
	form.Set("hash", hash)

	req, err := http.NewRequest("POST", "https://mb-api.abuse.ch/api/v1/", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return HashLookup{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Key", authKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return HashLookup{}, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return HashLookup{}, err
	}
	var result HashLookup
	err = json.Unmarshal(body, &result)
	if err != nil {
		return HashLookup{}, err
	}
	result.Sha256 = hash
	return result, nil
}

func CheckStreams(path string) ([]StdResult, int, error) {
	var results []StdResult
	total := 0
	streams, err := getAlternateDataStreams(path)
	if err != nil {
		return []StdResult{}, 0, err
	}
	if len(streams) < 2 {
		return []StdResult{}, 0, nil
	}

	for _, stream := range streams {
		//* check for executable alternative data stream
		isPe, err := hasPeMagic(stream)
		if err != nil {
			color.Red("[!] Failed to read %s:%s magic, error: %v", path, stream, err)
		}
		if hasExecutableExtension(stream) || isPe {
			results = append(results, StdResult{Description: "Executable file type in alternative stream", Score: 40, Severity: 2})
			total += 40
			continue
		}

		//* Check entropy of stream
		entropy, err := GetEntropyOfFile(path + ":" + stream)
		if err != nil {
			color.Red("[!] Failed to get entropy of %s!\n\tError: %v", path+":"+stream, err)
		} else {
			if entropy > 7.5 {
				desc := fmt.Sprintf("%s alternative data stream has entropy >7.5 (%f)", stream, entropy)
				results = append(results, StdResult{Description: desc, Score: 25, Severity: 1})
				total += 25
			}
		}

		//* Mark of The Web
		if stream == "Zone.Identifier" {
			zoneId, err := readMotwZoneId(path)
			if err != nil {
				color.Red("[!] Failed to read MOTW of %s, error: %v", path, err)
				continue
			}
			switch zoneId {
			case 0: // local machine
				continue
			case 1: // intranet
				results = append(results, StdResult{Description: "File from intranet", Score: 5, Severity: 0})
				total += 5
			case 2: // trusted site
				results = append(results, StdResult{Description: "File from trusted site", Score: 5, Severity: 0})
				total += 5
			case 3: // internet
				results = append(results, StdResult{Description: "File from the Internet", Score: 15, Severity: 1})
				total += 15
			case 4: // restricted sites
				results = append(results, StdResult{Description: "File from restricted site", Score: 30, Severity: 2})
				total += 30
			}
		} else if stream != ":$DATA" {
			desc := fmt.Sprintf("Unknown alternative data stream %s", stream)
			results = append(results, StdResult{Description: desc, Score: 10})
		}
	}
	return results, total, nil
}

// TODO: test
func CheckForProxyDll(path string, file *pe.File) ([]StdResult, int, error) {
	var (
		results []StdResult
		total   = 0
	)
	isPe, err := hasPeMagic(path)
	if err != nil {
		return []StdResult{}, 0, err
	} else if !isPe {
		return []StdResult{}, -1, fmt.Errorf("%s does not have pe magic\n", path)
	}

	//* check if imports dll of same name
	libs, err := file.ImportedLibraries()
	if err != nil {
		return results, total, err
	}
	baseName := strings.ToLower(filepath.Base(path))
	for _, lib := range libs {
		if strings.ToLower(lib) == baseName {
			results = append(results, StdResult{Description: "Imports library of same name as own, likely proxy DLL", Score: 20, Severity: 1})
			total += 20
			break
		}
	}

	//* check if more than 5 are exported to same name function
	exports, err := file.Exports()
	if err != nil {
		return results, total, err
	}
	fwdCounter := 0
	sameLibName := false
	for _, fn := range exports {
		parts := strings.Split(fn.Forward, ".")
		if len(parts) == 2 {
			if fn.Name == parts[1] {
				fwdCounter++
			}
			if strings.ToLower(parts[0]) == baseName {
				sameLibName = true
			}
		}
	}
	if fwdCounter > 5 {
		desc := fmt.Sprintf("Forward exports %d functions of same name", fwdCounter)
		results = append(results, StdResult{Description: desc, Score: 40, Severity: 2})
		total += 40
		if sameLibName {
			results = append(results, StdResult{Description: "Forward exports to library of same name", Score: 10, Severity: 1})
			total += 10
		}
		return results, total, nil
	}

	// +40, mutually exclusive with the check above
	//* check if more than 3 same name imports as exports
	importsList, err := file.ImportedSymbols()
	if err != nil {
		return results, total, err
	}
	imports := make(map[string]bool)
	impExpCounter := 0
	for _, symbol := range importsList {
		parts := strings.Split(symbol, ":")
		imports[parts[0]] = true
	}

	//* check if same function is in exports and imports
	for _, fn := range exports {
		if imports[fn.Name] {
			impExpCounter++
		}
	}
	if impExpCounter > 3 {
		desc := fmt.Sprintf("Imports and exports %d same functions, likely a proxy DLL", impExpCounter)
		results = append(results, StdResult{Description: desc, Score: 40, Severity: 2})
		total += 40
	}
	return results, total, nil
}

func CheckForMaliciousImports(path string, file *pe.File) ([]StdResult, int, error) {
	var (
		imports           = make(map[string]bool)
		results           []StdResult
		total             = 0
		singleFuncCounter = 0
		singleFuncScore   = 0
	)
	importsList, err := file.ImportedSymbols()
	if err != nil {
		return results, total, err
	}
	//* check individual functions and create map of imports
	for _, fn := range importsList {
		parts := strings.Split(fn, ":")
		imports[parts[0]] = true
		if entry, exists := malapi[parts[0]]; exists {
			//? all functions are added seperately to results, but not added to total yet
			results = append(results, StdResult{Name: entry.Name, Score: entry.Score, Severity: entry.Severity, Tag: "Import", Category: entry.Tag})
			singleFuncScore += entry.Score
			singleFuncCounter++
		}
	}
	if singleFuncScore > 0 {
		if singleFuncScore > MAX_INDIVIDUAL_FN_SCORE {
			singleFuncScore = MAX_INDIVIDUAL_FN_SCORE
		}
		desc := fmt.Sprintf("File imports %d suspicious functions (total score added from imports)", singleFuncCounter)
		results = append(results, StdResult{Description: desc, Score: singleFuncScore, Severity: 1})
		total += singleFuncScore
	}
	//* check api patterns
	patternResults := CheckStaticApiPatterns(imports)
	results = append(results, patternResults.Results...)
	total += patternResults.TotalScore
	return results, total, nil
}

func hasPackerName(name string) bool {
	packerName := map[string]bool{
		".hidden":     true,
		".stub":       true,
		".bootloader": true,
		".loader":     true,
		".upx":        true,
		".upx0":       true,
		".upx1":       true,
		".themida":    true,
		".aspack":     true,
		".fsg":        true,
		".fsg0":       true,
		".fsg1":       true,
		".fsg2":       true,
		".pcmp":       true,
		".text0":      true,
		".text1":      true,
		".mem":        true,
		".kol":        true,
		".koldata":    true,
		".mpress":     true,
		".magma":      true,
		".yoda":       true,
		".encrypted":  true,
		".obfuscated": true,
		".packed":     true,
		".confuserex": true,
	}
	return packerName[strings.ToLower(name)]
}

func isCommonSection(name string) bool {
	commonSections := map[string]bool{
		".text":   true,
		".data":   true,
		".rdata":  true,
		".pdata":  true,
		".xdata":  true,
		".rodata": true,
		".bss":    true,
		".edata":  true,
		".idata":  true,
		".crt":    true,
		".tls":    true,
		".reloc":  true,
	}
	if commonSections[strings.ToLower(name)] {
		return true
	}
	parts := strings.Split(name, "_")
	if parts[0] == ".debug" {
		return true
	}
	return false
}

func CheckSections(file *pe.File) ([]StdResult, int, error) {
	var (
		results          []StdResult
		highEntropyCount = 0
		xSectionCount    = 0
		xSection         = false
		packer           = false
		total            = 0
	)
	for _, section := range file.Sections {
		//* inspect name
		if hasPackerName(section.Name) && !packer {
			desc := fmt.Sprintf("File has section named \"%s\" indicating packer", section.Name)
			results = append(results, StdResult{Description: desc, Score: 35, Severity: 2, Tag: "Packer"})
			total += 35
			packer = true
		}

		//* inspect memory attributes
		if section.Name != ".text" &&
			(section.Characteristics&pe.IMAGE_SCN_CNT_CODE != 0 || section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0) {
			// common section like .rsrc marked as executable is more suspicious
			if isCommonSection(section.Name) && !xSection {
				desc := fmt.Sprintf("%s section set as executable or contains code, highly unusual", section.Name)
				results = append(results, StdResult{Description: desc, Score: 40, Severity: 2})
				total += 40
				xSection = true
			} else {
				xSectionCount++
			}
		}

		//* inspect entropy
		data, err := section.Data()
		if err != nil {
			return results, total, err
		}
		entropy := GetEntropy(data)
		if entropy > 7.5 {
			highEntropyCount++
		}
	}
	if xSectionCount > 0 {
		desc := fmt.Sprintf("Contains %d added sections containing executable memory or marked as code", xSectionCount)
		results = append(results, StdResult{Description: desc, Score: 30, Severity: 2})
		total += 30
	}
	if highEntropyCount > 0 {
		var desc string
		if highEntropyCount == 1 {
			desc = "Contains section with entropy >7.5"
		} else {
			desc = fmt.Sprintf("Contains %d sections with entropy >7.5", highEntropyCount)
		}
		results = append(results, StdResult{Description: desc, Score: 20, Severity: 1})
		total += 20
	}
	return results, total, nil
}
