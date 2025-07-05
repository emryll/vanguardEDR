package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/Binject/debug/pe"

	"github.com/fatih/color"
)

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

func CheckStreams(path string) ([]StaticResult, int, error) {
	var results []StaticResult
	total := 0
	streams, err := getAlternateDataStreams(path)
	if err != nil {
		return []StaticResult{}, 0, err
	}
	if len(streams) < 2 {
		return []StaticResult{}, 0, nil
	}

	for _, stream := range streams {
		//* check for executable alternative data stream
		isPe, err := hasPeMagic(stream)
		if err != nil {
			color.Red("[!] Failed to read %s:%s magic, error: %v", path, stream, err)
		}
		if hasExecutableExtension(stream) || isPe {
			results = append(results, StaticResult{Description: "Executable file type in alternative stream", Score: 40, Severity: 2})
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
				results = append(results, StaticResult{Description: desc, Score: 25, Severity: 1})
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
				results = append(results, StaticResult{Description: "File from intranet", Score: 5, Severity: 0})
				total += 5
			case 2: // trusted site
				results = append(results, StaticResult{Description: "File from trusted site", Score: 5, Severity: 0})
				total += 5
			case 3: // internet
				results = append(results, StaticResult{Description: "File from the Internet", Score: 15, Severity: 1})
				total += 15
			case 4: // restricted sites
				results = append(results, StaticResult{Description: "File from restricted site", Score: 30, Severity: 2})
				total += 30
			}
		} else if stream != ":$DATA" {
			desc := fmt.Sprintf("Unknown alternative data stream %s", stream)
			results = append(results, StaticResult{Description: desc, Score: 10})
		}
	}
	return results, total, nil
}

// TODO: test
func CheckForProxyDll(path string, file *pe.File) ([]StaticResult, int, error) {
	var (
		results []StaticResult
		total   = 0
	)
	isPe, err := hasPeMagic(path)
	if err != nil {
		return []StaticResult{}, 0, err
	} else if !isPe {
		return []StaticResult{}, -1, fmt.Errorf("%s does not have pe magic\n", path)
	}

	//* check if imports dll of same name
	libs, err := file.ImportedLibraries()
	if err != nil {
		return results, total, err
	}
	baseName := strings.ToLower(filepath.Base(path))
	for _, lib := range libs {
		if strings.ToLower(lib) == baseName {
			results = append(results, StaticResult{Description: "Imports library of same name as own, likely proxy DLL", Score: 20, Severity: 1})
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
		results = append(results, StaticResult{Description: desc, Score: 40, Severity: 2})
		total += 40
		if sameLibName {
			results = append(results, StaticResult{Description: "Forward exports to library of same name", Score: 10, Severity: 1})
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
		results = append(results, StaticResult{Description: desc, Score: 40, Severity: 2})
		total += 40
	}
	return results, total, nil
}

func CheckForMaliciousImports(path string, file *pe.File) ([]StaticResult, int, error) {
	var (
		imports           = make(map[string]bool)
		results           []StaticResult
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
		if entry, exists := maliciousApis[parts[0]]; exists {
			//? all functions are added seperately to results, but not added to total yet
			results = append(results, StaticResult{Name: entry.Name, Score: entry.Score, Severity: entry.Severity, Tag: "Import", Category: entry.Tag})
			singleFuncScore += entry.Score
			singleFuncCounter++
		}
	}
	if singleFuncScore > 0 {
		if singleFuncScore > MAX_INDIVIDUAL_FN_SCORE {
			singleFuncScore = MAX_INDIVIDUAL_FN_SCORE
		}
		desc := fmt.Sprintf("File imports %d suspicious functions (total score added from imports)", singleFuncCounter)
		results = append(results, StaticResult{Description: desc, Score: singleFuncScore, Severity: 1})
		total += singleFuncScore
	}
	//* check api patterns
	patternResults, patternTotal := CheckApiPatterns(imports)
	results = append(results, patternResults...)
	total += patternTotal
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

func CheckSections(file *pe.File) ([]StaticResult, int, error) {
	var (
		results          []StaticResult
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
			results = append(results, StaticResult{Description: desc, Score: 35, Severity: 2, Tag: "Packer"})
			total += 35
			packer = true
		}

		//* inspect memory attributes
		if section.Name != ".text" &&
			(section.Characteristics&pe.IMAGE_SCN_CNT_CODE != 0 || section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0) {
			// common section like .rsrc marked as executable is more suspicious
			if isCommonSection(section.Name) && !xSection {
				desc := fmt.Sprintf("%s section set as executable or contains code, highly unusual", section.Name)
				results = append(results, StaticResult{Description: desc, Score: 40, Severity: 2})
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
		results = append(results, StaticResult{Description: desc, Score: 30, Severity: 2})
		total += 30
	}
	if highEntropyCount > 0 {
		var desc string
		if highEntropyCount == 1 {
			desc = "Contains section with entropy >7.5"
		} else {
			desc = fmt.Sprintf("Contains %d sections with entropy >7.5", highEntropyCount)
		}
		results = append(results, StaticResult{Description: desc, Score: 20, Severity: 1})
		total += 20
	}
	return results, total, nil
}

/*
func main() {
	if len(os.Args) < 2 {
		color.Red("[!] Not enough args")
	}
	streams, err := getAlternateDataStreams(os.Args[1])
	if err != nil {
		color.Red("[!] Failed to get ADS, error: %v", err)
		return
	}
	color.Green("[+] Found %d streams", len(streams))
	for _, stream := range streams {
		fmt.Printf("\t%s\n", stream)
		if stream == "Zone.Identifier" {
			id, err := readMotwZoneId(os.Args[1] + ":" + stream)
			if err != nil || id == -1 {
				color.Red("[!] Failed to read MOTW")
				return
			}
			fmt.Printf("\t\tZoneId: %d\n", id)
		}
	}
	r, err := hasPeMagic(os.Args[1])
	if err != nil {
		color.Red("[!] Failed to get magic, error: %v", err)
		return
	}
	if r {
		fmt.Printf("[i] %s has PE magic\n", os.Args[1])
	}

	file, err := pe.Open(os.Args[1])
	if err != nil {
		color.Red("[!] Failed to open parser for %s, error: %v", os.Args[1], err)
		return
	}
	defer file.Close()
	symbols, err := file.ImportedSymbols()
	if err != nil {
		color.Red("[!] Failed to get imported symbols, error: %v", err)
		return
	}
	fmt.Println("Imported symbols:")
	for _, symbol := range symbols {
		fmt.Printf("\t%s\n", symbol)
	}

	exports, err := file.Exports()
	if err != nil {
		color.Red("[!] Failed to get exports, error: %v", err)
		return
	}
	fmt.Println("Exports")
	for _, fn := range exports {
		fmt.Printf("\tName: %s, Forward: %s\n", fn.Name, fn.Forward)
	}

	fmt.Println("Sections")
	for _, section := range file.Sections {
		fmt.Printf("\t%s", section.Name)
		if section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0 {
			fmt.Printf("(executable)")
		}
		if section.Characteristics&pe.IMAGE_SCN_CNT_CODE != 0 {
			fmt.Printf("(code)")
		}
		fmt.Printf("\n")
		data, err := section.Data()
		if err != nil {
			color.Red("[!] Failed to read section, error: %v", err)
			return
		}
		entropy := GetEntropy(data)
		fmt.Printf("\t\t\\==={ Entropy: %f\n", entropy)
	}
}
*/
