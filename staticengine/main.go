package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Binject/debug/pe"

	"github.com/fatih/color"
)

//TODO: make results text be white while [*] and (+%d) are colored

func main() {
	if len(os.Args) < 2 {
		color.Red("Not enough arguments!")
		fmt.Printf("[i] Usage: %s <path> [rule dir] [flags]\n\t\"%s help\" for extended info", os.Args[0], os.Args[0])
		return
	} else if os.Args[1] == "help" {
		fmt.Printf("This is a static analysis tool to give a score 0-100 on how likely the file is malware, as well as differentiating where detection comes from")
		cyan := color.New(color.FgCyan, color.Bold)
		cyan.Printf("\tFor full checks you need YARA rules and a list of API patterns and malicious APIs")
		color.Cyan("\t\t+ do \"%s install\" to install default ruleset, or create your own")
		color.Cyan("\t\t(YARA rules need to be *.yara, patterns need to be *.pattern, )\n")
		fmt.Printf("\t[*] Default directory for rules is .\\rules\n\n")
		color.Yellow("\t%s <path> [rule dir]", os.Args[0])
		fmt.Printf("\t- Specify directory to search for rules\n")
	}
	var (
		rulesPath      = ""
		yaraRulesFound = false
		path           = os.Args[1]
	)
	if len(os.Args) > 2 && os.Args[2][0] != '-' {
		rulesPath = os.Args[2]
	}
	if _, err := os.Stat(path); err != nil {
		color.Red("\n[!] %s could not be found, ensure the path is correct(error: %v)", path, err)
		return
	}
	//* get yara rules at .\rules\*.yara
	var yaraResults []StaticResult
	rules, scanner, err := LoadYaraRulesFromFolder(rulesPath)
	if err != nil || rules == nil || scanner == nil {
		color.Red("\n[!] Failed to load YARA rules\n\tError: %v", err)
	} else {
		yaraRulesFound = true
	}
	//* get api patterns at .\rules\*.pattern
	apiPatterns, err = LoadApiPatternsFromDisk(rulesPath)
	if err != nil {
		color.Red("[!] Failed to load API patterns from disk!\n\tError: %v", err)
	}
	fmt.Printf("[i] Loaded %d API patterns\n", len(apiPatterns))
	//* get malicious apis list at .\rules\*.malapi
	maliciousApis, err = LoadMaliciousApiListFromDisk(rulesPath)
	if err != nil {
		color.Red("[!] Failed to load malicious API list from disk!\n\tError: %v", err)
	}
	/*
		//* if no rules found, ask if user wants to install default ruleset
		if !yaraRulesFound && (apiPatterns == nil || len(apiPatterns) == 0) && (malapi == nil || len(malapi) == 0) {
			color.Red("\n[!] No YARA rules, API patterns or malicious API list was found!")
			var answer = "empty"
			for strings.ToLower(answer) != "y" && strings.ToLower(answer) != "n" && answer != "" {
				fmt.Printf("[*] Would you like to install default ruleset? (y/n) ")
				reader := bufio.NewReader(os.Stdin)
				input, err := reader.ReadString('\n')
				if err != nil {
					color.Red("\n[!] Failed to read input!\n\tError: %v", err)
					answer = "n"
				}
				answer = strings.TrimSpace(input)
				fmt.Printf("\n")
				if strings.ToLower(answer) != "y" && strings.ToLower(answer) != "n" && answer != "" {
					color.Red("\tYou entered %s, please enter y for yes or n for no\n", answer)
				}
			}
			if strings.ToLower(answer) == "y" {
				err := InstallDefaultRuleSetFromGithub("")
				if err == nil {
					fmt.Printf("[i] You will have to restart to use the newly installed rules\n\t")
					for _, arg := range os.Args {
						color.Cyan("%s ", arg)
					}
					fmt.Printf("\n")
					return
				} else {
					color.Red("\n[!] Failed to install default ruleset!\n\tError: %v", err)
				}
			}
		}*/

	fmt.Printf("[i] Analyzing %s...\n", path)
	var (
		total           = 0
		isPe            = false
		file            *pe.File
		results         = []StaticResult{}
		importedFuncs   = []StaticResult{}
		importPatterns  = []StaticResult{}
		malimpResults   = []StaticResult{}
		proxyDllResults = []StaticResult{}
		sectionResults  = []StaticResult{}
		malScore        = 0
		proxyScore      = 0
		sectionScore    = 0
	)

	SortMagic()
	maxLen := len(magicToType[0].Bytes)
	magic, err := GetMagic(path, maxLen)
	if err != nil {
		color.Red("\n[!] Failed to get magic bytes of file!\n\tError: %v", err)
	} else if magic == "DOS MZ / PE File (.exe, .dll, ++)" {
		isPe = true
	}

	mbAuthKey := os.Getenv("MALWAREBAZAAR_KEY")
	if mbAuthKey == "" {
		color.Red("\n[!] Failed to get malwarebazaar API auth key")
		fmt.Println("\tSet MALWAREBAZAAR_KEY environment variable to your API key")
		fmt.Println("\tGet one for free at https://auth.abuse.ch/user/me")
	}

	if yaraRulesFound {
		yaraResults, err = YaraScanFile(scanner, path)
		if err != nil {
			color.Red("\n[!] Failed to perform YARA scan on file!\n\tError: %v", err)
		}
		scanner.Destroy()
		rules.Destroy()
		for _, m := range yaraResults {
			total += m.Score
		}
	}

	if isPe {
		file, err = pe.Open(path)
		if err != nil {
			color.Red("[!] Failed to open %s: %v", path, err)
			return
		}
		defer file.Close()

		if len(apiPatterns) > 0 || len(maliciousApis) > 0 {
			malimpResults, malScore, err = CheckForMaliciousImports(path, file)
			if err != nil {
				color.Red("[!] Failed to check imports!\n\tError: %v", err)
			}
			results = append(results, malimpResults...)
			total += malScore
		}
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
	}

	streamResults, streamScore, err := CheckStreams(path)
	if err != nil {
		color.Red("[!] Failed to check alternative data streams!\n\tError: %v", err)
	}
	results = append(results, streamResults...)
	total += streamScore

	if isPe {
		sectionResults, sectionScore, err = CheckSections(file)
		if err != nil {
			color.Red("[!] Failed to check sections\n\tError: %v", err)
		}
		results = append(results, sectionResults...)
		total += sectionScore
	}

	if total > 100 {
		total = 100
	}
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
