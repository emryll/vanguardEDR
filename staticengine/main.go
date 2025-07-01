package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

//TODO: C function to fetch IAT functions

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
	path := os.Args[1]
	_, err := os.Stat(path); err != nil {
		color.Red("\n[!] %s could not be found, ensure the path is correct", path)
		return
	}
	fmt.Printf("[i] Analyzing %s...\n", path)
	var (
		total = 0
		results []StaticResult{}
		importedFuncs []StaticResult{}
		importPatterns []StaticResult{}
		
	)

	//TODO: check magic
	//TODO: check hash
	//TODO: check YARA rules

	//TODO: read api pattern rules
	//TODO: read malapi list

	file, err := pe.Open(path)
	if err != nil {
		color.Red("[!] Failed to open %s: %v", path, err)
		return
	}
	defer file.Close()

	if len(apiPatterns) > 0 || len(maliciousApis) > 0 { 
		malimpResults, malScore, err := CheckForMaliciousImports(path, file)
		if err != nil {
			color.Red("[!] Failed to check imports!\n\tError: %v", err)
		}
		results = append(results, malimpResults...)
		total += malScore
	}

	proxyDllResults, proxyScore, err := CheckForProxyDll(path, file)
	if err != nil {
		color.Red("[!] Failed to check if %s is a proxy DLL!\n\tError: %v", err)
	}
	results = append(results, proxyDllResults...)
	total += proxyScore

	streamResults, streamScore, err := CheckStreams(path)
	if err != nil {
		color.Red("[!] Failed to check alternative data streams!\n\tError: %v", err)
	}
	results = append(results, streamResults...)
	total += streamScore

	sectionResults, sectionScore, err := CheckSections(file)
	if err != nil {
		color.Red("[!] Failed to check sections\n\tError: %v", err)
	}
	results = append(results, sectionResults...)
	total += sectionScore

	if total > 100 {
		total = 100
	}
	//* portray results
	starts := "****************************************************************"
	
	//TODO less important yara rules

	//* imported funcs
	if len(importedFuncs) > 0 {
		fmt.Println("\t{ Suspicious imported functions }")
		for _, fn := range importedFuncs {
			fn.Print()
		}
		fmt.Println(stars)
	}

	//* api patterns
	if len(importPatterns) > 0 {
		fmt.Println("\t{ Suspicious function patterns }")
		for _, pattern := range importPatterns {
			pattern.Print()
		}
		fmt.Println(stars)
	}

	//* streams
	if streamScore > 0 {
		fmt.Println("\t{ Alternative data streams }")
		for _, stream := range streamResults {
			stream.Print()
		}
		fmt.Println(stars)
	}

	//* proxy dll
	if proxyScore > 0 {
		fmt.Println("\t{ Proxy DLL analysis }")
		for _, result := range proxyDllResults {
			result.Print()
		fmt.Println(stars)
		}
	}
	//TODO critical yara rules
	//TODO hash lookup

	//* total score
	switch {
	case total < 30:
		green := color.New(color.FgGreen, color.Bold)
		color.Green("\t[*] Total score from static analysis of %s:")
		green.Printf("\t\t\t%d", total)
		color.Green("/100, looks quite normal.")
	case total < 50:
		yellow := color.New(color.FgYellow, color.Bold)
		color.Yellow("\t[*] Total score from static analysis of %s:")
		yellow.Printf("\t\t\t%d", total)
		color.Yellow("/100, moderately suspicious...")
	case total < 70:
		yellow := color.New(color.FgYellow, color.Bold)
		color.Yellow("\t[*] Total score from static analysis of %s:")
		yellow.Printf("\t\t\t%d", total)
		color.Yellow("/100, looks quite suspicious!")
	case total >= 70:
		red := color.New(color.FgRed, color.Bold)
		color.Red("\t[*] Total score from static analysis of %s:")
		red.Printf("\t\t\t%d", total)
		color.Red("/100, looks ")
		red.Printf("very suspicious\n!")
	}
}
