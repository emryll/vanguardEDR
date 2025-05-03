package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

//TODO: C function to fetch IAT functions

func main() {
	if len(os.Args) > 2 {
		color.Red("You entered too many arguments, you may only enter one file at a time")
	}
	var filepath string

	if len(os.Args) == 1 {
		//TODO: ask for file to analyze
	}
	if len(os.Args) == 2 {
		filepath = os.Args[1]
	}
	_, err := os.Stat(filepath); err != nil {
		color.Red("\n[!] %s could not be found, ensure the path is correct", filepath)
	}
	fmt.Printf("[i] Analyzing %s...\n", filepath)

	//TODO: check hash

	//TODO: check YARA rules

	//TODO: check imported functions

	//TODO: check entropy

	//TODO: check magic

	//TODO: check streams

	//TODO: calculate total score


	//TODO: portray results
}
