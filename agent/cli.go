package main

//#include "memscan.h"
import "C"

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/fatih/color"
	"golang.org/x/sys/windows"
)

// list of available commands, for the help command
var cliCommands = []CliCommand{
	{"help", "Print info about available commands"},
	{"exit|quit", "Shut down the entire program (not just CLI)"},
	{"scan <static|memory> <pid> [type]", "Manually launch a scan on a specified target. Static scan can be given a file or process. Memory scan only accepts a PID."},
	{"query <pid> [type]", "Query different types of information about a specified (tracked) process."},
	{"launch|demo <path>", "Manually create a process to be tracked. For demo-purposes pre-callbacks."},
	{"inject|track|attach <pid>", "Start tracking an already running (untracked) process"},
}

func cli_help() {
	//TODO make the print prettier
	for _, cmd := range cliCommands {
		fmt.Printf("%s - %s\n", cmd.Syntax, cmd.Description)
	}
}

// Handle a single command. Take input, parse it, and act on it
// You can launch demo, inject, query info or start scan
// This function takes the input, split into words.
// Return value tells if program should exit. True means exit, false means continue
func cli_parse(tokens []string) bool {
	switch strings.ToLower(tokens[0]) {
	case "help":
		cli_help()

	case "verbose":
		if len(tokens) > 1 {
			if tokens[1] == "off" {
				printLog = false
				return false
			}
		}
		printLog = true

	case "exit", "quit", "q":
		// trigger terminate signal for all routines
		close(terminate)
		return true

	case "scan", "s":
		// scan <static|memory> <pid> [type]
		if len(tokens) < 3 {
			color.Red("\n[!] Not enough args!")
			fmt.Printf("\tUsage: %s <static|memory> <pid|path> [type]\n", tokens[0])
			return false
		}
		scantype := ""
		if len(tokens) > 3 {
			scantype = tokens[3]
		}

		cli_scan(tokens[1], scantype, tokens[2])

	case "query", "get":
		// process info, alerts, telemetry, api history
		// query <pid> [type]
		if len(tokens) < 2 {
			color.Red("\n[!] Not enough args!")
			fmt.Printf("\tUsage: %s <pid> [type]\n", tokens[0])
			return false
		}
		querytype := ""
		if len(tokens) > 2 {
			querytype = tokens[2]
		}

		pid, err := strconv.Atoi(tokens[1])
		if err != nil {
			pid = 0
			querytype = tokens[1]
		}

		fmt.Printf("[debug] pid: %d querytype: %s\n", pid, querytype)
		err = cli_query(pid, querytype)
		if err != nil {
			color.Red("Error: %v", err)
		}

	case "launch", "demo":
		if len(tokens) < 2 {
			color.Red("\n[!] Not enough args!")
			fmt.Printf("\tUsage: %s <path>\n", tokens[0])
			return false
		}
		err := cli_launch(tokens[1])
		if err != nil {
			color.Red("\n[!] Failed to launch %s!", tokens[1])
			fmt.Printf("\tError: %v\n", err)
			return false
		}

	// TODO: test this
	case "inject", "track", "attach":
		if len(tokens) < 2 {
			color.Red("\n[!] Not enough args!")
			fmt.Printf("\tUsage: %s <pid>", tokens[0])
			return false
		}
		pid, err := strconv.Atoi(tokens[1])
		if err != nil {
			color.Red("\n[!] \"%s\" could not be converted to an integer!", tokens[1])
			fmt.Printf("\tError: %v\n", err)
			return false
		}

		_, exists := processes[pid]
		if exists {
			fmt.Printf("[i] Process %d is already being tracked\n", pid)
			return false
		}

		r := C.InjectDll(C.DWORD(pid))
		if r == C.int(0) {
			color.Green("[+] Injected hook successfully")
		}

		//* Register process
		path, err := GetProcessExecutable(uint32(pid))
		if err != nil {
			red.Log("\n[!] Failed to get executable of process %d!\n", pid)
			white.Log("\tError: %v\n", err)
		}

		RegisterProcess(pid, path)

	default:
		color.Red("\n[!] Unknown command, you can see available commands with \"help\"")
		return false
	}
	return false
}

//? For each command, there is a cli_cmd() function to
//? handle it. Outside of this, arg count will be
//? validated, but all other error checks happen within this.

func cli_scan[T string | int](scan string, scantype string, target T) error {
	switch scan {
	case "static", "s":
		StaticScan(target, true)

	case "memory", "mem", "m":
		var pid int
		switch val := any(target).(type) {
		case int:
			pid = val
		default:
			return fmt.Errorf("Invalid PID provided to memory scan: %v", target)
		}
		switch scantype {
		case "basic", "":
			fmt.Printf("[debug] starting basic mem scan\n")
			result, err := BasicMemoryScan(uint32(pid), scanner)
			if err != nil {
				red.Log("\n[!] Failed to perform basic memory scan on process %d!\n", pid)
				white.Log("\tError: %v\n", err)
				return nil // i am only returning errors which are due to improper commandline
			}
			result.Log("basic memory scan", pid)

		case "full":
			result, err := FullMemoryScan(uint32(pid), scanner)
			if err != nil {
				red.Log("\n[!] Failed to perform full memory scan on process %d!\n", pid)
				white.Log("\tError: %v\n", err)
				return nil // i am only returning errors which are due to improper commandline
			}
			result.Log("full memory scan", pid)

		default:
			return fmt.Errorf("Unknown memory scan type: \"%s\"", scantype)
		}
	default:
		return fmt.Errorf("Unknown scan type: %s", scan)
	}
	return nil
}

func cli_query(pid int, querytype string) error {
	// basic: cert + exe, score
	// api calls
	// patterns

	switch querytype {
	case "basic", "info", "": // print basic info
		entry, exists := processes[pid]
		if !exists {
			return fmt.Errorf("Process %d not tracked", pid)
		}
		entry.PrintBasic(pid)
	case "api", "calls": // print tracked api calls that were used
		entry, exists := processes[pid]
		if !exists {
			return fmt.Errorf("Process %d not tracked", pid)
		}
		fmt.Printf("Tracked winapi functions called by process %d:\n", pid)
		for _, data := range entry.APICalls {
			fmt.Printf("*\t%s!%s\n", data.DllName, data.FuncName)
		}
	case "tracked": // list all tracked processes
		fmt.Printf("%d tracked processes\n", len(processes))
		for _, entry := range processes {
			entry.PrintBasic(pid)
		}
	case "matches", "matched", "patterns":
		entry, exists := processes[pid]
		if !exists {
			return fmt.Errorf("Process %d not tracked", pid)
		}
		if len(entry.PatternMatches) == 0 {
			fmt.Printf("No pattern matches found so far with process %d", pid)
			return nil
		}
		for _, match := range entry.PatternMatches {
			// TODO: make an option to not log this to file.
			match.Log()
		}
	default:
		return fmt.Errorf("Unknown query type: \"%s\"", querytype)
	}
	return nil
}

// create process, inject dll, start tracking
func cli_launch(cmdLine string) error {
	//* prepare args for winapi
	utf16cl, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return err
	}

	var (
		si windows.StartupInfo
		pi windows.ProcessInformation
	)
	si.Cb = uint32(unsafe.Sizeof(si))

	err = windows.CreateProcess(
		nil,                        // appname (alternative to cmdline)
		utf16cl,                    // cmdline as utf16 ptr
		nil,                        // ProcessAttributes
		nil,                        // ThreadAttributes
		false,                      // InheritHandles
		windows.CREATE_NEW_CONSOLE, // CreationFlags
		nil,                        // Environment
		nil,                        // CurrentDirectory
		&si,                        // StartupInfo
		&pi,                        // ProcessInformation
	)
	if err != nil {
		return err
	}

	r := C.InjectDll(C.DWORD(pi.ProcessId))
	if r != 0 {
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
		TerminateProcess(int(pi.ProcessId))
		return fmt.Errorf("Failed to inject DLL, error code: %d", r)
	}

	path, err := GetProcessExecutable(pi.ProcessId)
	if err != nil {
		red.Log("\n[!] Failed to get path of process %d! (created from %s)\n", pi.ProcessId, cmdLine)
		white.Log("\tError: %v\n", err)
	}
	RegisterProcess(int(pi.ProcessId), path)
	return nil
}

func (p *Process) PrintBasic(pid int) {
	fmt.Printf("\n[*] Process %d [*]\n", pid)
	fmt.Printf("\tFilepath: %s", p.Path)
	if p.IsSigned {
		color.Green(" (signed)")
	} else {
		fmt.Println(" (NOT signed)")
	}
	fmt.Printf("\tScore: %d/100\n\n", p.TotalScore)
}

func PrintBanner(banner int) {
	switch banner {
	case DUCK_BANNER:
		color.Yellow("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣶⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣶⣦⣄⠀⠀⠀⠀⠀")
		color.Yellow("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀")
		color.Yellow("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⠀")
		color.Yellow("⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣾⣿⣿⣿⣶⣦⣄⠀⠀⠹⣿⣿⣿⠁⠀ ⠈⠉⠛⠁⠀⠀⠀⠀⢀⣤⣶⣾⣿⣿⣿⣶⣦⣄⠀⠀⠹⣿⣿⣿⠁⠀⠀⠈⠉⠛⠁")
		color.Yellow("⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣀⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣀⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀")
		color.Yellow("⠰⣿⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀ ⠰⣿⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀")
		color.Yellow("⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀ ⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀")
		color.Yellow("⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀ ⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀")
		color.Yellow("⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀")
	case TOTORO_BANNER1:
		fmt.Println("⠀⠀⠀⢀⣀⠤⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    ⠀⢀⣀⠤⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      ⠀⢀⣀⠤⣤⣄⠀ ")
		fmt.Println("⠀⣠⣼⣿⣿⣿⣾⣿⠀⠀⣷⡄⠀⣀⣀⣀⡀⣴⠇⠀⠀⠀⠀⠀  ⠀⣠⣼⣿⣿⣿⣾⣿⠀⠀⣷⡄⠀⣀⣀⣀⡀⣴⠇⠀⠀⠀⠀⠀   ⣠⣼⣿⣿⣿⣾⣿⠀⠀⣷⡄⠀⣀⣀⣀⡀⣴⠇⠀⠀⠀⠀⠀   ")
		fmt.Println("⢠⣿⣿⣿⣿⢿⣿⣁⠀⠀⣨⣿⣉⣿⠯⠽⣯⣻⣦⡀⣀⣴⣾⡧  ⢠⣿⣿⣿⣿⢿⣿⣁⠀⠀⣨⣿⣉⣿⠯⠽⣯⣻⣦⡀⣀⣴⣾⡧  ⢠⣿⣿⣿⣿⢿⣿⣁⠀⠀⣨⣿⣉⣿⠯⠽⣯⣻⣦⡀⣀⣴⣾⡧  ")
		fmt.Println("⠈⡿⠿⠟⠋⣵⣽⣿⣷⣶⣿⣧⣄⣀⡀⣀⣀⣤⣾⣿⣿⣿⣿⡇  ⠈⡿⠿⠟⠋⣵⣽⣿⣷⣶⣿⣧⣄⣀⡀⣀⣀⣤⣾⣿⣿⣿⣿⡇  ⠈⡿⠿⠟⠋⣵⣽⣿⣷⣶⣿⣧⣄⣀⡀⣀⣀⣤⣾⣿⣿⣿⣿⡇  ")
		fmt.Println("⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⡿⠛⠉⢉⣁⠀⢀⣀⠉⠙⢿⣿⣿⠁   ⠀⠀⠀⠀⠘⢿⣿⣿⣿⡿⠛⠉⢉⣁⠀⢀⣀⠉⠙⢿⣿⣿⠁   ⠀⠀⠀⠀⠘⢿⣿⣿⣿⡿⠛⠉⢉⣁⠀⢀⣀⠉⠙⢿⣿⣿⠁   ")
		fmt.Println("⠀⠀⠀⠀⠀⠀⠈⢻⣿⡏⠀⠊⢁⣌⠀⠤⠤⠀⠠⡀⠀⢻⠃⠀   ⠀⠀⠀⠀⠀⠈⢻⣿⡏⠀⠊⢁⣌⠀⠤⠤⠀⠠⡀⠀⢻⠃⠀     ⠀⠀⠀⠈⢻⣿⡏⠀⠊⢁⣌⠀⠤⠤⠀⠠⡀⠀⢻⠃⠀    ")
		fmt.Println("⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀    ⠀⠀⠀⠀⠀⢸⣿⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀    ⠀⠀⠀⠀⠀⢸⣿⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀     ")
		fmt.Println("⠀⠀⠀⠀⠀⠀⠀⠘⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀   ⠀⠀⠀⠀⠀⠀⠘⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀    ⠀⠀⠀⠀⠀⠘⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀     ")
		fmt.Println("⠀⠀⠀⠀⠀⠀⠀⠀⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠏⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠏⠀⠀    ⠀⠀⠀⠀⠀⠀⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠏⠀⠀     ")
		fmt.Println("⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣷⣄⠀⠀⠀⠀⠀⠀⢀⣴⠏⠀⠀⠀   ⠀⠀⠀⠀⠀⠀⠀⠘⢿⣷⣄⠀⠀⠀⠀⠀⠀⢀⣴⠏⠀⠀⠀  ⠀⠀⠀  ⠀⠀⠀⠘⢿⣷⣄⠀⠀⠀⠀⠀⠀⢀⣴⠏⠀⠀⠀    ")
		fmt.Println("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣷⣦⣤⣤⣴⣾⠋⠁⠀⠀⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣷⣦⣤⣤⣴⣾⠋⠁⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠀  ⠀⠀⠀⠙⢿⣷⣦⣤⣤⣴⣾⠋⠁⠀⠀⠀⠀   ")

	case POLICE_BANNER:
		fmt.Println("⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀")
		fmt.Println("⠀⠀⠀⠀⠈⣦⣀⠀⣰⣧⢀⣴⡇⠀⠀⢸⣦⡀⣼⣆⠀⣀⣴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣦⣀⠀⣰⣧⢀⣴⡇⠀⠀⢸⣦⡀⣼⣆⠀⣀⣴⠁⠀⠀⠀⠀⠀")
		fmt.Println("⠀⠀⠀⠰⣤⣜⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣣⣤⠆⠀⠀⠀⠀⠀⠀⠀⠰⣤⣜⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣣⣤⠆⠀⠀⠀⠀")
		fmt.Println("⠀⠀⠀⢀⣹⣿⣿⠀⣤⣤⣤⡄⢠⣤⣤⡄⢠⣤⣤⣤⠀⣿⣿⣏⡀⠀⠀⠀⠀⠀⠀⠀⢀⣹⣿⣿⠀⣤⣤⣤⡄⢠⣤⣤⡄⢠⣤⣤⣤⠀⣿⣿⣏⡀⠀⠀⠀⠀")
		fmt.Println("⠀⠐⠚⠛⠛⠻⢿⣀⣿⣿⣿⣧⣼⣿⣿⣧⣼⣿⣿⣿⣀⡿⠟⠛⠛⠓⠂⠀⠀⠀⠐⠚⠛⠛⠻⢿⣀⣿⣿⣿⣧⣼⣿⣿⣧⣼⣿⣿⣿⣀⡿⠟⠛⠛⠓⠂⠀⠀")
		fmt.Println("⠀⠀⠀⠀⠀⢠⡟⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⢻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⢻⡄⠀⠀⠀⠀⠀⠀")
		fmt.Println("⠀⠀⡀⠀⢀⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡀⠀⢀⠀⠀⠀⠀⠀⡀⠀⢀⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡀⠀⢀⠀⠀⠀")
		fmt.Println("⠐⠐⢿⡿⠗⠊⢁⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡈⠑⠺⢿⡿⠂⠀⢿⡿⠗⠊⢁⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡈⠑⠺⢿⡿⠂⠀")
		fmt.Println("⠀⠀⠀⠀⠺⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠗⠀⠀⠀⠀⠀⠀⠺⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠗⠀⠀⠀⠀")
		fmt.Println("⠀⢸⣿⢷⣦⣌⡙⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⢋⣡⣴⡾⣿⡇⠀⠀⠀⢸⣿⢷⣦⣌⡙⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⢋⣡⣴⡾⣿⡇⠀⠀")
		fmt.Println("⠀⠀⣿⠇⠀⠀⠈⢹⣷⣦⠀⣤⣤⣤⣤⣤⣤⣤⣤⠀⣴⣾⡏⠁⠀⠀⠸⣿⠀⠀⣿⠇⠀⠀⠈⢹⣷⣦⠀⣤⣤⣤⣤⣤⣤⣤⣤⠀⣴⣾⡏⠁⠀⠀⠸⣿⠀⠀")
		fmt.Println("⠀⠀⣿⣶⣶⣶⣶⣾⣿⡿⠀⠛⠛⠛⠛⠛⠛⠛⠛⠀⢿⣿⣷⣶⣶⣶⣶⣿⠀⠀⣿⣶⣶⣶⣶⣾⣿⡿⠀⠛⠛⠛⠛⠛⠛⠛⠛⠀⢿⣿⣷⣶⣶⣶⣶⣿⠀⠀")
		fmt.Println("⠀⠀⢹⣷⣤⣤⣤⣼⠟⢡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣷⡌⠻⣧⣤⣤⣤⣾⡏⠀⠀⢹⣷⣤⣤⣤⣼⠟⢡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣷⡌⠻⣧⣤⣤⣤⣾⡏⠀⠀")
		fmt.Println(" ⠀⢰⣶⣶⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⣶⣶⡆⠀⠀ ⠀⢰⣶⣶⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⣶⣶⡆⠀⠀")
		fmt.Println(" ⠀⠈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀ ⠀⠈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀")
	}
	fmt.Printf("\n\t\t\t[ Version: %s ]\n\n", VERSION)
}
