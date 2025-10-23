package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	yara "github.com/VirusTotal/yara-x/go"
	"github.com/fatih/color"
)

var (
	white       *Color
	green       *Color
	yellow      *Color
	red         *Color
	printLog    = true
	logName     = "agent.log"
	logFile     *os.File
	logger      *log.Logger
	logMu       sync.Mutex
	writer      *DualWriter
	terminate   = make(chan struct{})    // close this to terminate all goroutines
	processes   = make(map[int]*Process) // key: pid
	mu          sync.Mutex
	scannerMu   sync.Mutex
	scanner     *yara.Scanner
	rules       *yara.Rules
	malapi      map[string]MalApi
	apiPatterns []ApiPattern
	frPatterns  []FRPattern // patterns for file system and registry events
)

// TODO: test
func PeriodicScanScheduler(wg *sync.WaitGroup, terminate chan struct{}) {
	defer wg.Done()
	memoryScan := time.NewTicker(time.Duration(MEMORYSCAN_INTERVAL) * time.Second)
	heartbeat := time.NewTicker(time.Duration(HEARTBEAT_INTERVAL) * time.Second)
	defer memoryScan.Stop()
	defer heartbeat.Stop()

	var (
		tasks         = make(chan Scan)
		priorityTasks = make(chan Scan)
	)

	const numWorkers = 10
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go PeriodicScanHandler(wg, priorityTasks, tasks, terminate)
	}

	for {
		select {
		case <-terminate:
			close(tasks)
			close(priorityTasks)
			scanner.Destroy()
			rules.Destroy()
			return
		case <-memoryScan.C:
			go func() { // launch a goroutine to schedule memory scans
				for pid, process := range processes {
					if process.IsSigned {
						tasks <- Scan{Pid: pid, Type: SCAN_MEMORYSCAN}
					} else {
						priorityTasks <- Scan{Pid: pid, Type: SCAN_MEMORYSCAN}
					}
				}
			}()
		case <-heartbeat.C:
			go func() { // launch a goroutine to check each heartbeat
				for pid, process := range processes {
					now := time.Now().Unix()
					if process.LastHeartbeat < (now - MAX_HEARTBEAT_DELAY) {
						TerminateProcess(pid)
						mu.Lock()
						delete(processes, pid)
						mu.Unlock()
					}
				}
			}()
		}
	}
}

func PeriodicScanHandler(wg *sync.WaitGroup, priorityTasks chan Scan, tasks chan Scan, terminate chan struct{}) {
	defer wg.Done()
	for {
		select {
		case <-terminate:
			return
		case scan := <-priorityTasks: // prioritize unsigned processes
			switch scan.Type {
			case SCAN_MEMORYSCAN:
				results, err := BasicMemoryScan(uint32(scan.Pid), scanner)
				if err != nil {
					red.Log("[!] Failed to perform memory scan: %v", err)
				}
				results.Log("basic memory scan", scan.Pid)
				if results.TotalScore > 10 {
					priorityTasks <- Scan{Pid: scan.Pid, Type: SCAN_MEMORYSCAN_FULL}
				}
			}
		case scan := <-tasks:
			switch scan.Type {
			case SCAN_MEMORYSCAN:
				results, err := BasicMemoryScan(uint32(scan.Pid), scanner)
				if err != nil {
					red.Log("[!] Failed to perform memory scan: %v", err)
				}
				results.Log("basic memory scan", scan.Pid)
				if results.TotalScore > 10 {
					priorityTasks <- Scan{Pid: scan.Pid, Type: SCAN_MEMORYSCAN_FULL}
				}
			}
		}
	}
}

func main() {
	var wg sync.WaitGroup

	err := InitializeLogger(logName)
	if err != nil {
		color.Red("\n[!] Failed to initialize logger!")
		fmt.Printf("\tError: %v\n", err)
		return
	}

	defer logFile.Close()
	//wg.Add(5)
	wg.Add(3)
	go heartbeatListener(&wg, terminate)
	go telemetryListener(&wg, terminate)
	//go commandListener(&wg) //TODO add terminate
	go PeriodicScanScheduler(&wg, terminate)
	//go HistoryCleaner(&wg, terminate)

	//? should it be allowed to run without yara ruleset or api patterns?

	//TODO: add option to specify rules directory
	//* load ruleset
	rules, scanner, err = LoadYaraRulesFromFolder("")
	if err != nil {
		red.Log("\n[FATAL] Unable to load yara rules!")
		white.Log("\tError: %v\n", err)
		return
	}

	malapi, err = LoadMaliciousApiListFromDisk("")
	if err != nil {
		red.Log("\n[!] Failed to load malicious API list!")
		white.Log("\tError: %v\n", err)
	}

	apiPatterns, err = LoadApiPatternsFromDisk("")
	if err != nil {
		red.Log("\n[!] Failed to load")
	}
	//TODO: load file patterns
	//TODO: load reg patterns
	// setup for static engine for reading magic bytes
	SortMagic()

	//* cli loop
	PrintBanner(DEFAULT_BANNER)
Cli:
	for {
		select {
		case <-terminate:
			break Cli
		default:
		}
		// main loop code here
		g := color.New(color.FgGreen, color.Bold)
		g.Print(" $ ")
		reader := bufio.NewReader(os.Stdin)
		command, _ := reader.ReadString('\n')
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		tokens := strings.Fields(command)
		exit := cli_parse(tokens)
		if exit {
			break Cli
		}
	}
	wg.Wait()
}
