package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	yara "github.com/VirusTotal/yara-x/go"
	"github.com/fatih/color"
)

var (
	printLog  = true
	logFile   *os.File
	logName   = "agent.log"
	processes = make(map[int]*Process) // key: pid
	mu        sync.Mutex
	scannerMu sync.Mutex
	scanner   *yara.Scanner
	rules     *yara.Rules
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

	rules, scanner, err := LoadYaraRulesFromFolder("")
	if err != nil {
		color.Red("[!] Failed to load yara rules: %v", err)
	}

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
					color.Red("[!] Failed to perform memory scan: %v", err)
				}
				//TODO: increment yara score, append results to log
				for _, result := range results {
					result.Print()
				}
			}
		case scan := <-tasks:
			switch scan.Type {
			case SCAN_MEMORYSCAN:
				results, err := BasicMemoryScan(uint32(scan.Pid), scanner)
				if err != nil {
					color.Red("[!] Failed to perform memory scan: %v", err)
				}
				//TODO: increment yara score, append results to log
				for _, result := range results {
					result.Print()
				}
			}
		}
	}
}

func main() {
	var (
		wg        sync.WaitGroup
		terminate = make(chan struct{})
		err       error // define because of global var
	)
	logFile, err = os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		color.Red("\n[!] Failed to open log: %v", err)
		//TODO: should you return?
	}
	defer logFile.Close()
	//wg.Add(5)
	wg.Add(3)
	go heartbeatListener(&wg, terminate)
	go telemetryListener(&wg, terminate)
	//go commandListener(&wg) //TODO add terminate
	go PeriodicScanScheduler(&wg, terminate)
	//go HistoryCleaner(&wg, terminate)

	//TODO: banner print

	//TODO: cli loop
	for {
		var input string
		fmt.Printf(" $ ")
		fmt.Scanln(&input)
		args := strings.Split(input, " ")

		switch strings.ToLower(args[0]) {
		case "exit", "quit", "q":
			//TODO: trigger terminate signal
			break
		case "demo":
			if len(args) < 2 {
				color.Red("Not enough args!")
				fmt.Println("Usage: demo <path>")
				continue
			}
		case "scan":
			if len(args) < 3 {
				color.Red("Not enough args!")
				fmt.Println("Usage: scan <static|memory> <path|pid> [type]")
				continue
			}
			switch args[1] {
			case "static", "s":
				StaticScan(args[2], true)
			case "memory", "mem", "m":
				if len(args) > 3 {
					switch args[3] {
					case "basic":
					case "full":
					case "module":
					}
				}
				//TODO: memory scan
			}
		}
	}
	wg.Wait()
}
