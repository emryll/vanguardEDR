package main

import (
	"sync"
	"time"

	yara "github.com/VirusTotal/yara-x/go"
	"github.com/fatih/color"
)

var (
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
			for pid, process := range processes {
				if process.IsSigned {
					tasks <- Scan{Pid: pid, Type: SCAN_MEMORYSCAN}
				} else {
					priorityTasks <- Scan{Pid: pid, Type: SCAN_MEMORYSCAN}
				}
			}
		case <-heartbeat.C:
			now := time.Now().Unix()
			for pid, process := range processes {
				if process.LastHeartbeat < (now - MAX_HEARTBEAT_DELAY) {
					TerminateProcess(pid)
					mu.Lock()
					delete(processes, pid)
					mu.Unlock()
				}
			}
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
	)
	//wg.Add(5)
	wg.Add(2)
	go heartbeatListener(&wg, terminate)
	go telemetryListener(&wg, terminate)
	//go commandListener(&wg) //TODO add terminate
	//go PeriodicScanScheduler(&wg, terminate)
	//go HistoryCleaner(&wg, terminate)
	wg.Wait()
}
