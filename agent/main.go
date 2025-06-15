package main

import (
	"sync"
	"time"
)

var processes = make(map[int]Process) // key: pid
//? ^should this be slice instead, do i need map?

// TODO: test
func PeriodicScanScheduler(wg *sync.WaitGroup, terminate chan struct{}) {
	defer wg.Done()
	memoryScan := time.NewTicker(time.Duration(MEMORYSCAN_INTERVAL) * time.Second)
	heartbeat := time.NewTicker(time.Duration(HEARTBEAT_INTERVAL) * time.Second)
	defer memoryScan.Stop()
	defer heartbeat.Stop()

	tasks := make(chan Scan)
	priorityTasks := make(chan Scan)
	const numWorkers = 10
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go PeriodicScanHandler(wg, priorityTasks, tasks, terminate)
	}

	for {
		select {
		case <-terminate:
			close(tasks)
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
					delete(processes, pid)
				}
			}
		}
	}
}

func PeriodicScanHandler(wg *sync.WaitGroup, priorityTasks chan Scan, tasks chan Scan, terminate chan struct{}) {
	defer wg.Done()
	for {
		select {
		case scan := <-priorityTasks: // prioritize unsigned processes
			switch scan.Type {
			case SCAN_MEMORYSCAN:
				MemoryScan(scan.Pid)
			}
		case scan := <-tasks:
			switch scan.Type {
			case SCAN_MEMORYSCAN:
				MemoryScan(scan.Pid)
			}
		}
	}
}

func main() {
	var (
		wg        sync.WaitGroup
		terminate = make(chan struct{})
	)
	wg.Add(4)
	go heartbeatListener(&wg, terminate)
	go telemetryListener(&wg, terminate)
	go commandHandler(&wg, terminate)
	go PeriodicScanScheduler(&wg, terminate)
	wg.Wait()
}
