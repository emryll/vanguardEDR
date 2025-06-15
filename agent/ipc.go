package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	winio "github.com/Microsoft/go-winio"
	"github.com/fatih/color"
)

var (
	HEARTBEAT_PIPE string = "\\\\.\\pipe\\vgrd_hb"
	TELEMETRY_PIPE string = "\\\\.\\pipe\\vgrd_tm"
	COMMANDS_PIPE  string = "\\\\.\\pipe\\vgrd_cmd"
)

// create pipe, accept connections
func heartbeatListener(wg *sync.WaitGroup) error {
	defer wg.Done()
	l, err := winio.ListenPipe(HEARTBEAT_PIPE, nil)
	if err != nil {
		return err
	}
	defer l.Close()

	fmt.Println("[heartbeat] Waiting for connection...")

	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("Failed to accept connection: %v", err)
		}

		go heartbeatHandler(conn, wg)
		wg.Add(1)
	}
}

// handle individual connection
func heartbeatHandler(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()
	color.Green("[heartbeat] Client connected!")
	for {
		var hb Heartbeat
		err := binary.Read(conn, binary.LittleEndian, &hb)
		if err != nil {
			color.Red("\n[!] Read error: %v", err)
			return
		}

		// Convert C-style string (null-terminated) into Go string
		heartbeat := string(hb.Heartbeat[:])
		if i := bytes.IndexByte(hb.Heartbeat[:], 0); i >= 0 {
			heartbeat = heartbeat[:i]
		}

		color.Green("[heartbeat] Received %s from %d", heartbeat, hb.Pid)
		if p, exists := processes[int(hb.Pid)]; exists {
			p.LastHeartbeat = time.Now().Unix()
		} else {
			color.Green("[+] New process detected (%d)", hb.Pid)
			path, err := GetProcessExecutable(hb.Pid)
			if err != nil {
				TerminateProcess(int(hb.Pid))
				continue
			}
			r, err := IsSignatureValid(path)
			if err != nil {
				TerminateProcess(int(hb.Pid))
				continue
			}
			var isSigned bool
			switch r {
			case IS_UNSIGNED:
				isSigned = false
				fmt.Printf("[i] Process %d with path %s is not signed\n", hb.Pid, path)
			case HAS_SIGNATURE:
				isSigned = true
				color.Green("[+] Process %d with path %s is signed", hb.Pid, path)
			case HASH_MISMATCH:
				color.Red("[!] Signature hash mismatch in %s!", path)
				TerminateProcess(int(hb.Pid))
				continue
			}
			processes[int(hb.Pid)] = Process{Path: path,
				LastHeartbeat: time.Now().Unix(),
				IsSigned:      isSigned,
				APICalls:      make(map[string]ApiCallData),
				FileEvents:    make(map[string]FileEventData),
				RegEvents:     make(map[string]RegEventData)}
		}
	}
}

// accept connections
func telemetryListener(wg *sync.WaitGroup) error {
	defer wg.Done()
	l, err := winio.ListenPipe(TELEMETRY_PIPE, nil)
	if err != nil {
		return err
	}
	defer l.Close()

	fmt.Println("[telemetry] Waiting for connection...")

	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("Failed to accept connection: %v", err)
		}

		go telemetryHandler(conn, wg)
		wg.Add(1)
	}
}

// TODO: add telemetry to specified process' history
// handle individual connection
func telemetryHandler(conn net.Conn, wg *sync.WaitGroup) {
	defer conn.Close()
	color.Green("[telemetry] Client connected!")
	for {
		var tm Telemetry
		err := binary.Read(conn, binary.LittleEndian, &tm)
		if err != nil {
			color.Red("\n[!] Failed to read telemetry pipe: %v", err)
			if err.Error() == "EOF" {
				time.Sleep(time.Duration(1) * time.Second)

				err = binary.Read(conn, binary.LittleEndian, &tm)
				if err != nil {
					if err.Error() == "EOF" {
						fmt.Println("[i] Encountered EOF again, shutting connection...")
						return
					} else {
						color.Red("\n[!] Failed to read telemetry pipe: %v", err)
						continue
					}
				}
			}
			continue
		}
		switch tm.Header.Type {
		case TM_TYPE_API_CALL:
			var apiCall ApiCallData
			buf := bytes.NewReader(tm.RawData[:])
			err := binary.Read(buf, binary.LittleEndian, &apiCall)
			if err != nil {
				color.Red("\n[!] Failed to decode ApiCallData: %v", err)
				continue
			}
			processes[int(tm.Header.Pid)].APICalls[string(apiCall.FuncName)] = 
			
		case TM_TYPE_TEXT_INTEGRITY:
			var textCheck TextCheckData
			buf := bytes.NewReader(tm.RawData[:])
			err := binary.Read(buf, binary.LittleEndian, &textCheck)
			if err != nil {
				color.Red("\n[!] Failed to decode TextCheckData: %v", err)
				continue
			}
			if textCheck.Result == 1 {
				color.Green("[telemetry] .text integrity check of process %d: TRUE", tm.Header.Pid)
			}
			if textCheck.Result == 0 {
				color.Red("[telemetry] .text integrity check of process %d: FALSE", tm.Header.Pid)
				//TODO: launch extensive memory scan
			}
		}
	}
}

// TODO:
func commandHandler(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	//TODO: wait for new commands on channel, then pass it to pipe

	var cmdBuf [64]byte
	copy(cmdBuf[:], cmd)

	command := Command{
		Pid:     0,
		Command: cmdBuf,
	}

	err := binary.Write(conn, binary.LittleEndian, &command)
	if err != nil {
		color.Red("\n[!] Failed to write command to pipe: %v", err)
		return
	}
	color.Green("[cmd] Sent command!")
}
