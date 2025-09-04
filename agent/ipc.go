package main

//#include "memscan.h"
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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
func heartbeatListener(wg *sync.WaitGroup, terminate chan struct{}) error {
	defer wg.Done()
	l, err := winio.ListenPipe(HEARTBEAT_PIPE, nil)
	if err != nil {
		return err
	}
	defer l.Close()

	fmt.Println("[heartbeat] Waiting for connection...")

	for {
		select {
		case <-terminate:
			fmt.Println("[heartbeat] Exiting listener...")
			return nil
		default:
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("Failed to accept connection: %v", err)
			}

			go heartbeatHandler(conn, wg, terminate)
			wg.Add(1)
		}
	}
}

// handle individual connection
func heartbeatHandler(conn net.Conn, wg *sync.WaitGroup, terminate chan struct{}) {
	defer wg.Done()
	defer conn.Close()
	color.Green("[heartbeat] Client connected!")
	for {
		select {
		case <-terminate:
			return
		default:
			var hb Heartbeat
			err := binary.Read(conn, binary.LittleEndian, &hb)
			if err != nil {
				color.Red("\n[heartbeat] Read error: %v", err)
				//continue
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
				result, err := IsSignatureValid(path)
				if err != nil {
					TerminateProcess(int(hb.Pid))
					continue
				}
				var isSigned bool
				switch result {
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
				mu.Lock()
				processes[int(hb.Pid)] = &Process{Path: path,
					LastHeartbeat: time.Now().Unix(),
					IsSigned:      isSigned,
					APICalls:      make(map[string]ApiCallData),
					FileEvents:    make(map[string]FileEventData),
					RegEvents:     make(map[string]RegEventData)}
				mu.Unlock()
			}
		}
	}
}

// accept connections
func telemetryListener(wg *sync.WaitGroup, terminate chan struct{}) error {
	defer wg.Done()
	l, err := winio.ListenPipe(TELEMETRY_PIPE, nil)
	if err != nil {
		return err
	}
	defer l.Close()

	fmt.Println("[telemetry] Waiting for connection...")

	for {
		select {
		case <-terminate:
			fmt.Println("[telemetry] Exiting listener...")
			return nil
		default:
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("Failed to accept connection: %v", err)
			}

			go telemetryHandler(conn, wg, terminate)
			wg.Add(1)
		}
	}
}

// TODO: add telemetry to specified process' history
// handle individual connection
func telemetryHandler(conn net.Conn, wg *sync.WaitGroup, terminate chan struct{}) {
	defer wg.Done()
	defer conn.Close()
	color.Green("[telemetry] Client connected!")
	for {
		select {
		case <-terminate:
			return
		default:
			//* first read the header to get size and type of data
			var tmHeader TelemetryHeader
			//err := binary.Read(conn, binary.LittleEndian, &tm)
			tmhBuf := make([]byte, TM_HEADER_SIZE)
			_, err := io.ReadFull(conn, tmhBuf)
			if err != nil {
				color.Red("[telemetry] Failed to read telemetry header: %v", err)
				continue
			}
			err = binary.Read(bytes.NewReader(tmhBuf), binary.LittleEndian, &tmHeader)
			if err != nil {
				color.Red("[telemetry] binary.Read failed on buffer: %v", err)
				continue
			}
			/*if n == 0 {
				continue
			}*/
			if tmHeader.Type == TM_TYPE_EMPTY_VALUE {
				continue
			}
			fmt.Printf("pid: %d\ntype: %d\nTimestamp: %d\ndataSize: %d\n", tmHeader.Pid, tmHeader.Type, tmHeader.TimeStamp, tmHeader.DataSize)

			//* now read the actual data which comes after the header
			dataBuf := make([]byte, tmHeader.DataSize)
			_, err = io.ReadFull(conn, dataBuf)
			if err != nil {
				color.Red("[telemetry] Failed to read data of telemetry packet: %v", err)
				continue
			}

			switch tmHeader.Type {
			case TM_TYPE_API_CALL:
				//TODO: log
				//* parse packet and add to process' api call history
				apiCall := ParseApiTelemetryPacket(dataBuf)
				apiCall.TimeStamp = tmHeader.TimeStamp
				processes[int(tmHeader.Pid)].PushToApiCallHistory(apiCall)

				//* debug prints
				fmt.Println("[*] New API telemetry packet")
				fmt.Printf("\n\tTid: 0x%X\n\tFunction: %s!%s\n", apiCall.ThreadId, apiCall.DllName, apiCall.FuncName)
				for i, arg := range apiCall.Args {
					switch arg.Type {
					case API_ARG_TYPE_DWORD:
						fmt.Printf("\tArg #%d (DWORD): %d\n", i, arg.Read())
					case API_ARG_TYPE_ASTRING:
						fmt.Printf("\tArg #%d (ASTRING): %s\n", i, arg.Read())
					case API_ARG_TYPE_WSTRING:
						fmt.Printf("\tArg #%d (WSTRING): %s\n", i, arg.Read())
					case API_ARG_TYPE_BOOL:
						bval := arg.Read().(bool)
						if bval {
							fmt.Printf("\tArg #%d (BOOL): TRUE\n", i)
						} else {
							fmt.Printf("\tArg #%d (BOOL): FALSE\n", i)
						}
					case API_ARG_TYPE_PTR:
						fmt.Printf("\tArg #%d (LPVOID): 0x%X\n", i, ReadPointerValue(arg.RawData[:]))
					}
				}

			case TM_TYPE_TEXT_INTEGRITY:
				textCheck := ParseTextTelemetryPacket(dataBuf)
				if err != nil {
					color.Red("\n[!] Failed to decode TextCheckData: %v", err)
					continue
				}
				if textCheck.Result {
					color.Green("[telemetry] .text integrity check of process %d: TRUE", tmHeader.Pid)
					//TODO: log
				} else {
					//TODO: log
					color.Red("[telemetry] .text integrity check of process %d: FALSE", tmHeader.Pid)
					results, err := MemoryScanEx(tmHeader.Pid, scanner)
					if err != nil {
						color.Red("[!] Failed to run MemoryScanEx on process %d: %v", tmHeader.Pid, err)
					} else if len(results) > 0 {
						//TODO: yara scan got matches; add them somewhere in the process entry
						//TODO: anything else?
					}
				}
			}
		}
	}
}

/*
func commandListener(wg *sync.WaitGroup) error {
	wg.Done()
	l, err := winio.ListenPipe(COMMANDS_PIPE, nil)
	if err != nil {
		return fmt.Errorf("Failed to start command pipe: %v", err)
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			color.Red("\n[!] Failed to accept command pipe connection: %v", err)
			continue
		}
		defer conn.Close()
		go commandHandler(conn, cmdChan, wg)
		wg.Add(1)
	}
}

func commandHandler(conn net.Conn, commands chan Command, wg *sync.WaitGroup) {
	defer wg.Done()
	//* wait for new commands on channel, then pass it to pipe
	for {
		select {
		case cmd := <-commands:
			var cmdBuf [68]byte
			binary.LittleEndian.PutUint32(cmdBuf[0:4], cmd.Pid)
			copy(cmdBuf[4:], cmd.Command[:])

			err := binary.Write(conn, binary.LittleEndian, &cmdBuf)
			if err != nil {
				color.Red("\n[!] Failed to write command to pipe: %v", err)
				return
			}
			color.Green("[cmd] Sent command!")
		}
	}
}
*/
