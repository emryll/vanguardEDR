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

type HEARTBEAT struct {
	Pid       uint32
	Heartbeat [260]byte
}

type COMMAND struct {
	Pid     uint32
	Command [64]byte
}

const TM_MAX_DATA_SIZE = 520

type TELEMETRY_HEADER struct {
	Pid       uint32
	Type      uint32
	TimeStamp int64
}

type TELEMETRY struct {
	Header  TELEMETRY_HEADER
	RawData [TM_MAX_DATA_SIZE]byte
}

type TextCheckData struct {
	Result int32 // BOOL
}

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
		var hb HEARTBEAT
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

// handle individual connection
func telemetryHandler(conn net.Conn, wg *sync.WaitGroup) {
	defer conn.Close()
	color.Green("[telemetry] Client connected!")
	for {
		var tm TELEMETRY
		err := binary.Read(conn, binary.LittleEndian, &tm)
		if err != nil {
			color.Red("\n[!] Failed to read telemetry pipe: %v", err)
			if err.Error() == "EOF" {
				time.Sleep(time.Duration(1) * time.Second)

				err = binary.Read(conn, binary.LittleEndian, &tm)
				if err.Error() == "EOF" {
					fmt.Println("[i] Encountered EOF again, shutting connection...")
					return
				}
			}
			continue
		}
		switch tm.Header.Type {
		case 3: //.text integrity check
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
				color.Green("[telemetry] .text integrity check of process %d: FALSE", tm.Header.Pid)
			}
		}
	}
}

func commandHandler(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	time.Sleep(time.Second * time.Duration(60))
	cmd := "exit"
	var cmdBuf [64]byte
	copy(cmdBuf[:], cmd)

	command := COMMAND{
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

func main() {
	var wg sync.WaitGroup
	// launch pipe listeners, creating the pipes
	go heartbeatListener(&wg)
	go telemetryListener(&wg)
	wg.Add(2)

	// create command pipe, wait for connections and launch handler
	l, err := winio.ListenPipe(COMMANDS_PIPE, nil)
	if err != nil {
		color.Red("\n[!] Failed to start command pipe: %v", err)
	} else {
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				color.Red("\n[!] Failed to accept command pipe connection: %v", err)
				continue
			}
			defer conn.Close()
			go commandHandler(conn, &wg)
			wg.Add(1)
		}
	}
	wg.Wait()
}
