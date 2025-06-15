package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unsafe"

	winio "github.com/Microsoft/go-winio"
	"github.com/fatih/color"
)

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

func telemetryHandler(conn net.Conn, wg *sync.WaitGroup) {
	defer conn.Close()
	color.Green("[telemetry] Client connected!")
	for {
		var tm Telemetry
		//fmt.Printf("[i] Telemetry struct size: %d\n", unsafe.Sizeof(tm))
		//fmt.Printf("[i] API call data struct size: %d\n", unsafe.Sizeof(ApiCallData{}))
		/*err := binary.Read(conn, binary.LittleEndian, &tm)
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
		}*/
		buf := make([]byte, unsafe.Sizeof(tm))
		n, err := io.ReadFull(conn, buf)
		if err != nil {
			color.Red("\n[!] Failed to read telemetry pipe: %v", err)
			if err.Error() == "EOF" {
				time.Sleep(time.Second)
			}
		}
		if n == 0 {
			continue
		}
		fmt.Printf("[i] Read %d bytes\n", n)
		r := bytes.NewReader(buf)
		err = binary.Read(r, binary.LittleEndian, &tm)
		if err != nil {
			color.Red("[!] Failed to read contents of telemetry packet into struct: %v", err)
		}

		fmt.Printf("Telemetry header:\n\tPid: %d\n\tType: %d\n\tTimestamp: %d\n\n", tm.Header.Pid, tm.Header.Type, tm.Header.TimeStamp)

		switch tm.Header.Type {
		case TM_TYPE_API_CALL:
			apiCall := ParseApiTelemetryPacket(tm.RawData[:])
			fmt.Printf("Thread Id: %d\nDll name: %s\nFunc Id: %d\n", apiCall.ThreadId, apiCall.DllName, apiCall.FuncId)
			fmt.Println("Function args:")
			for i, arg := range apiCall.Args {
				switch arg.Type {
				case API_ARG_TYPE_DWORD:
					fmt.Printf("\t#%d: Type: DWORD, value: %d\n", i, ReadDWORDValue(arg.RawData))
				case API_ARG_TYPE_ASTRING:
					fmt.Printf("\t#%d: Type: ANSI string, value: %s\n", i, ReadAnsiStringValue(arg.RawData))
				case API_ARG_TYPE_WSTRING:
					fmt.Printf("\t#%d: Type: Wide string, value: %s\n", i, ReadWideStringValue(arg.RawData))
				case API_ARG_TYPE_BOOL:
					fmt.Printf("\t#%d: Type: BOOL, value: %t\n", i, ReadBoolValue(arg.RawData))
				case API_ARG_TYPE_PTR:
					fmt.Printf("\t#%d: Type: Pointer, value: 0x%X\n", i, ReadPointerValue(arg.RawData))
				}
			}

		}
	}
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)
	go telemetryListener(&wg)
	wg.Wait()
}
