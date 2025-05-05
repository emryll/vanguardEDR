package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	winio "github.com/Microsoft/go-winio"
	"github.com/fatih/color"
)

type HeartbeatPacket struct {
	PID       uint32
	Heartbeat [260]byte
}

func handleConnection(conn net.Conn) {
	color.Green("[+] Client connected!")

	//	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	for {
		var hb HeartbeatPacket
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

		color.Green("[+] Received %s from %d", heartbeat, hb.PID)
	}
}

func main() {
	pipe := `\\.\pipe\vgrd`

	// create pipe
	l, err := winio.ListenPipe(pipe, nil)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	fmt.Println("[i] Waiting for connection...")

	for {
		// wait for client connection
		conn, err := l.Accept()
		if err != nil {
			color.Red("\n[!] Failed to accept connection: %v", err)
			continue
		}
		defer conn.Close()

		go handleConnection(conn)
	}
}
