package main

import (
	"encoding/binary"
	"unicode/utf16"
)

func ParseApiTelemetryPacket(rawData []byte) ApiCallData {
	var apiCall ApiCallData
	apiCall.ThreadId = binary.LittleEndian.Uint32(rawData[0:4])
	apiCall.DllName = ReadAnsiStringValue(rawData[4 : 64+4])
	apiCall.FuncId = binary.LittleEndian.Uint32(rawData[68 : 68+4])

	counter := 72
	for i := 0; i < MAX_API_ARGS; i++ {
		apiCall.Args = append(apiCall.Args, ApiArg{Type: binary.LittleEndian.Uint32(rawData[counter : counter+4])})
		counter += 8 // 4 byte padding after 4 byte enum
		switch apiCall.Args[i].Type {
		case API_ARG_TYPE_DWORD:
			apiCall.Args[i].RawData = rawData[counter : counter+4]
		case API_ARG_TYPE_ASTRING:
			apiCall.Args[i].RawData = rawData[counter : counter+260]
		case API_ARG_TYPE_WSTRING:
			apiCall.Args[i].RawData = rawData[counter : counter+520]
		case API_ARG_TYPE_BOOL:
			apiCall.Args[i].RawData = rawData[counter : counter+4] // BOOL is uint32
		case API_ARG_TYPE_PTR:
			apiCall.Args[i].RawData = rawData[counter : counter+8]
		}
		counter += 520 // largest union member is wchar_t[260] which is 520 bytes
	}
	return apiCall
}

func ReadAnsiStringValue(data []byte) string {
	n := 0
	for ; n < len(data); n++ {
		if data[n] == 0 {
			break // null terminator
		}
	}
	return string(data[:n])
}

// Converts a []byte (UTF-16 encoded, null-terminated) to a Go string
func ReadWideStringValue(data []byte) string {
	u16s := make([]uint16, 0, len(data)/2)

	for i := 0; i < len(data); i += 2 {
		u16 := uint16(data[i]) | uint16(data[i+1])<<8
		if u16 == 0 {
			break // Null-terminator
		}
		u16s = append(u16s, u16)
	}

	return string(utf16.Decode(u16s))
}

func ReadDWORDValue(rawData []byte) uint32 {
	return binary.LittleEndian.Uint32(rawData)
}

func ReadPointerValue(rawData []byte) uint64 {
	return binary.LittleEndian.Uint64(rawData)
}

func ReadBoolValue(rawData []byte) bool {
	return binary.LittleEndian.Uint32(rawData) == 1
}

// TODO: test this
func ParseFileTelemetryPacket(data []byte) FILE_EVENT {
	var fileEvent FILE_EVENT
	fileEvent.Path = ReadAnsiStringValue(data[0:260])
	fileEvent.Action = ReadDWORDValue(data[260:264])
	return fileEvent
}

// TODO: test this
func ParseRegTelemetryPacket(data []byte) REG_EVENT {
	var regEvent REG_EVENT
	regEvent.Path = ReadAnsiStringValue(data[0:260])
	regEvent.Value = ReadAnsiStringValue(data[260 : 260+260])
	return regEvent
}

// TODO: test this
func ParseTextTelemetryPacket(data []byte) TEXT_CHECK {
	var textCheck TEXT_CHECK
	textCheck.Result = ReadBoolValue(data[0:4])
	textCheck.Module = ReadAnsiStringValue(data[4 : 4+260])
	return textCheck
}
