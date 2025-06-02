package main

const (
	MEMORYSCAN_INTERVAL  = 45000  //ms
	THREADSCAN_INTERVAL  = 45000  //ms
	HEARTBEAT_INTERVAL   = 30000  //ms
	NETWORKSCAN_INTERVAL = 180000 //ms, 3min

	TM_TYPE_API_CALL       = 0
	TM_TYPE_FILE_EVENT     = 1
	TM_TYPE_REG_EVENT      = 2
	TM_TYPE_TEXT_INTEGRITY = 3

	API_ARG_TYPE_DWORD   = 0
	API_ARG_TYPE_ASTRING = 1
	API_ARG_TYPE_WSTRING = 2
	API_ARG_TYPE_BOOL    = 3
	API_ARG_TYPE_PTR     = 4

	MAX_API_ARGS     = 10
	API_ARG_MAX_SIZE = 520
	TM_MAX_DATA_SIZE = 520
)

type Heartbeat struct {
	Pid       uint32
	Heartbeat [64]byte
}

type Command struct {
	Pid     uint32
	Command [64]byte
}

type TelemetryHeader struct {
	Pid       uint32
	Type      uint32
	TimeStamp int64
}

type Telemetry struct {
	Header  TelemetryHeader
	RawData [TM_MAX_DATA_SIZE]byte
}

type ApiArg struct {
	Type    int
	RawData [API_ARG_MAX_SIZE]byte
}

type ApiCallData struct {
	ThreadId uint32
	DllName  [260]byte
	FuncName [260]byte
	args     [MAX_API_ARGS]ApiArg
}

type TextCheckData struct {
	Result
}

type FileEventData struct {
}

type RegEventData struct {
}
