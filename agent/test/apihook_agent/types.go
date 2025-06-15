package main

const (
	TM_TYPE_API_CALL       = 0
	TM_TYPE_FILE_EVENT     = 1
	TM_TYPE_REG_EVENT      = 2
	TM_TYPE_TEXT_INTEGRITY = 3

	API_ARG_TYPE_EMPTY   = 0
	API_ARG_TYPE_DWORD   = 1
	API_ARG_TYPE_ASTRING = 2
	API_ARG_TYPE_WSTRING = 3
	API_ARG_TYPE_BOOL    = 4
	API_ARG_TYPE_PTR     = 5

	MAX_API_ARGS     = 10
	API_ARG_MAX_SIZE = 520
	TM_MAX_DATA_SIZE = 5368 - 16

	ACTION_CREATE  = 0
	ACTION_MODIFY  = 1
	ACTION_REMOVE  = 2
	ACTION_MOVE    = 3
	TELEMETRY_PIPE = "\\\\.\\pipe\\vg_tm"
)

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
	Type    uint32
	RawData []byte
}

type ApiCallData struct {
	ThreadId uint32
	DllName  string
	FuncId   uint32
	//	Args     [MAX_API_ARGS]ApiArg
	Args []ApiArg
}

// Match DWORD and BOOL from Windows (both are uint32)
type DWORD uint32
type BOOL uint32

// TELEMETRY_HEADER
type TELEMETRY_HEADER struct {
	PID       DWORD
	Type      DWORD
	TimeStamp int64 // time_t is usually int64 on Windows
}

// FILE_EVENT
type FILE_EVENT struct {
	Path   string
	Action uint32
}

// REG_EVENT
type REG_EVENT struct {
	Path  string
	Value string
}

// TEXT_CHECK
type TEXT_CHECK struct {
	Result bool
	Module string
}

/*// FUNC_CHECK
type FUNC_CHECK struct {
	MismatchCount uint64
	Mismatches    [][]byte
}*/
