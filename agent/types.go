package main

type Process struct {
	Path           string
	LastHeartbeat  int64
	IsSigned       bool
	APICalls       map[string]ApiCallData   // key: api call name
	FileEvents     map[string]FileEventData // key: filepath
	RegEvents      map[string]RegEventData  // key: name of reg key
	PatternMatches map[string]PatternResult
	TotalScore     int
}

type Scan struct {
	Pid  int
	Type int
	Arg  string
}

const (
	MEMORYSCAN_INTERVAL  = 45  //sec
	THREADSCAN_INTERVAL  = 45  //sec
	HEARTBEAT_INTERVAL   = 30  //sec
	NETWORKSCAN_INTERVAL = 180 //sec, 3min
	MAX_HEARTBEAT_DELAY  = HEARTBEAT_INTERVAL * 2

	SCAN_MEMORYSCAN    = 0 // scan RWX, .text of main module
	SCAN_MEMORYSCAN_EX = 1 // scan all sections of all modules
	SCAN_MEMORY_MODULE = 2 // fully scan specific module

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

	IS_UNSIGNED   = 0
	HAS_SIGNATURE = 1
	HASH_MISMATCH = 2

	FILE_ACTION_DELETE = 0
	FILE_ACTION_MODIFY = 1 << 0
	FILE_ACTION_CREATE = 1 << 1
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

type History[T any] interface {
	GetTime() int64
	HistoryPtr() *[]T
}

type ApiCallData struct {
	ThreadId  uint32
	DllName   string
	FuncId    int
	TimeStamp int64
	Args      []ApiArg      // important ones max 3
	History   []ApiCallData // sorted by timestamp
}

func (a ApiCallData) GetTime() int64 {
	return a.TimeStamp
}

func (a ApiCallData) HistoryPtr() *[]ApiCallData {
	return &a.History
}

type TextCheckData struct {
	Result
}

type FileEventData struct {
	TimeStamp int64
	History   []FileEventData
}

func (f FileEventData) GetTime() int64 {
	return f.TimeStamp
}

type RegEventData struct {
	TimeStamp int64
}

func (r RegEventData) GetTime() int64 {
	return r.TimeStamp
}

// TODO: use ints for memory efficiency and faster comparison?
type ApiFuncs struct {
	Funcs []string //  use ids instead with bit manipulation for memory efficiency
}

// TODO change name to id
type ApiPattern struct {
	Name      string
	ApiCalls  []ApiFuncs // lets you define all possible options, so can do both kernel32 and nt
	TimeRange int        // seconds
	Severity  int
}

// TODO change name to id
type FilePattern struct {
	Name     string
	Path     []string // make into map?
	Action   int      // can be multiple, check with &
	Severity int
}

// TODO change name to id
type RegPattern struct {
	Name     string
	Path     string
	Value    string
	Severity string
}

type Result struct {
	TotalScore int
	Results    []PatternResult
}

// TODO change name to id
type PatternResult struct {
	Name      string
	Severity  int
	TimeStamp int64 // time of detection, not call
	Count     int
}

func (p PatternResult) GetTime() int64 {
	return p.TimeStamp
}
