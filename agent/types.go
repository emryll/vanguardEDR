package main

import (
	"bytes"
	"sync"
	"unsafe"
)

type Process struct {
	Path     string
	IsSigned bool
	ApiMu    sync.Mutex
	// this is collected telemetry data history
	APICalls   map[string]ApiCallData   // key: api call name
	FileEvents map[string]FileEventData // key: filepath
	RegEvents  map[string]RegEventData  // key: name of reg key
	// this is the matched patterns that make up the total score
	PatternMatches map[string]*StdResult // key: name of pattern
	//TODO: seperate score and results for static analysis?
	LastHeartbeat int64
	ScoreMu       sync.Mutex
	YaraScore     int
	TotalScore    int
}

type Scan struct {
	Pid  int
	Type int
	Arg  string
}

const (
	MAX_PATH                    = 260 // MAX_PATH from windows.h
	DEFAULT_RULE_DIR            = ".\\rules"
	MEMORYSCAN_INTERVAL         = 45  //sec
	THREADSCAN_INTERVAL         = 45  //sec
	HEARTBEAT_INTERVAL          = 30  //sec
	NETWORKSCAN_INTERVAL        = 180 //sec, 3min
	MAX_HEARTBEAT_DELAY         = HEARTBEAT_INTERVAL * 2
	TM_HISTORY_CLEANUP_INTERVAL = 30 //sec

	SCAN_MEMORYSCAN    = 0 // scan RWX mem and .text of main module
	SCAN_MEMORYSCAN_EX = 1 // scan all sections of all modules
	SCAN_MEMORY_MODULE = 2 // fully scan specific module

	TM_TYPE_EMPTY_VALUE    = 0
	TM_TYPE_API_CALL       = 1
	TM_TYPE_FILE_EVENT     = 2
	TM_TYPE_REG_EVENT      = 3
	TM_TYPE_TEXT_INTEGRITY = 4
	TM_TYPE_HOOK_INTEGRITY = 5

	API_ARG_TYPE_EMPTY   = 0
	API_ARG_TYPE_DWORD   = 1
	API_ARG_TYPE_ASTRING = 2
	API_ARG_TYPE_WSTRING = 3
	API_ARG_TYPE_BOOL    = 4
	API_ARG_TYPE_PTR     = 5

	MAX_API_ARGS     = 10
	API_ARG_MAX_SIZE = 520
	TM_HEADER_SIZE   = 16
	TM_MAX_DATA_SIZE = 67624 - TM_HEADER_SIZE

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
	DataSize  int64
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
	FuncName  string
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
	Result    bool
	Module    string
	TimeStamp int64
}

type FileEventData struct {
	Path      string
	Action    uint32
	TimeStamp int64
	History   []FileEventData
}

func (f FileEventData) GetTime() int64 {
	return f.TimeStamp
}

type RegEventData struct {
	Path      string
	Action    uint32
	Value     string
	TimeStamp int64
	History   []RegEventData
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
	Name        string
	Description string
	Category    []string
	ApiCalls    []ApiFuncs // lets you define all possible options, so can do both kernel32 and nt
	TimeRange   int        // seconds
	Score       int        // actual score for how malicious it is
	Severity    int        // severity only for coloring output: 0(low), 1(medium) or 2(high)
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
	Results    []StdResult
}

// TODO change name to id
type PatternResult struct {
	Name      string
	Score     int   // actual score for how malicious it is
	Severity  int   // severity only for coloring output: 0(low), 1(medium) or 2(high)
	TimeStamp int64 // time of detection, not call
	Count     int
}

func (p PatternResult) GetTime() int64 {
	return p.TimeStamp
}

type MemRegion struct {
	Address unsafe.Pointer
	Size    uint64
}

type RemoteModule struct {
	Name        [260]byte
	NumSections uint64
	Sections    []MemRegion
}

func (m *RemoteModule) GetName() string {
	i := bytes.IndexByte(m.Name[:], 0)
	if i == -1 {
		return string(m.Name[:]) // fallback
	}
	return string(m.Name[:i])
}

// universal type for portraying results
type StdResult struct {
	Name        string   // short name of pattern
	Description string   // what the pattern match means
	Tag         string   // to help portray results; for example "imports"
	Category    []string // for example "evasion"; describes what sort of pattern it was
	Score       int      // actual score for how likely its malicious
	Severity    int      // 0, 1, 2 (low, medium, high); only for colors, doesnt affect anything else
	Count       int
	TimeStamp   int64 // latest
}

type Magic struct {
	Bytes []byte
	Type  string
}

var magicToType = []Magic{
	{[]byte{0x4D, 0x5A}, "DOS MZ / PE File (.exe, .dll, ++)"},
	{[]byte{0x5A, 0x4D}, "DOS ZM legacy executable (.exe)"},
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, "ELF Executable"},
	{[]byte{0x25, 0x50, 0x44, 0x46}, "Zip archive"},
	{[]byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, "SQLite Database"},
	{[]byte{0x00, 0x00, 0x01, 0x00}, "Icon file"},
	{[]byte{0x1F, 0x9D}, "tar archive (Lempel-Ziv-Welch algorithm)"},
	{[]byte{0x1F, 0xA0}, "tar archive (LZH algorithm)"},
	{[]byte{0x2D, 0x6C, 0x68, 0x30, 0x2D}, "Lempel Ziv Huffman archive (method 0, no compression)"},
	{[]byte{0x2D, 0x6C, 0x68, 0x35, 0x2D}, "Lempel Ziv Huffman archive (method 5)"},
	{[]byte{0x42, 0x5A, 0x68}, "Bzip2 archive"},
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, "GIF file"},
	{[]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, "GIF file"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xDB}, "jpg or jpeg"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xEE}, "jpg or jpeg"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xE0}, "jpg or jpeg"},
	{[]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}, "jpg or jpeg"},
	{[]byte{0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A}, "JPEG 2000 format"},
	{[]byte{0xFF, 0x4F, 0xFF, 0x51}, "JPEG 2000 format"},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, "zip file format"},
	{[]byte{0x50, 0x4B, 0x05, 0x06}, "zip file format(empty archive)"},
	{[]byte{0x50, 0x4B, 0x07, 0x08}, "zip file format(spanned archive)"},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, "Roshal ARchive (RAR), >v1.50"},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, "Roshal ARchive (RAR), >v5.00"},
	{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "Portable Network Graphics (PNG) format"},
	{[]byte{0xEF, 0xBB, 0xBF}, "UTF-8 byte order mark (.txt, ++)"},
	{[]byte{0xFF, 0xFE}, "UTF-16LE byte order mark (.txt, ++)"},
	{[]byte{0xFE, 0xFF}, "UTF-16BE byte order mark (.txt, ++)"},
	{[]byte{0xFF, 0xFE, 0x00, 0x00}, "UTF-32LE byte order mark (.txt, ++)"},
	{[]byte{0x00, 0x00, 0xFE, 0xFF}, "UTF-32BE byte order mark (.txt, ++)"},
	{[]byte{0xFE, 0xED, 0xFA, 0xCE}, "Mach-O executable (32-bit)"},
	{[]byte{0xFE, 0xED, 0xFA, 0xCF}, "Mach-O executable (64-bit)"},
	{[]byte{0xCE, 0xFA, 0xED, 0xFE}, "Mach-O executable (reverse-order, 32-bit)"},
	{[]byte{0xCF, 0xFA, 0xED, 0xFE}, "Mach-O executable (reverse-order, 64-bit)"},
	{[]byte{0x25, 0x21, 0x50, 0x53}, "PostScript Document"},
	{[]byte{0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x2D, 0x33, 0x2E, 0x30, 0x20, 0x45, 0x50, 0x53, 0x46, 0x2D, 0x33, 0x2E, 0x30}, "Encapsulated PostScript v3.0"},
	{[]byte{0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x2D, 0x33, 0x2E, 0x31, 0x20, 0x45, 0x50, 0x53, 0x46, 0x2D, 0x33, 0x2E, 0x30}, "Encapsulated PostScript v3.1"},
	{[]byte{0x25, 0x50, 0x44, 0x46, 0x2D}, "PDF Document"},
	{[]byte{0x43, 0x44, 0x30, 0x30, 0x31}, "ISO9660 CD/DVD image file"},
	{[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "Compound File Binary Format (Microsoft Office)"},
	{[]byte{0x43, 0x72, 0x32, 0x34}, "Google Chrome extension or packaged app"},
	{[]byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30}, "tar archive"},
	{[]byte{0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00}, "tar archive"},
	{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7-Zip archive"},
	{[]byte{0x1F, 0x8B}, "GZIP compressed file"},
	{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "XZ compression utility using LZMA2 compression"},
	{[]byte{0x00, 0x61, 0x73, 0x6D}, "WebAssembly binary format"},
	{[]byte{0x49, 0x73, 0x5A, 0x21}, "Compressed ISO image"},
	//TODO: add audio formats
	//TODO: add more executable types
	//TODO: lnk and other common malicious initial vector file types
}

type HashLookup struct {
	Sha256 string
	Status string `json:"query_status"` // ok / hash_not_found
	Data   []struct {
		Signature string   `json:"signature"`
		Tags      []string `json:"tags"`
		YaraRules []struct {
			Name        string `json:"rule_name"`
			Description string `json:"description"`
		} `json:"yara_rules"`
	} `json:"data"`
}
