package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/fatih/color"
)

func (r StdResult) Log() {
	switch r.Severity {
	case 0:
		green.Log("[*] ")
		if r.Name == "" {
			white.Log("%s ", r.Description) //text in white so its easier to read
			green.Log("(+%d)\n", r.Score)
		} else {
			white.Log("%s ", r.Name) //text in white so its easier to read
			green.Log("(+%d)\n", r.Score)
			if r.Description != "" {
				green.Log("\t[?] ")
				white.Log("%s\n", r.Description)
			}
		}
	case 1:
		yellow.Log("[*] ")
		if r.Name == "" {
			white.Log("%s ", r.Description)
			yellow.Log("(+%d)\n", r.Score)
		} else {
			white.Log("%s ", r.Name)
			yellow.Log("(+%d)\n", r.Score)
			if r.Description != "" {
				yellow.Log("\t[?] ")
				white.Log("%s\n", r.Description)
			}
		}
	case 2:
		red.Log("[*] ")
		if r.Name == "" {
			white.Log("%s ", r.Description)
			red.Add(color.Bold)
			red.Log("(+%d)\n", r.Score)
		} else {
			white.Log("%s ", r.Name)
			red.Add(color.Bold)
			red.Log("(+%d)\n", r.Score)
			if r.Description != "" {
				white.Log("\t[?] %s\n", r.Description)
			}
		}
	default:
		red.Log("[!] Invalid severity value in YARA rule (%d), must be 0(low), 1(medium) or 2(high)", r.Severity)
		white.Log("[*] ")
		if r.Name == "" {
			white.Log("%s (+%d)\n", r.Description, r.Score)
		} else {
			white.Log("%s (+%d)\n", r.Name, r.Score)
			if r.Description != "" {
				white.Log("\t[?] %s\n", r.Description)
			}
		}
	}
	if len(r.Category) > 0 {
		white.Log("\tCategory: ")
		for i, t := range r.Category {
			white.Log("%s", t)
			if len(r.Category) > i+1 {
				white.Log(", ")
			}
		}
		white.Log("\n")
	}
}

// This method will log telemetry packet to file on disk (logFile), add it to process history,
// and print it out if printLog is enabled. It will also launch further action if needed
func (header TelemetryHeader) Log(dataBuf []byte) {
	switch header.Type {
	case TM_TYPE_EMPTY_VALUE:
		return
	case TM_TYPE_API_CALL:
		white.Log("\n\nPID: %d, new API call\n", header.Pid)

		//* Parse packet and add to process' API call history
		apiCall := ParseApiTelemetryPacket(dataBuf, header.TimeStamp)
		if _, exists := processes[int(header.Pid)]; !exists {
			if header.Pid <= 0 || header.Pid > 1000000 {
				return
			}

			var signed bool
			path, err := GetProcessExecutable(uint32(header.Pid))
			if err != nil {
				red.Log("\n[!] Failed to get executable path of process %d", header.Pid)
				white.Log("\tError: %v\n", err)
			} else {
				signedstatus, err := IsSignatureValid(path)
				if err != nil {
					red.Log("\n[!] Failed to check digital certificate!")
					white.Log("\tError: %v\n", err)
				} else {
					switch signedstatus {
					case IS_UNSIGNED:
						signed = false
					case HASH_MISMATCH:
						red.Log("\n[!] Hash mismatch in process %d!", header.Pid)
						TerminateProcess(int(header.Pid))
					case HAS_SIGNATURE:
						signed = true
					}
				}
			}
			processes[int(header.Pid)] = &Process{
				Path:           path,
				IsSigned:       signed,
				APICalls:       make(map[string]ApiCallData),
				FileEvents:     make(map[string]FileEventData),
				RegEvents:      make(map[string]RegEventData),
				PatternMatches: make(map[string]*StdResult),
			}
		}
		mu.Lock()
		processes[int(header.Pid)].PushToApiCallHistory(apiCall)
		mu.Unlock()

		white.Log("\t[TID: %d] %s!%s:\n", apiCall.ThreadId, apiCall.DllName, apiCall.FuncName)
		//* Log the args
		for i, arg := range apiCall.Args {
			switch arg.Type {
			case API_ARG_TYPE_EMPTY:
				continue
			case API_ARG_TYPE_DWORD:
				white.Log("\tArg #%d (DWORD): %d\n", i, arg.Read())
			case API_ARG_TYPE_ASTRING:
				white.Log("\tArg #%d (ASTRING): %s\n", i, arg.Read())
			case API_ARG_TYPE_WSTRING:
				white.Log("\tArg #%d (WSTRING): %s\n", i, arg.Read())
			case API_ARG_TYPE_PTR:
				white.Log("\tArg #%d (LPVOID): 0x%X\n", i, arg.Read())
			case API_ARG_TYPE_BOOL:
				bval := arg.Read().(bool) //? ^probably need to do this cast with all of them
				if bval {
					white.Log("\tArg #%d (BOOL): TRUE\n", i)
				} else {
					white.Log("\tArg #%d (BOOL): FALSE\n", i)
				}
			}
		}

	case TM_TYPE_TEXT_INTEGRITY: //TODO: maybe only log hash mismatches
		white.Log("\n\nPID: %d, new .text integrity check\n", header.Pid)

		//* Parse and log result of check
		textCheck := ParseTextTelemetryPacket(dataBuf)
		if textCheck.Result { // true means the integrity remains, its fine
			white.Log("\tModule \"%s\" integrity: TRUE\n", textCheck.Module)
		} else { // hash mismatch
			red.Log("\tModule \"%s\" integrity: FALSE\n", textCheck.Module)
			go func() { // goroutine so memscan does not block execution
				results, err := MemoryScanEx(header.Pid, scanner)
				if err != nil {
					red.Log("\n[!] Failed to launch MemoryScanEx on process %d: %v\n", header.Pid, err)
				} else if results.TotalScore > 0 {
					go results.Log("MemoryScanEx", int(header.Pid)) // goroutine to not block execution, self-explanatory func
				}
			}()
		}
		//TODO: case TM_TYPE_FILE_EVENT:
		//TODO: case TM_TYPE_REG_EVENT:
	}
	//* Add a line after the log
	white.Log("\n")
}

// Process and log results. Launch further actions or alerts if needed
func (r Result) Log(scanName string, pid int) {
	white.Log("\n\nGot %d total score from %s (%d matches)\n", r.TotalScore, scanName, len(r.Results))

	_, pidExists := processes[pid]
	if pidExists {
		processes[pid].ScoreMu.Lock()
		processes[pid].TotalScore += r.TotalScore
		processes[pid].ScoreMu.Unlock()
	}
	//TODO: check if score exceeds thresholds, make a function for this

	//TODO: if m.Severity is severe, trigger an alert
	for _, m := range r.Results {
		t := time.Unix(m.TimeStamp, 0)
		formatted := t.Format("15:04:05")

		var name string
		if m.Name == "" {
			name = m.Description
		} else {
			name = m.Name
		}
		white.Log("[%s] %s (+%d)\n", formatted, name, m.Score)
		if m.Description != "" {
			white.Log("\t[?] %s\n", m.Description)
		}
		if len(m.Category) > 0 {
			categories := "\tCategory: "
			for i, c := range m.Category {
				categories += c
				if len(m.Category) > i+1 {
					categories += ", "
				}
			}
			categories += "\n"
			white.Log(categories)
		}
		//* update process' history
		if pidExists {
			mu.Lock()
			_, exists := processes[pid].PatternMatches[name]
			if exists {
				processes[pid].PatternMatches[name].Count++
			} else {
				processes[pid].PatternMatches[name] = &m
			}
			mu.Unlock()
		}
	}
	white.Log("\n\n")
}

// Initialize a color that can be used with custom log method
func NewColor(c *color.Color) *Color {
	return &Color{Color: c}
}

// Initialize everything. After this you can just call Color's Log method
func InitializeLogger(logPath string) error {
	var err error
	logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	writer = &DualWriter{
		file:   logFile,
		stdout: os.Stdout,
		print:  printLog,
	}

	logger = log.New(writer, "", log.LstdFlags|log.Lshortfile)

	white = NewColor(color.New())
	red = NewColor(color.New(color.FgRed))
	green = NewColor(color.New(color.FgGreen, color.Bold))
	yellow = NewColor(color.New(color.FgYellow, color.Bold))
	return nil
}

// required method for writer interface. Write to log file
func (w *DualWriter) Write(p []byte) (int, error) {
	n, err := w.file.Write(p)
	if err != nil {
		return n, err
	}
	return n, nil
}

// Log to file and optionally also print it, with color
func (c *Color) Log(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	// write to file
	logMu.Lock()
	logger.Output(2, msg)

	if printLog {
		if c != nil {
			c.Print(msg)
		} else {
			fmt.Print(msg)
		}
	}
	logMu.Unlock()
}
