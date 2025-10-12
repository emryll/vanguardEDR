package main

import (
  "fmt"
  "strings"
  "github.com/fatih/color"
)

// Handle a single command. Take input, parse it, and act on it
// You can launch demo, inject, query info or start scan
func cli_parse(tokens string) {
  switch strings.ToLower(tokens[0]) {
  case "help":
    //TODO print help
  case "exit", "quit", "q":
    //TODO trigger terminate signal
    break
  case "scan", "s":
  // scan <static|memory> <pid> [type]
    if len(tokens) < 3 {
      color.Red("\n[!] Not enough args!")
      fmt.Printf("\tUsage: %s <static|memory> <pid> [type]\n", tokens[0])
    }
    type := ""
    if len(tokens) > 3 {
      type = tokens[3]
    }

    cli_scan(tokens[1], type, tokens[2])

  case "query", "get":
  // process info, alerts, telemetry, api history
  // query <pid> [type]
    if len(tokens) < 2 {
      color.Red("\n[!] Not enough args!")
      fmt.Printf("\tUsage: %s <pid> [type]\n" tokens[0])
      return
    }
    pid, err := strconv.Atoi(tokens[1])
    if err != nil {
      color.Red("\n[!] Failed to convert \"%s\" to integer", tokens[1])
      fmt.Printf("\tError: %v\n", err)
      return
    }

    type := ""
    if len(tokens) > 2 {
      type = tokens[2]
    }

    cli_query(pid, type)

  case "launch", "demo":
    if len(tokens) < 2 {
      color.Red("\n[!] Not enough args!")
      fmt.Printf("\tUsage: %s <path>\n", tokens[0])
      return
    }
    err = cli_launch(tokens[1])
    if err != nil {
      color.Red("\n[!] Failed to launch %s!", tokens[1])
      fmt.Printf("\tError: %v\n", err)
      return
    }

  case "inject", "track", "attach":
    if len(tokens) < 2 {
      color.Red("\n[!] Not enough args!")
      fmt.Printf("\tUsage: %s <pid>", tokens[0])
      return
    }
    pid, err := strconv.Atoi(tokens[1])
    if err != nil {
      color.Red("\n[!] \"%s\" could not be converted to an integer!", tokens[1])
      fmt.Printf("\tError: %v\n", err)
      return
    }
    
    _, exists := processes[pid]
    if exists {
      fmt.Printf("[i] Process %d is already being tracked\n", pid)
      return
    }

    InjectDll(pid)

    //* Register process
    path, err := GetProcessExecutable(uint32(pid))
    if err != nil {
      color.Red("\n[!] Failed to get executable of %d!", pid)
      fmt.Errorf("\tError: %v\n", err)
    }

    RegisterProcess(pid, path)

  default:
    color.Red("\n[!] Unknown command, you can see available commands with \"help\"")
    return
  }
}

//? For each command, there is a cli_cmd() function to
//? handle it. Outside of this, arg count will be
//? validated, but all other error checks happen within this.

func cli_scan[T string|int](scan string, type string, target T) error {
  switch scan {
  case "static", "s":
    //TODO check if target is string or int
  case "memory", "mem", "m":
    switch type {
    case "basic":

    case "full":

    default:
      return fmt.Errorf("Unknown memory scan type: \"%s\"", type)
    }
  default:
    return fmt.Errorf("Unknown scan type: %s", scan)
  }
}

func cli_query(pid int, type string) error {
  // basic: cert + exe, score
  // api calls
  // patterns
  if pid != 0 {
    entry, exists := processes[pid]
    if !exists {
      return fmt.Errorf("Process %d not tracked", pid)
    }
  }

  switch type {
  case "basic", "info", "": // print basic info
    entry.PrintBasic()
  case "api", "calls": // print tracked api calls that were used
    fmt.Printf("Tracked winapi functions called by process %d:\n", pid)
    for _, data := range entry.APICalls {
      fmt.Printf("*\t%s!%s\n", data.DllName, data.FuncName)
    }
  case "tracked": // list all tracked processes
    for id, entry := range processes {
      entry.PrintBasic()
    }
  case "matches", "matched", "patterns":
    for _, match := range entry.PatternMatches {
      match.Print()
    }
  default:
    return fmt.Errorf("Unknown query type: \"%s\"", type)
  }
}

// create process, inject dll, start tracking
func cli_launch(cmdLine string) error {
  //* prepare args for winapi
  utf16cl, err := windows.UTF16PtrFromString(cmdLine)
  if err != nil {
    return err
  }

  var (
    si windows.StartupInfo
    pi windows.ProcessInformation
  )
  si.Cb = uint32(unsafe.Sizeof(si))

  err = windows.CreateProcess(
    nil,     // appname (alternative to cmdline)
    utf16cl, // cmdline as utf16 ptr
    nil,     // ProcessAttributes
    nil,     // ThreadAttributes
    false,   // InheritHandles
    0,       // CreationFlags
    nil,     // Environment
    nil,     // CurrentDirectory
    &si,     // StartupInfo
    &pi,     // ProcessInformation
  )
  if err != nil {
    return err
  }

  err = InjectDll(pi.ProcessId)
  if err != nil {
    windows.CloseHandle(pi.Process)
    windows.CloseHandle(pi.Thread)
    TerminateProcess(int(pi.ProcessId))
    return err
  }

  path, err = GetProcessExecutable(pi.ProcessId)
  if err != nil {
    color.Red("\n[!] Failed to get path of process %d! (created from %s)", pi.ProcessId, cmdLine)
    fmt.Errorf("\tError: %v\n", err)
  }
  RegisterProcess(int(pi.ProcessId), path)
}

func cli_help() {}

func RegisterProcess(pid int, path string) {
  _, exists := processes[pid]
  if exists {
    return
  }

  processes[pid] = &Process{
    Path:           path,
    IsSigned:       IsSigned(path),
    APICalls:       make(map[string]ApiCallData),
    FileEvents:     make(map[string]FileEventData),
    RegEvents:      make(map[string]RegEventData),
    PatternMatches: make(map[string]*StdResult),
  }
  //TODO launch static scan
}

func (p *Process) PrintBasic() {
  fmt.Printf("\n[*] Process %d [*]\n", p)
}
