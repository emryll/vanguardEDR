package main

// experimental v2 design for patterns

type BehaviorPattern struct {
	Name                string
	Description         string
	Categories          []string
	Severity            int
	Score               int
	TimeRange           int
	UniversalConditions *UniversalConditions
	Components          []*Component
}

type Component interface {
	IsMatch(p *Process) ComponentMatch
}

type ComponentMatch struct {
	Match	   bool
	TimeStamps []int64
}

type ApiComponent struct {
	Options 		  []string
	Conditions  	  []Condition
	UniversalOverride *UniversalConditions
	TimeMatters 	  bool
}
type FileComponent struct {
	Action 			  uint32 // enum
	PathOptions 	  []string
	NameOptions []string
	Conditions  	  []Condition
	UniversalOverride *UniversalConditions
	TimeMatters 	  bool
}
type RegComponent struct {

}

type Condition interface {
	// method needs access to required data
	Check(p *Process, event interface{}) bool
}

// "target_process" / "process" conditions
type ProcessFilter struct {
	Name      []string
	NameNot   []string
	Path      []string
	PathNot   []string
	Integrity []int // which integrity levels are needed for a match (enums)
	IsSigned    bool
	IsElevated  bool
}

// "target_file" condition
type FileFilter struct {
	Name       []string
	NameNot    []string
	Path       []string
	PathNot    []string
	Extension  []string
	ExtNot     []string
	MagicMatch bool
}

type UniversalConditions struct {
	Parent    	 []string
	ParentNot 	 []string
	Process   	 *ProcessFilter
	//IsRemote  	 bool
//? ^for this one you need to implement calling thread collection into all telemetry packets (add tid field to header)
	SessionId    []uint32
	SessionIdNot []uint32
	User 		 []string
	UserNot 	 []string
}

// conditions for memory allocation
type AllocFilter struct {
	SizeMin        int64
	SizeMax        int64
	Protection     []uint32 // enums
	ProtectionNot  []uint32
	IsImageSection bool
}

// for changing memory page protections
type ProtectFilter struct {
	OldProtection []uint32
	NewProtection []uint32
}

// for opening handle to thread or process
type HandleFilter struct {
	TargetPath 		 []string
	DesiredAccess    []uint32 // enums
	DesiredAccessNot []uint32
}

// for creating process or thread (seperate one for files/reg)
type PTCreationFilter struct {
	CreationFlags    []uint32 // enums
	CreationFlagsNot []uint32 // enums
}

const {
	//TODO: creation flags
	//TODO: memory protection constants
	//TODO: thread/process access constants
	//TODO: integrity level enums
}


