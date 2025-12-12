package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

// Outer function that will parse every parameter in provided data buffer.
// Name must not be null-terminated. Size must be size in bytes. Header portion must be null-terminated.
func ParseParameters(data []byte) []Parameter {
	var params []Parameter
	cursor := 0
	for cursor < len(data) {
		parameter := ReadAnsiString(data[cursor:])
		cursor += len(parameter) + 1 // +1 because null-terminator occupies one byte after

		// -1 so you wont get out of bounds error, but prevent off-by-one error.
		param, err := ParseParameterString(parameter, data[cursor-1:])
		if err != nil || param.Buffer == nil {
			if err != nil {
				color.Red("\n[!] Failed to parse parameter: %v", err)
			}
			if len(parameter) == 0 {
				break // prevent infinite loop
			}
			continue
		}
		cursor += len(param.Buffer)
		params = append(params, param)
	}
	return params
}

func ParseParameterString(header string, data []byte) (Parameter, error) {
	var (
		param   Parameter
		isArray = false
	)

	// skip empty reads. minimum possible size of header is 3 (a:b)
	if header == "" || len(header) < 3 {
		return Parameter{}, nil
	}

	parts := strings.Split(header, ":")
	if len(parts) < 2 {
		return Parameter{}, fmt.Errorf("packet string does not contain \":\" (%s)", header)
	}

	head := strings.Split(parts[0], "/")
	param.Name = head[0]

	if len(head) > 1 {
		fmt.Printf("%s\n", head[1])
	} else {
		fmt.Println("nil")
	}

	// remove possible null-terminator from first byte
	if len(data) > 0 && data[0] == '\000' {
		data = data[1:]
	}

	// non-array types should have only one string in head (no "/")
	if len(head) > 1 {
		if len(head[1]) == 0 {
			return Parameter{}, fmt.Errorf("invalid header: size (%s)", header)
		}
		size, err := strconv.Atoi(head[1])
		if err != nil {
			return Parameter{}, fmt.Errorf("failed to read size into integer: %v (%s)", err, header)
		}
		param.Buffer = append([]byte(nil), data[:size]...)
		isArray = true
	}

	param.Type = GetParameterType(parts[1], isArray)

	if !isArray {
		switch int(param.Type) {
		case PARAMETER_ANSISTRING:
			str := ReadAnsiString(data)
			param.Buffer = append([]byte(nil), data[:len(str)+1]...)
		case PARAMETER_BOOLEAN, PARAMETER_UINT32:
			param.Buffer = append([]byte(nil), data[:4]...)
		case PARAMETER_UINT64, PARAMETER_POINTER:
			param.Buffer = append([]byte(nil), data[:8]...)
		}
	}
	return param, nil
}

func GetParameterType(ptype string, isArray bool) uint32 {
	switch ptype[0] {
	case 's':
		return uint32(PARAMETER_ANSISTRING)
	case 'x':
		return uint32(PARAMETER_BYTES)
	case 'd':
		if isArray {
			return uint32(PARAMETER_UINT32_ARR)
		}
		return uint32(PARAMETER_UINT32)
	case 'q':
		if isArray {
			return uint32(PARAMETER_UINT64_ARR)
		}
		return uint32(PARAMETER_UINT64)
	case 'p':
		if isArray {
			return uint32(PARAMETER_POINTER_ARR)
		}
		return uint32(PARAMETER_POINTER)
	case 'b':
		if isArray {
			return uint32(PARAMETER_BOOLEAN_ARR)
		}
		return uint32(PARAMETER_BOOLEAN)
	}
	return 0
}
