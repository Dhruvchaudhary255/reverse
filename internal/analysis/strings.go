package analysis

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"reverse/internal/disasm"
	"reverse/internal/elfx"
)

var (
	reHex    = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	reAddImm = regexp.MustCompile(`#\s*(0x[0-9a-fA-F]+|-?\d+)`)
)

// StringResult represents a recovered string with metadata
type StringResult struct {
	Value string // Escaped string content
	Len   int    // Original byte length
}

// EscapeUnprintable returns a string where printable Unicode runes are preserved.
// Control and unprintable runes are escaped as \uXXXX. Invalid UTF-8 is escaped as \xXX.
func EscapeUnprintable(b []byte) string {
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 sequence, escape the byte
			sb.WriteString(fmt.Sprintf("\\x%02X", b[0]))
		} else if unicode.IsPrint(r) {
			sb.WriteRune(r)
		} else {
			sb.WriteString(fmt.Sprintf("\\u%04X", r))
		}
		b = b[size:]
	}
	return sb.String()
}

// FormatRecovered returns both the escaped Unicode string and the hex encoding.
// Use for debug and log of recovered secrets.
func FormatRecovered(b []byte) (string, string) {
	return EscapeUnprintable(b), fmt.Sprintf("%x", b)
}

// ReadAndEscapeString reads a C string from memory and returns both the escaped version
// and the original byte length for XXTEA usage
func ReadAndEscapeString(im *elfx.Image, va uint64, maxLen int) (escapedString string, originalLength int, ok bool) {
	if rawBytes, success := im.ReadBytesVA(va, maxLen); success {
		// Find null terminator
		rawString := ""
		for i, b := range rawBytes {
			if b == 0 {
				rawString = string(rawBytes[:i])
				break
			}
		}
		if rawString == "" && len(rawBytes) == maxLen {
			rawString = string(rawBytes)
		}
		return EscapeUnprintable([]byte(rawString)), len(rawString), true
	}
	return "", 0, false
}

// ParameterRole represents the semantic role of a function parameter
type ParameterRole int

const (
	FirstParam  ParameterRole = iota // x0 on ARM64, rdi on x86_64
	SecondParam                      // x1 on ARM64, rsi on x86_64
	ThirdParam                       // x2 on ARM64, rdx on x86_64
	FourthParam                      // x3 on ARM64, rcx on x86_64
)

// archRegisterName maps parameter roles to architecture-specific register names
func archRegisterName(role ParameterRole) string {
	// Currently ARM64-specific, but could be extended for other architectures
	switch role {
	case FirstParam:
		return "x0"
	case SecondParam:
		return "x1"
	case ThirdParam:
		return "x2"
	case FourthParam:
		return "x3"
	default:
		return "x0"
	}
}

// FindRodataStringInParam attempts to find a string in rodata pointed to by the given parameter role
// Returns the string result, VA, and success flag
func FindRodataStringInParam(im *elfx.Image, win disasm.Stream, idx int, param ParameterRole) (StringResult, uint64, bool) {
	reg := archRegisterName(param)

	// Try ADRP+ADD pattern first
	if va, ok := ResolveADRPADD(win, idx, reg); ok && im.InRodata(va) {
		if escaped, originalLen, ok := ReadAndEscapeString(im, va, MaxStringLength); ok {
			return StringResult{Value: escaped, Len: originalLen}, va, true
		}
	}

	return StringResult{}, 0, false
}

// parseImm parses an immediate value from assembly text
func parseImm(s string) int64 {
	s = strings.TrimSpace(s)
	sign := int64(1)
	if strings.HasPrefix(s, "-") {
		sign = -1
		s = strings.TrimPrefix(s, "-")
	}
	s = strings.TrimPrefix(s, "+")
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, _ := strconv.ParseUint(s[2:], 16, 64)
		return sign * int64(v)
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return sign * v
}

// ResolveADRPADD walks back up to ~12 insns from idx and computes a literal VA
// formed by ADR/ADRP + ADD into xReg. Handles relative forms like "ADRP X1, .+0x9c0000".
// Also handles MOV chains where the target register gets its value from another register.
func ResolveADRPADD(code disasm.Stream, idx int, xReg string) (uint64, bool) {
	return resolveADRPADDRecursive(code, idx, xReg, 0, make(map[string]bool))
}

// resolveADRPADDRecursive implements the recursive logic with cycle detection
func resolveADRPADDRecursive(code disasm.Stream, idx int, xReg string, depth int, visited map[string]bool) (uint64, bool) {
	// Prevent infinite recursion
	if depth > 5 || visited[xReg] {
		return 0, false
	}
	visited[xReg] = true

	page := uint64(0)
	tmp := ""
	xReg = strings.ToLower(xReg)

	// First, try to find direct ADRP+ADD into xReg
	for i := idx; i >= 0 && idx-i <= SearchWindowSmall; i-- {
		s := strings.ToLower(code[i].Text)

		// Handle MOV instructions first - trace through register reassignments
		if strings.HasPrefix(s, "mov ") {
			fields := strings.Fields(s)
			if len(fields) >= 3 {
				dst := strings.TrimSuffix(fields[1], ",")
				src := strings.TrimSuffix(fields[2], ",")

				// If we found a MOV that sets our target register, recurse on the source
				if dst == xReg && strings.HasPrefix(src, "x") {
					if va, ok := resolveADRPADDRecursive(code, i-1, src, depth+1, visited); ok {
						return va, true
					}
				}
			}
			continue
		}

		// Look for ADD instructions
		if !strings.HasPrefix(s, "add ") {
			continue
		}
		fields := strings.Fields(s)
		if len(fields) < 4 {
			continue
		}
		rd := strings.TrimSuffix(fields[1], ",")
		rs := strings.TrimSuffix(strings.TrimSuffix(fields[2], ","), ",")
		if rd != xReg {
			continue
		}
		// parse imm from ADD
		m := reAddImm.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		off := parseImm(m[1])
		tmp = rs
		// search back for matching ADR/ADRP that sets tmp
		for k := i - 1; k >= 0 && i-k <= SearchWindowSmall; k-- {
			s2 := strings.ToLower(code[k].Text)
			if !(strings.HasPrefix(s2, "adrp ") || strings.HasPrefix(s2, "adr ")) {
				continue
			}
			f2 := strings.Fields(s2)
			if len(f2) < 3 {
				continue
			}
			dst := strings.TrimSuffix(f2[1], ",")
			if dst != tmp {
				continue
			}
			instPage := code[k].VA &^ 0xfff
			if strings.Contains(s2, ".+") || strings.Contains(s2, ".-") {
				sign := int64(1)
				if strings.Contains(s2, ".-") {
					sign = -1
				}
				if hx := reHex.FindString(s2); hx != "" {
					v, _ := strconv.ParseUint(hx[2:], 16, 64)
					if sign < 0 {
						page = uint64(int64(instPage) - int64(v))
					} else {
						page = instPage + uint64(v)
					}
				} else {
					page = instPage
				}
			} else if hx := reHex.FindString(s2); hx != "" {
				v, _ := strconv.ParseUint(hx[2:], 16, 64)
				page = v &^ 0xfff
			} else {
				page = instPage
			}
			return page + uint64(off), true
		}
	}
	return 0, false
}
