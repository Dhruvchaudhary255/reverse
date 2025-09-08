package analysis

import (
	"fmt"
	"strconv"
	"strings"

	"reverse/internal/elfx"

	"golang.org/x/arch/arm64/arm64asm"
)

// ParamValue represents what we could resolve for a call argument
type ParamValue struct {
	Reg     string      // register used (x0, x1, w2, etc.)
	Value   interface{} // could be string, int, uint64, or nil if unresolved
	From    string      // source of value: "immediate", "adrp+add", "ldr_rodata", "stack", "unknown"
	TraceVA uint64      // VA where this register's value was set (for tracing)
}

// CallFinding is a semantic event detected in disassembly
type CallFinding struct {
	CallVA    uint64                 // Virtual address of the call instruction
	TargetVA  uint64                 // Virtual address of the target function (if known)
	Target    string                 // Demangled symbol name or "indirect"
	Symbol    string                 // Original symbol name
	Args      []ParamValue           // Interpreted parameters
	Comment   string                 // Human-readable summary
	TraceMin  uint64                 // Earliest VA involved in parameter setup
	TraceMax  uint64                 // Latest VA (the call itself)
	Backtrace []string               // Call chain from entry point (e.g., ["AppDelegate", "regist_lua"])
	Metadata  map[string]interface{} // Detector-specific metadata
}

// AnnotatedInst represents a disassembled instruction with annotations
type AnnotatedInst struct {
	VA          uint64
	Bytes       [4]byte
	Inst        arm64asm.Inst
	Mnemonic    string
	Operands    string
	Annotations []string // Comments to display
}

// findFunctionAt finds the function symbol containing the given address
func findFunctionAt(img *elfx.Image, va uint64) *elfx.DynSym {
	// Check dynamic symbols - just find the symbol with matching address
	// since DynSym doesn't have size information
	for _, sym := range img.Dynsyms {
		if sym.Addr == va {
			return &sym
		}
	}
	// Check regular symbols
	for _, sym := range img.Syms {
		if sym.Addr == va {
			return &sym
		}
	}
	return nil
}

func isStackOffset(v uint64) bool {
	return v < 0x1000
}

// isValidOffset returns true if v is a reasonable offset for vtables or similar structures
func isValidOffset(v uint64) bool {
	return v > 0 && v < 0x1000
}

// String formats the instruction with padding at column 50 for annotations
// This returns plain text - colorization should be done after formatting
func (a AnnotatedInst) String() string {
	// Check if this is a comment-only line (vtable info on separate line)
	if a.Mnemonic == "" && a.Operands == "" && len(a.Annotations) > 0 {
		// Format as indented comment line
		return fmt.Sprintf("           %-6s %-30s ; %s", "", "", strings.Join(a.Annotations, ", "))
	}

	// Check if this is a label (ends with colon)
	if strings.HasSuffix(a.Mnemonic, ":") {
		// Format label without address, left-aligned
		return fmt.Sprintf("%x  %s", a.VA, a.Mnemonic)
	}

	// Format: address  mnemonic  operands
	addr := fmt.Sprintf("%x", a.VA) // No 0x prefix, will be added by colorizer if needed

	// Build the base instruction with fixed-width fields
	base := fmt.Sprintf("%-10s %-6s %-30s", addr, a.Mnemonic, a.Operands)

	// Add annotations if present
	if len(a.Annotations) > 0 {
		return fmt.Sprintf("%s ; %s", base, strings.Join(a.Annotations, ", "))
	}
	return base
}

// AnnotatorResult contains both annotated listing and semantic findings
type AnnotatorResult struct {
	Listing  []AnnotatedInst
	Findings []CallFinding
}

// RegisterState tracks register values during execution
type RegisterState struct {
	regs            map[string]interface{} // Current register values
	pages           map[string]uint64      // ADRP page values by register name
	sources         map[string]uint64      // VA where each register was last set
	traceMin        uint64                 // Earliest VA in current trace
	x0ValidUntil    uint64                 // If nonzero, PC at which x0 should be cleared
	stdStrings      map[uint64]string      // Stack offset -> string value for std::string objects
	stdStringSrcs   map[uint64]uint64      // Stack offset -> original source VA for std::string
	pendingStr      *PendingString         // Pending std::string constructor detection
	vtableOffsets   map[string]uint64      // Register -> vtable offset (for tracking add reg, reg, #offset)
	objectSources   map[string]string      // Register -> function that returned the object
	stackPointers   map[uint64]uint64      // Stack offset -> pointer value (for indirect references)
	funcParams      map[string]string      // Register -> original parameter register (e.g., x19 -> x2)
	xorTransformed  map[string]uint64      // Register -> XOR key used (for XOR obfuscation detection)
	signExtendLoads map[string]bool        // Register -> true if loaded with sign extension (LDRSB)
	isVtablePtr     map[string]bool        // Register -> true if contains a vtable pointer
}

// addAnnotation adds an annotation
func (s *RegisterState) addAnnotation(annotations *[]string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	*annotations = append(*annotations, msg)
}

// clearVtableState clears vtable-related state for a register
func (s *RegisterState) clearVtableState(regName string) {
	delete(s.vtableOffsets, regName)
	delete(s.isVtablePtr, regName)
}

// PendingString tracks a potential std::string constructor pattern
type PendingString struct {
	stackOffset uint64 // Stack offset where string will be constructed
	stringValue string // The C string to be stored
	stringAddr  uint64 // Address of the C string
	sourceVA    uint64 // VA where the string was originally loaded (ADRP)
}

// NewRegisterState creates a new register tracking state
func NewRegisterState() *RegisterState {
	return &RegisterState{
		regs:            make(map[string]interface{}),
		pages:           make(map[string]uint64),
		sources:         make(map[string]uint64),
		stdStrings:      make(map[uint64]string),
		stdStringSrcs:   make(map[uint64]uint64),
		vtableOffsets:   make(map[string]uint64),
		objectSources:   make(map[string]string),
		stackPointers:   make(map[uint64]uint64),
		funcParams:      make(map[string]string),
		xorTransformed:  make(map[string]uint64),
		signExtendLoads: make(map[string]bool),
		isVtablePtr:     make(map[string]bool),
	}
}

// enrichWithStdStringParams tries to resolve std::string parameters from stack
// This is useful for functions that take std::string const& parameters
func enrichWithStdStringParams(callArgs []ParamValue, symName string, listing []AnnotatedInst, state *RegisterState) []ParamValue {
	// Look back through recent instructions for LDR x1/x3, [sp, #N] to find stack offsets
	// We'll scan back up to 16 instructions
	var lastX1Offset, lastX3Offset uint64

	for idx := len(listing) - 1; idx >= 0 && len(listing)-idx <= 16; idx-- {
		ai := listing[idx]
		if ai.Mnemonic == "ldr" {
			ops := strings.ReplaceAll(ai.Operands, " ", "")
			if strings.HasPrefix(ops, "x1,[sp,#") {
				// Parse offset
				offStr := ops[len("x1,[sp,#"):]
				if i := strings.Index(offStr, "]"); i > 0 {
					offStr = offStr[:i]
				}
				var offset uint64
				if strings.HasPrefix(offStr, "0x") {
					fmt.Sscanf(offStr[2:], "%x", &offset)
				} else {
					fmt.Sscanf(offStr, "%d", &offset)
				}
				if offset != 0 {
					lastX1Offset = offset
				}
			} else if strings.HasPrefix(ops, "x3,[sp,#") {
				offStr := ops[len("x3,[sp,#"):]
				if i := strings.Index(offStr, "]"); i > 0 {
					offStr = offStr[:i]
				}
				var offset uint64
				if strings.HasPrefix(offStr, "0x") {
					fmt.Sscanf(offStr[2:], "%x", &offset)
				} else {
					fmt.Sscanf(offStr, "%d", &offset)
				}
				if offset != 0 {
					lastX3Offset = offset
				}
			}
		}
	}

	// Check if we found std::string at these offsets
	enriched := make([]ParamValue, 0, len(callArgs))
	for _, arg := range callArgs {
		enriched = append(enriched, arg)
	}

	// Add std::string parameters if found
	if lastX1Offset != 0 {
		if s, ok := state.stdStrings[lastX1Offset]; ok && s != "" {
			// Check if x1 is already in args
			found := false
			for i, arg := range enriched {
				if arg.Reg == "x1" {
					enriched[i].Value = s
					enriched[i].From = "std::string&"
					found = true
					break
				}
			}
			if !found {
				enriched = append(enriched, ParamValue{
					Reg:   "x1",
					Value: s,
					From:  "std::string&",
				})
			}
		}
	}

	if lastX3Offset != 0 {
		if s, ok := state.stdStrings[lastX3Offset]; ok && s != "" {
			// Check if x3 is already in args
			found := false
			for i, arg := range enriched {
				if arg.Reg == "x3" {
					enriched[i].Value = s
					enriched[i].From = "std::string&"
					found = true
					break
				}
			}
			if !found {
				enriched = append(enriched, ParamValue{
					Reg:   "x3",
					Value: s,
					From:  "std::string&",
				})
			}
		}
	}

	return enriched
}

// parseImmediate extracts an immediate value from an instruction argument
func parseImmediate(arg interface{}) (uint64, bool) {
	switch a := arg.(type) {
	case arm64asm.Imm:
		return uint64(a.Imm), true
	case arm64asm.ImmShift:
		str := a.String()
		if strings.HasPrefix(str, "#0x") {
			if val, err := strconv.ParseUint(str[3:], 16, 64); err == nil {
				return val, true
			}
		} else if strings.HasPrefix(str, "#") {
			if val, err := strconv.ParseInt(str[1:], 10, 64); err == nil {
				return uint64(val), true
			}
		}
	}
	return 0, false
}

// TryResolveCString tries to read a null-terminated string at the given VA.
// Returns the escaped string if valid UTF-8, else returns empty string.
func TryResolveCString(img *elfx.Image, addr uint64) (string, bool) {
	// Use existing ReadAndEscapeString which handles null termination and escaping
	escaped, originalLen, ok := ReadAndEscapeString(img, addr, MaxStringLength)
	if !ok || originalLen == 0 {
		return "", false
	}
	return escaped, true
}

// TraceDisasm performs semantic analysis on disassembled code
// TraceDisasm disassembles and annotates code starting at startVA
func TraceDisasm(img *elfx.Image, startVA uint64, maxInsns int) (*AnnotatorResult, error) {
	return TraceDisasmWithBacktrace(img, startVA, maxInsns, nil)
}

// TraceDisasmWithBacktrace disassembles and annotates code with call chain tracking
func TraceDisasmWithBacktrace(img *elfx.Image, startVA uint64, maxInsns int, backtrace []string) (*AnnotatorResult, error) {
	return TraceDisasmWithState(img, startVA, maxInsns, backtrace, nil)
}

// TraceDisasmWithState disassembles and annotates code with call chain tracking and register state
func TraceDisasmWithState(img *elfx.Image, startVA uint64, maxInsns int, backtrace []string, initialState *RegisterState) (*AnnotatorResult, error) {
	// Read the code bytes
	data, ok := img.ReadBytesVA(startVA, maxInsns*4)
	if !ok || len(data) == 0 {
		return nil, fmt.Errorf("failed to read code at %x", startVA)
	}

	// Create vtable resolver for resolving virtual calls
	vtableResolver := NewVTableResolver(img)

	// Build symbol map for faster lookups
	symMap := buildSymbolMap(img)

	// First pass: identify local branch targets
	localLabels := make(map[uint64]string)
	pc := startVA
	for i := 0; i < len(data)-3 && i/4 < maxInsns; i += 4 {
		inst, err := arm64asm.Decode(data[i : i+4])
		if err != nil {
			pc += 4
			continue
		}

		// Check for local branches
		opStr := inst.Op.String()
		if strings.HasPrefix(opStr, "B") || strings.HasPrefix(opStr, "CB") || strings.HasPrefix(opStr, "TB") {
			if pcRel, ok := inst.Args[len(inst.Args)-1].(arm64asm.PCRel); ok {
				targetAddr := uint64(int64(pc) + int64(pcRel))
				// Check if it's a local branch (within the function)
				if targetAddr >= startVA && targetAddr < startVA+uint64(maxInsns*4) {
					if _, exists := localLabels[targetAddr]; !exists {
						localLabels[targetAddr] = fmt.Sprintf("loc_%x", targetAddr)
					}
				}
			}
		}
		pc += 4
	}

	// Check if this is a C++ member function
	// Member functions have "::" in their demangled name and x0 contains 'this'
	funcName := ""
	if sym, exists := symMap[startVA]; exists {
		// Demangle the function name to check for member functions
		funcName = CachedDemangle(sym)
	}

	// Initialize register state - use provided state or create new
	var state *RegisterState
	if initialState != nil {
		// Clone the initial state to avoid modifying it
		state = &RegisterState{
			regs:            make(map[string]interface{}),
			pages:           make(map[string]uint64),
			sources:         make(map[string]uint64),
			stdStrings:      make(map[uint64]string),
			stdStringSrcs:   make(map[uint64]uint64),
			vtableOffsets:   make(map[string]uint64),
			objectSources:   make(map[string]string),
			stackPointers:   make(map[uint64]uint64),
			xorTransformed:  make(map[string]uint64),
			signExtendLoads: make(map[string]bool),
			isVtablePtr:     make(map[string]bool),
		}
		// Copy register values
		for k, v := range initialState.regs {
			state.regs[k] = v
		}
		for k, v := range initialState.pages {
			state.pages[k] = v
		}
		for k, v := range initialState.sources {
			state.sources[k] = v
		}
		state.traceMin = initialState.traceMin
		state.x0ValidUntil = initialState.x0ValidUntil
	} else {
		state = NewRegisterState()
	}

	// If this is a C++ member function, mark x0 as containing 'this' pointer
	if strings.Contains(funcName, "::") && !strings.Contains(funcName, "::getInstance") {
		// Extract class name from function name (keep namespace if present)
		className := funcName
		// Find the last :: before the method name
		if idx := strings.LastIndex(funcName, "::"); idx > 0 {
			className = funcName[:idx]
		}
		// Handle function names with parameters like "cc::BaseGame::init()"
		if parenIdx := strings.Index(className, "("); parenIdx > 0 {
			className = className[:parenIdx]
		}
		state.objectSources["x0"] = className
	}

	result := &AnnotatorResult{
		Listing:  []AnnotatedInst{},
		Findings: []CallFinding{},
	}

	// Second pass: disassemble with annotations
	pc = startVA
	for i := 0; i < len(data)-3 && i/4 < maxInsns; i += 4 {
		// At the start of each instruction, check if x0 needs to be cleared
		if state.x0ValidUntil != 0 && pc == state.x0ValidUntil {
			// Don't clear if x0 contains an extracted string
			if str, ok := state.regs["x0"].(string); !ok || !strings.HasPrefix(str, "extracted:") {
				delete(state.regs, "x0")
				delete(state.sources, "x0")
			}
			state.x0ValidUntil = 0
		}
		// Check if this address has a label
		if label, hasLabel := localLabels[pc]; hasLabel {
			// Add a label instruction
			labelInst := AnnotatedInst{
				VA:       pc,
				Bytes:    [4]byte{},
				Inst:     arm64asm.Inst{},
				Mnemonic: label + ":",
				Operands: "",
			}
			result.Listing = append(result.Listing, labelInst)
		}

		// Decode instruction
		inst, err := arm64asm.Decode(data[i : i+4])
		if err != nil {
			pc += 4
			continue
		}

		// Detect PLT stub pattern and try to resolve it
		// PLT stubs typically start with ADRP x16, ... followed by LDR x17, ...
		if inst.Op == arm64asm.ADRP && len(inst.Args) >= 2 {
			if reg, ok := inst.Args[0].(arm64asm.Reg); ok && reg.String() == "X16" {
				// Look ahead to see if next instruction is LDR x17
				if i+4 < len(data)-3 {
					nextInst, err := arm64asm.Decode(data[i+4 : i+8])
					if err == nil && nextInst.Op == arm64asm.LDR && len(nextInst.Args) >= 2 {
						if reg, ok := nextInst.Args[0].(arm64asm.Reg); ok && reg.String() == "X17" {
							// This looks like a PLT stub - try to resolve it
							stubAddr := pc

							// Try to find what function this PLT stub is for
							targetName := ""
							targetAddr := uint64(0)

							// Check if we have PLT relocation info
							for _, rel := range img.PLTRels {
								if rel.PLTAddr == stubAddr {
									targetName = rel.SymName
									// Try to find the actual implementation
									for _, sym := range img.Dynsyms {
										if sym.Name == targetName && sym.Addr != 0 {
											targetAddr = sym.Addr
											break
										}
									}
									break
								}
							}

							// If we found the target, continue tracing there
							if targetAddr != 0 && targetName != "" {
								annotated := AnnotatedInst{
									VA:          pc,
									Bytes:       [4]byte{data[i], data[i+1], data[i+2], data[i+3]},
									Inst:        inst,
									Mnemonic:    strings.ToLower(inst.Op.String()),
									Operands:    strings.ToLower(inst.String())[len(inst.Op.String())+1:],
									Annotations: []string{fmt.Sprintf("[PLT STUB for %s @ 0x%x - continuing]", targetName, targetAddr)},
								}
								result.Listing = append(result.Listing, annotated)

								// Build the new backtrace
								newBacktrace := append([]string{}, backtrace...)
								newBacktrace = append(newBacktrace, fmt.Sprintf("PLT:%s", targetName))

								// Continue tracing at the resolved target
								remainingInsns := maxInsns - len(result.Listing)
								if remainingInsns > SearchWindowMedium {
									// Pass the current state to the resolved function
									resolvedResult, err := TraceDisasmWithState(img, targetAddr, remainingInsns, newBacktrace, state)
									if err == nil && resolvedResult != nil {
										result.Listing = append(result.Listing, resolvedResult.Listing...)
										for _, finding := range resolvedResult.Findings {
											if len(finding.Backtrace) == 0 {
												finding.Backtrace = newBacktrace
											}
											result.Findings = append(result.Findings, finding)
										}
									}
								}
								return result, nil
							}

							// If we couldn't resolve it, just note it and stop
							annotated := AnnotatedInst{
								VA:          pc,
								Bytes:       [4]byte{data[i], data[i+1], data[i+2], data[i+3]},
								Inst:        inst,
								Mnemonic:    strings.ToLower(inst.Op.String()),
								Operands:    strings.ToLower(inst.String())[len(inst.Op.String())+1:],
								Annotations: []string{"[PLT STUB - unresolved, stopping]"},
							}
							result.Listing = append(result.Listing, annotated)
							return result, nil
						}
					}
				}
			}
		}

		// Create annotated instruction
		annotated := AnnotatedInst{
			VA:       pc,
			Bytes:    [4]byte{data[i], data[i+1], data[i+2], data[i+3]},
			Inst:     inst,
			Mnemonic: strings.ToLower(inst.Op.String()),
		}

		// Get operands string and potentially replace with local label
		instStr := strings.ToLower(inst.String())
		parts := strings.SplitN(instStr, " ", 2)
		if len(parts) > 1 {
			operands := parts[1]

			// Check if this is a branch that should use a local label
			opStr := inst.Op.String()

			switch {
			case strings.HasPrefix(opStr, "B") && opStr != "BL" && opStr != "BLR":
				// Regular branch (not a call)
				if pcRel, ok := inst.Args[len(inst.Args)-1].(arm64asm.PCRel); ok {
					targetAddr := uint64(int64(pc) + int64(pcRel))
					if label, hasLabel := localLabels[targetAddr]; hasLabel {
						operands = label
					}
				}

			case strings.HasPrefix(opStr, "CB"), strings.HasPrefix(opStr, "TB"):
				// Conditional branches with register (CBZ, CBNZ, TBZ, TBNZ)
				if len(inst.Args) >= 2 {
					if pcRel, ok := inst.Args[len(inst.Args)-1].(arm64asm.PCRel); ok {
						targetAddr := uint64(int64(pc) + int64(pcRel))
						if label, hasLabel := localLabels[targetAddr]; hasLabel {
							parts := strings.Split(operands, ",")
							if len(parts) >= 2 {
								newOps := strings.Join(parts[:len(parts)-1], ",")
								operands = newOps + ", " + label
							}
						}
					}
				}
			}

			annotated.Operands = operands
		}

		// Track register values and annotate
		annotations := []string{}

		switch inst.Op {
		case arm64asm.BL:
			// Branch and link - function call (most important for tracking XXTEA setters)
			if pcRel, ok := inst.Args[0].(arm64asm.PCRel); ok {
				targetAddr := uint64(int64(pc) + int64(pcRel))

				// Look up symbol
				symName := symMap[targetAddr]
				if symName == "" {
					symName = fmt.Sprintf("sub_%x", targetAddr)
				}

				// Check for std::string constructor pattern
				switch {
				case state.pendingStr != nil && state.pendingStr.stackOffset != 0:
					// First try: pendingStr with explicit stackOffset
					// We have both string and stack offset - this might be a constructor
					// Store the string at this stack offset
					state.stdStrings[state.pendingStr.stackOffset] = state.pendingStr.stringValue
					state.stdStringSrcs[state.pendingStr.stackOffset] = state.pendingStr.sourceVA
					state.addAnnotation(&annotations, "\"%s\" → [sp+#0x%x]",
						EscapeUnprintable([]byte(state.pendingStr.stringValue)), state.pendingStr.stackOffset)
					state.pendingStr = nil // Clear pending

				case state.pendingStr != nil:
					// Second try: pendingStr without stackOffset but x0 has one
					if x0Val, hasX0 := state.regs["x0"]; hasX0 {
						if stackOffset, ok := x0Val.(uint64); ok && isStackOffset(stackOffset) {
							// x0 has a stack offset, use it for the constructor
							state.stdStrings[stackOffset] = state.pendingStr.stringValue
							state.stdStringSrcs[stackOffset] = state.pendingStr.sourceVA
							state.addAnnotation(&annotations, "\"%s\" → [sp+#0x%x]",
								EscapeUnprintable([]byte(state.pendingStr.stringValue)), stackOffset)
							state.pendingStr = nil // Clear pending
						}
					}

				default:
					// Check for std::string extractor pattern
					// If x0 contains a stack offset that has a std::string
					if x0Offset, ok := state.regs["x0"].(uint64); ok {
						if str, hasString := state.stdStrings[x0Offset]; hasString {
							// This looks like a .c_str() or similar extraction
							// Annotate it and track that x0 will contain a pointer to this string
							state.addAnnotation(&annotations, ".c_str() → \"%s\"", EscapeUnprintable([]byte(str)))
							// Track that x0 will have a pointer to this string after the call
							// Store it in a special format that won't be confused with direct strings
							state.regs["x0"] = fmt.Sprintf("ptr_to:%s", str)
							// Keep the original source for parameter tracking
							if srcVA, ok := state.stdStringSrcs[x0Offset]; ok {
								state.sources["x0"] = srcVA
							} else {
								state.sources["x0"] = pc
							}
							// Mark that this is a .c_str() result
							state.x0ValidUntil = pc + 12 // Give more time for .c_str() results
						}
					}
				}

				// If x0 holds the address of a stack std::string we reconstructed, set x0 to the actual string
				if x0Offset, ok := state.regs["x0"].(uint64); ok && isStackOffset(x0Offset) {
					if str, has := state.stdStrings[x0Offset]; has {
						state.addAnnotation(&annotations, "std::string arg (x0) = \"%s\"", EscapeUnprintable([]byte(str)))
						state.regs["x0"] = str
						if srcVA, ok := state.stdStringSrcs[x0Offset]; ok {
							state.sources["x0"] = srcVA
						} else {
							state.sources["x0"] = pc
						}
					}
				}

				// Store register state first
				callArgs := resolveCallParams(state, img)

				// Try to resolve std::string parameters from stack for functions that might use them
				// This is generic parameter tracking, not XXTEA-specific
				callArgs = enrichWithStdStringParams(callArgs, symName, result.Listing, state)

				// Create finding with basic information
				finding := CallFinding{
					CallVA:    pc,
					TargetVA:  targetAddr,
					Symbol:    symName,
					Target:    demangleSymbol(symName),
					TraceMax:  pc, // The call itself
					Args:      callArgs,
					Backtrace: backtrace,
				}

				// Add the demangled target name as annotation
				if len(annotations) == 0 || !strings.Contains(annotations[len(annotations)-1], "std::string") {
					annotations = append(annotations, finding.Target)
				}

				// Compute TraceMin based on actual parameters used
				var minTrace uint64
				for _, arg := range finding.Args {
					if arg.TraceVA != 0 && (minTrace == 0 || arg.TraceVA < minTrace) {
						minTrace = arg.TraceVA
					}
				}
				if minTrace == 0 {
					minTrace = pc // Fall back to the call itself
				}
				finding.TraceMin = minTrace

				result.Findings = append(result.Findings, finding)

				// Track the function that returned in x0 for vtable resolution
				state.objectSources["x0"] = finding.Target

				// After a function call, clear caller-saved registers
				// x0 is the return value register
				if strVal, ok := state.regs["x0"].(string); ok && strings.HasPrefix(strVal, "ptr_to:") {
					// This is a .c_str() result, keep it for parameter tracking
				} else {
					// Clear x0 as it's the return value register
					delete(state.regs, "x0")
					delete(state.sources, "x0")
				}
				// x1-x7 are parameter/caller-saved registers that should be cleared
				for i := 1; i <= 7; i++ {
					xReg := fmt.Sprintf("x%d", i)
					wReg := fmt.Sprintf("w%d", i)
					delete(state.regs, xReg)
					delete(state.sources, xReg)
					delete(state.regs, wReg)
					delete(state.sources, wReg)
				}
				state.x0ValidUntil = 0
			}

		case arm64asm.ADRP:
			// ADRP reg, imm → reg = page base
			if pcRel, ok := inst.Args[1].(arm64asm.PCRel); ok {
				page := uint64(int64(pc) + int64(pcRel))
				page &= ^uint64(0xfff) // page align
				if reg, ok := inst.Args[0].(arm64asm.Reg); ok {
					r := strings.ToLower(reg.String())
					state.pages[r] = page
					state.regs[r] = page  // Also store in regs so ADD can consume it
					state.sources[r] = pc // Track where this value was set
					// Don't update traceMin here - we'll compute it based on actual params used

					// Add annotation showing the page base address
					state.addAnnotation(&annotations, "page = 0x%x", page)
				}
			}

		case arm64asm.ADD, arm64asm.SUB:
			// Handle ADD/SUB instructions - including stack address calculations
			// Common patterns:
			// ADD x0, sp, #0x38 for std::string constructor
			// SUB x0, x29, #0x60 for stack-relative addressing

			// Parse the instruction string to get actual register names
			// This handles cases where the decoder gives us RegSP for both args
			instStr := strings.ToLower(inst.String())
			parts := strings.Fields(instStr)

			// Only proceed if we have the expected format
			if len(parts) >= 3 && len(inst.Args) >= 3 && inst.Args[2] != nil {
				// Extract destination and source register names from the string
				dstName := strings.TrimSuffix(parts[1], ",")
				srcName := strings.TrimSuffix(parts[2], ",")

				// Check if this is a stack address calculation
				switch srcName {
				case "sp", "x29":
					// Get the offset
					offset, gotOffset := parseImmediate(inst.Args[2])
					if gotOffset {
						// For SUB, we need to handle negative offsets
						// SUB x0, x29, #0x60 means x29 - 0x60, which is still a stack offset
						// We store it as the offset value itself for consistency
						if inst.Op == arm64asm.SUB {
							// SUB from frame pointer - still a stack offset, just calculated differently
							// We'll store the offset as-is since it represents a stack location
							state.addAnnotation(&annotations, "%s = [%s-#0x%x]", dstName, srcName, offset)
						} else {
							state.addAnnotation(&annotations, "%s = [%s+#0x%x]", dstName, srcName, offset)
						}

						// Store the stack offset in the destination register
						state.regs[dstName] = offset
						state.sources[dstName] = pc

						// Check if this might be setting up for std::string constructor
						if dstName == "x0" && state.pendingStr != nil {
							state.pendingStr.stackOffset = offset
							state.addAnnotation(&annotations, "std::string dest [sp+#0x%x]", offset)
						}
					}
				}
			}

			// Continue with regular ADD handling (ADRP+ADD pattern)
			// Only handle the 3-arg form: ADD dst, src, imm (from ADRP+ADD)
			// Note: Args array may have length 5 with last 2 being nil
			if len(inst.Args) >= 3 && inst.Args[2] != nil &&
				(len(inst.Args) == 3 || inst.Args[3] == nil) {

				var dst, src arm64asm.Reg
				ok1, ok2 := false, false

				switch a := inst.Args[0].(type) {
				case arm64asm.Reg:
					dst, ok1 = a, true
				case arm64asm.RegSP:
					dst, ok1 = arm64asm.Reg(a), true
				}

				switch b := inst.Args[1].(type) {
				case arm64asm.Reg:
					src, ok2 = b, true
				case arm64asm.RegSP:
					src, ok2 = arm64asm.Reg(b), true
				}

				if ok1 && ok2 {
					dstName := strings.ToLower(dst.String())
					srcName := strings.ToLower(src.String())

					// First check if this is adding a vtable offset to an object pointer
					// Pattern: ADD x0, x0, #offset (where x0 contains object pointer, NOT a page address)
					if dstName == srcName && inst.Args[2] != nil {
						// Same register as source and dest - could be vtable offset OR ADRP+ADD completion
						// Check if this register has a page value from ADRP
						_, hasPage := state.pages[srcName]
						if !hasPage {
							// Not from ADRP, so check if it might be a vtable offset adjustment
							var offset uint64
							gotOffset := false
							offset, gotOffset = parseImmediate(inst.Args[2])

							if gotOffset && isValidOffset(offset) { // Reasonable vtable offset range
								// Only annotate as vtable offset if we have an object source
								if source, ok := state.objectSources[srcName]; ok {
									// Track this as a vtable offset
									state.vtableOffsets[dstName] = offset
									state.objectSources[dstName] = source
									state.addAnnotation(&annotations, "vtable+0x%x", offset)
								}
							}
						}
					}

					// Check for stack address pattern (ADD xN, x29, #offset or ADD xN, sp, #offset)
					handledStackAddr := false
					switch srcName {
					case "x29", "sp":
						if inst.Args[2] != nil {
							// This is loading a stack address
							var stackOffset uint64
							gotStackOffset := false
							stackOffset, gotStackOffset = parseImmediate(inst.Args[2])

							if gotStackOffset {
								// Store the stack offset in the register
								state.regs[dstName] = stackOffset
								state.sources[dstName] = pc

								// Track the stack offset in the register

								// Check if this might be setting up for std::string constructor
								// Common pattern: x0 or x3 gets stack address for destination
								switch dstName {
								case "x0", "x3":
									// Check if we have a pending string (from ADRP+ADD loading x1)
									if state.pendingStr != nil {
										state.pendingStr.stackOffset = stackOffset
										state.addAnnotation(&annotations, "std::string dest [sp+#0x%x]", stackOffset)
									}
								}
								// Also check if this stack offset has a stored std::string
								if str, ok := state.stdStrings[stackOffset]; ok {
									// We're loading the address of a std::string object
									state.addAnnotation(&annotations, "[x29+#0x%x] = \"%s\"", stackOffset, EscapeUnprintable([]byte(str)))
								}
								handledStackAddr = true
							}
						}
					}

					// Skip ADRP+ADD pattern if we handled stack address
					if handledStackAddr {
						break
					}

					// Handle general ADD pattern: ADD dst, src, #imm (where dst != src)
					// BUT ONLY if src doesn't have a page value (to not break ADRP+ADD)
					if dstName != srcName && inst.Args[2] != nil {
						// Check if source has a page value from ADRP
						_, hasPage := state.pages[srcName]
						if !hasPage {
							// This is not ADRP+ADD, so handle it as member access
							offset, gotOffset := parseImmediate(inst.Args[2])
							if gotOffset {
								// Special case: If this looks like accessing a std::string member (offset 0x40 is common)
								// and destination is x1 (typical for first parameter), mark it as potential std::string
								if dstName == "x1" && (offset == 0x40 || offset == 0x30 || offset == 0x20) {
									// Mark x1 as containing a std::string pointer
									// We use a special marker to indicate this is a member std::string
									state.regs[dstName] = fmt.Sprintf("member_string:%s+0x%x", srcName, offset)
									state.sources[dstName] = pc
									state.addAnnotation(&annotations, "%s = %s+#0x%x [std::string member]", dstName, srcName, offset)

									// If source has an object source, propagate it
									if objSrc, hasObj := state.objectSources[srcName]; hasObj {
										state.objectSources[dstName] = objSrc
										state.addAnnotation(&annotations, "std::string from %s", objSrc)
									}
								} else {
									// Check if source register has a value we're tracking
									if srcVal, hasSrc := state.regs[srcName]; hasSrc {
										// If srcVal is a stack offset, add the immediate to it
										if stackOff, isStack := srcVal.(uint64); isStack && isStackOffset(stackOff) {
											newOffset := stackOff + offset
											state.regs[dstName] = newOffset
											state.sources[dstName] = pc
											state.addAnnotation(&annotations, "%s = %s+#0x%x", dstName, srcName, offset)

											// Check if there's a std::string at this new offset
											if str, ok := state.stdStrings[newOffset]; ok {
												state.addAnnotation(&annotations, "points to \"%s\"", EscapeUnprintable([]byte(str)))
											}
										} else {
											// For other values, just track that we added an offset
											state.regs[dstName] = offset // Store just the offset for now
											state.sources[dstName] = pc
											state.addAnnotation(&annotations, "%s = %s+#0x%x", dstName, srcName, offset)
										}
									} else {
										// Even if we don't know the source value, track the operation
										state.addAnnotation(&annotations, "%s = %s+#0x%x", dstName, srcName, offset)
										// Store the offset so we know this register points to object+offset
										state.regs[dstName] = offset
										state.sources[dstName] = pc
									}

									// If source has an object source, propagate it
									if objSrc, hasObj := state.objectSources[srcName]; hasObj {
										state.objectSources[dstName] = objSrc
										state.addAnnotation(&annotations, "member of %s", objSrc)
									}
								}
							}
							break
						}
						// If it has a page value, fall through to ADRP+ADD handling below
					}

					// Get page value from ADRP or existing register value
					var pageVal uint64
					hasPage := false

					// Special case: when dst and src are the same (e.g., add x0, x0, #0x10)
					// This means we're adding an offset to the existing value
					if dstName == srcName {
						// Use the existing value in the register
						if v, ok := state.regs[srcName].(uint64); ok {
							pageVal = v
							hasPage = true
						} else if v, ok := state.pages[srcName]; ok {
							// Maybe it has a page value
							pageVal = v
							hasPage = true
						}
					} else {
						// Normal case: different source and destination
						pageVal, hasPage = state.pages[srcName]
						if !hasPage {
							// Fallback to regs
							if v, ok := state.regs[srcName].(uint64); ok {
								pageVal = v
								hasPage = true
							}
						}
					}

					if !hasPage {
						// No value for this register
						break
					}

					// Get offset
					offset, gotOffset := parseImmediate(inst.Args[2])
					if !gotOffset {
						break
					}

					addr := pageVal + offset
					// Try to resolve string immediately after computing addr
					if str, ok := TryResolveCString(img, addr); ok && str != "" {
						state.addAnnotation(&annotations, "0x%x = \"%s\"", addr, EscapeUnprintable([]byte(str)))
						// Prepare for potential std::string construction regardless of dst reg
						// (SSO often copies from a literal pointer in any temp register)
						srcVA := pc
						if pageVA, ok := state.sources[srcName]; ok {
							srcVA = pageVA
						}
						state.pendingStr = &PendingString{
							stringValue: str,
							stringAddr:  addr,
							sourceVA:    srcVA,
						}
						// Store a marker that this register points to a string literal
						if dstName == "x1" || dstName == "x0" {
							state.regs[dstName] = fmt.Sprintf("extracted:%s", str)
						} else {
							// For other registers, just store the address
							state.regs[dstName] = addr
						}
						// We already showed the string content above, no need to repeat it
					} else {
						state.addAnnotation(&annotations, "0x%x", addr)
						state.regs[dstName] = addr
					}
					// Set provenance: after setting state.regs, set sources[dstName] to ADRP VA that produced srcName, else current pc
					if srcVA, ok := state.sources[srcName]; ok {
						state.sources[dstName] = srcVA
					} else {
						state.sources[dstName] = pc
					}
					// Do NOT update state.pages[dstName] here (only ADRP sets pages)
				}
			}

		case arm64asm.MOV, arm64asm.MOVZ, arm64asm.MOVK:
			var dstName string
			if dst, ok := inst.Args[0].(arm64asm.Reg); ok {
				dstName = strings.ToLower(dst.String())
			} else {
				break
			}

			// Clear vtable state when register is overwritten
			state.clearVtableState(dstName)

			switch src := inst.Args[1].(type) {
			case arm64asm.Imm:
				// Immediate move
				state.regs[dstName] = uint64(src.Imm)
				state.sources[dstName] = pc
				annotations = append(annotations,
					fmt.Sprintf("%s = #%d", dstName, src.Imm))

			case arm64asm.Reg:
				// Register-to-register
				srcName := strings.ToLower(src.String())

				// Copy value if exists
				if val, exists := state.regs[srcName]; exists {
					state.regs[dstName] = val
					// Special case: if x0 gets a stack offset from a pending string
					if dstName == "x0" && state.pendingStr != nil {
						if stackOffset, ok := val.(uint64); ok && isStackOffset(stackOffset) {
							state.pendingStr.stackOffset = stackOffset
						}
					}
				} else {
					delete(state.regs, dstName)
				}

				// Copy provenance
				if srcVA, ok := state.sources[srcName]; ok {
					state.sources[dstName] = srcVA
				} else {
					delete(state.sources, dstName)
				}

				// Copy object source
				if objSrc, ok := state.objectSources[srcName]; ok {
					state.objectSources[dstName] = objSrc
				} else {
					delete(state.objectSources, dstName)
				}

				// Add annotation depending on what val was
				switch val := state.regs[srcName].(type) {
				case string:
					if strings.HasPrefix(val, "ptr_to:") {
						actualStr := val[7:]
						state.regs[dstName] = actualStr
						annotations = append(annotations,
							fmt.Sprintf("%s → %s (ptr to \"%s\")", srcName, dstName, EscapeUnprintable([]byte(actualStr))))
					} else {
						annotations = append(annotations,
							fmt.Sprintf("%s → %s (\"%s\")", srcName, dstName, EscapeUnprintable([]byte(val))))
					}
				case uint64:
					if str, ok := TryResolveCString(img, val); ok && str != "" {
						annotations = append(annotations,
							fmt.Sprintf("%s → %s (\"%s\")", srcName, dstName, EscapeUnprintable([]byte(str))))
					} else {
						annotations = append(annotations,
							fmt.Sprintf("%s → %s (0x%x)", srcName, dstName, val))
					}
				default:
					annotations = append(annotations,
						fmt.Sprintf("%s → %s", srcName, dstName))
				}

			default:
				// Fallback: unsupported operand type
			}

		case arm64asm.MOVN, arm64asm.ORR:
			// MOVN: move with NOT
			// ORR: can be used as MOV when second operand is WZR/XZR
			var dstName string
			if dst, ok := inst.Args[0].(arm64asm.Reg); ok {
				dstName = strings.ToLower(dst.String())
			} else {
				break
			}

			if inst.Op == arm64asm.ORR && len(inst.Args) >= 3 {
				// Check if this is ORR dst, wzr/xzr, src (MOV register pattern)
				if reg, ok := inst.Args[1].(arm64asm.Reg); ok {
					regName := strings.ToLower(reg.String())
					switch regName {
					case "wzr", "xzr":
						// Check if third arg is register (MOV Xd, Xn) or immediate (MOV Xd, #imm)
						if src, ok := inst.Args[2].(arm64asm.Reg); ok {
							// MOV dst, src (register to register)
							srcName := strings.ToLower(src.String())

							// Copy value from source to destination
							if val, exists := state.regs[srcName]; exists {
								state.regs[dstName] = val
								state.sources[dstName] = state.sources[srcName]
								state.addAnnotation(&annotations, "%s = %s", dstName, srcName)
							} else {
								state.addAnnotation(&annotations, "%s = %s", dstName, srcName)
							}

							// Track if this is copying from a function parameter
							// x0-x7 are argument registers, x19-x28 are callee-saved
							if strings.HasPrefix(srcName, "x") && strings.HasPrefix(dstName, "x") {
								srcNum := 0
								dstNum := 0
								fmt.Sscanf(srcName[1:], "%d", &srcNum)
								fmt.Sscanf(dstName[1:], "%d", &dstNum)

								// If moving from parameter register to callee-saved register
								if srcNum >= 0 && srcNum <= 7 && dstNum >= 19 && dstNum <= 28 {
									state.addAnnotation(&annotations, "saving %s to %s", srcName, dstName)
									// Mark this as a function parameter
									state.funcParams[dstName] = srcName
								}
							}

							// Also copy any other tracked state
							if page, exists := state.pages[srcName]; exists {
								state.pages[dstName] = page
							}
							if offset, exists := state.vtableOffsets[srcName]; exists {
								state.vtableOffsets[dstName] = offset
							}
							if source, exists := state.objectSources[srcName]; exists {
								state.objectSources[dstName] = source
							}
						} else {
							// MOV dst, #imm
							immVal, gotImm := parseImmediate(inst.Args[2])
							if gotImm {
								state.regs[dstName] = immVal
								state.sources[dstName] = pc
								annotations = append(annotations,
									fmt.Sprintf("%s = #%d", dstName, immVal))
							}
						}
					}
				}
			} else if inst.Op == arm64asm.MOVN {
				// MOVN: move with NOT
				if imm, ok := inst.Args[1].(arm64asm.Imm); ok {
					// MOVN loads the bitwise NOT of the immediate
					state.regs[dstName] = ^uint64(imm.Imm)
					state.sources[dstName] = pc
					annotations = append(annotations,
						fmt.Sprintf("%s = ~#%d", dstName, imm.Imm))
				}
			} else if inst.Op == arm64asm.MOVZ {
				// MOVZ: move with zero extend - common for loading immediate values
				if imm, ok := inst.Args[1].(arm64asm.Imm); ok {
					immVal := uint64(imm.Imm)
					state.regs[dstName] = immVal
					state.sources[dstName] = pc
					state.addAnnotation(&annotations, "%s = 0x%x", dstName, immVal)
				}
			} else if inst.Op == arm64asm.MOVK {
				// MOVK: move with keep - used to build larger immediates
				if imm, ok := inst.Args[1].(arm64asm.Imm); ok {
					// MOVK keeps other bits and sets specific bits based on shift
					// For simplicity, just track the immediate for now
					state.regs[dstName] = uint64(imm.Imm)
					state.sources[dstName] = pc
					state.addAnnotation(&annotations, "%s |= 0x%x", dstName, imm.Imm)
				}
			}

		case arm64asm.STR:
			if len(inst.Args) < 2 {
				break
			}

			srcReg, ok := inst.Args[0].(arm64asm.Reg)
			if !ok {
				break
			}
			srcName := strings.ToLower(srcReg.String())

			mem, ok := inst.Args[1].(arm64asm.MemImmediate)
			if !ok {
				break
			}
			baseName := strings.ToLower(mem.Base.String())

			switch baseName {
			case "sp", "x29":
				// Parse stack offset
				memStr := inst.Args[1].String()
				var stackOffset uint64
				if idx := strings.Index(memStr, "#"); idx >= 0 {
					offsetStr := memStr[idx+1:]
					if endIdx := strings.Index(offsetStr, "]"); endIdx >= 0 {
						offsetStr = offsetStr[:endIdx]
					}
					if strings.HasPrefix(offsetStr, "0x") {
						fmt.Sscanf(offsetStr[2:], "%x", &stackOffset)
					} else {
						fmt.Sscanf(offsetStr, "%d", &stackOffset)
					}
				}

				// Handle storing stack pointer indirection
				if val, ok := state.regs[srcName]; ok {
					if stackPtr, isUint := val.(uint64); isUint && isStackOffset(stackPtr) {
						if state.stackPointers == nil {
							state.stackPointers = make(map[uint64]uint64)
						}
						state.stackPointers[stackOffset] = stackPtr
						state.addAnnotation(&annotations, "[sp+#0x%x] ← ptr to [sp+#0x%x]", stackOffset, stackPtr)

						// Track that this stack location has a pointer to a string
					}
				}

				// Track object origin
				if source, ok := state.objectSources[srcName]; ok {
					state.objectSources[fmt.Sprintf("[%s+%d]", baseName, stackOffset)] = source
					state.addAnnotation(&annotations, "store object from %s", source)
				}
			default:
				// Other base registers ignored
			}

		case arm64asm.LDR:
			// Load from memory to register
			// Common patterns:
			// LDR x0, [sp, #N] - load from stack
			// LDR x0, [x0] - dereference pointer (vtable)
			// LDR q0, [x8] - load 128-bit SIMD value (string literal)
			if len(inst.Args) >= 2 {
				if reg, ok := inst.Args[0].(arm64asm.Reg); ok {
					regName := strings.ToLower(reg.String())
					if strings.HasPrefix(regName, "q") {
						// Handle SIMD register load
						if mem, ok := inst.Args[1].(arm64asm.MemImmediate); ok {
							baseName := strings.ToLower(mem.Base.String())
							if strAddr, ok := state.regs[baseName].(uint64); ok {
								// Try to read the string from memory
								if str, ok := TryResolveCString(img, strAddr); ok && str != "" {
									state.regs[regName] = str
									state.sources[regName] = strAddr
									state.addAnnotation(&annotations, "load \"%s\" → %s",
										EscapeUnprintable([]byte(str)), regName)
								}
							}
						}
					} else {
						// Existing logic for xN register loads
						dstName := regName

						// Check different load patterns
						if mem, ok := inst.Args[1].(arm64asm.MemImmediate); ok {
							baseName := strings.ToLower(mem.Base.String())

							switch baseName {
							case "sp", "x29":
								// Loading from stack
								// Get the offset from the string representation
								memStr := inst.Args[1].String()
								stackOffset := uint64(0)
								if idx := strings.Index(memStr, "#"); idx >= 0 {
									offsetStr := memStr[idx+1:]
									if endIdx := strings.Index(offsetStr, "]"); endIdx >= 0 {
										offsetStr = offsetStr[:endIdx]
									}
									if strings.HasPrefix(offsetStr, "0x") {
										fmt.Sscanf(offsetStr[2:], "%x", &stackOffset)
									} else {
										fmt.Sscanf(offsetStr, "%d", &stackOffset)
									}
								}
								// First check for pointer indirection - this takes priority
								// [sp,#56] contains a pointer to [sp,#48] where the string is
								if ptrOffset, hasPtr := state.stackPointers[stackOffset]; hasPtr {
									if str, ok := state.stdStrings[ptrOffset]; ok {
										state.regs[dstName] = str
										if srcVA, ok := state.stdStringSrcs[ptrOffset]; ok {
											state.sources[dstName] = srcVA
										} else {
											state.sources[dstName] = pc
										}
										state.addAnnotation(&annotations, "\"%s\" via ptr [sp+#0x%x] → [sp+#0x%x] → %s",
											EscapeUnprintable([]byte(str)), stackOffset, ptrOffset, dstName)
									} else {
										// Store the pointer value as-is for now
										state.regs[dstName] = ptrOffset
										state.sources[dstName] = pc
										state.addAnnotation(&annotations, "load ptr 0x%x from [sp+#0x%x] → %s", ptrOffset, stackOffset, dstName)
									}
								} else if str, ok := state.stdStrings[stackOffset]; ok {
									// Direct std::string at this location
									state.regs[dstName] = str // Store the actual string value
									if srcVA, ok := state.stdStringSrcs[stackOffset]; ok {
										state.sources[dstName] = srcVA
									} else {
										state.sources[dstName] = pc
									}
									state.addAnnotation(&annotations, "\"%s\" from [sp+#0x%x] → %s", EscapeUnprintable([]byte(str)), stackOffset, dstName)
								} else if stackOffset >= 8 {
									// Check if there's a std::string at offset-8
									// This handles the pattern where std::string object is at [sp+N] and c_str() is at [sp+N+8]
									if str, ok := state.stdStrings[stackOffset-8]; ok {
										state.regs[dstName] = str // Store the actual string value
										if srcVA, ok := state.stdStringSrcs[stackOffset-8]; ok {
											state.sources[dstName] = srcVA
										} else {
											state.sources[dstName] = pc
										}
										state.addAnnotation(&annotations, "\"%s\" from [sp+#0x%x] (via std::string at [sp+#0x%x]) → %s",
											EscapeUnprintable([]byte(str)), stackOffset, stackOffset-8, dstName)
									}
								}

								// Also track object sources (but don't override string values)
								stackKey := fmt.Sprintf("[%s+%d]", baseName, stackOffset)
								if source, ok := state.objectSources[stackKey]; ok {
									// This register now contains the object
									state.objectSources[dstName] = source
									// Only add annotation if we didn't find a string
									if _, isString := state.regs[dstName].(string); !isString {
										state.addAnnotation(&annotations, "load object from %s", source)
									}
								}
							}

							// Parse the immediate offset from the memory operand
							memStr := inst.Args[1].String()
							var memOffset uint64
							hasOffset := false
							if idx := strings.Index(memStr, "#"); idx >= 0 {
								offsetStr := memStr[idx+1:]
								if endIdx := strings.Index(offsetStr, "]"); endIdx >= 0 {
									offsetStr = offsetStr[:endIdx]
								}
								if strings.HasPrefix(offsetStr, "0x") {
									fmt.Sscanf(offsetStr[2:], "%x", &memOffset)
								} else {
									fmt.Sscanf(offsetStr, "%d", &memOffset)
								}
								hasOffset = true
							}

							// Clear vtable state when register is loaded with a new value
							// BUT do this AFTER we check if we're loading FROM a vtable pointer
							// Save the vtable state before clearing
							wasVtablePtr := state.isVtablePtr[baseName]

							// Now clear the destination register's vtable state
							state.clearVtableState(dstName)

							// Check if we're loading from a vtable pointer with an offset
							if wasVtablePtr && hasOffset && memOffset != 0 {
								// Loading function pointer from vtable at specific offset
								vtableOffset := memOffset
								if source, ok := state.objectSources[baseName]; ok {
									state.addAnnotation(&annotations, "load vtable+0x%x from %s", vtableOffset, source)
									// Store info for BLR to use
									state.vtableOffsets[dstName] = vtableOffset
									state.objectSources[dstName] = source
								} else {
									state.addAnnotation(&annotations, "load vtable+0x%x (no source)", vtableOffset)
									state.vtableOffsets[dstName] = vtableOffset
								}
							} else if vtableOffset, hasVtable := state.vtableOffsets[baseName]; hasVtable {
								// Loading function pointer from vtable (old path for compatibility)
								// This dst register will contain the function pointer
								if source, ok := state.objectSources[baseName]; ok {
									// Track that this register has a function pointer from a specific vtable
									state.addAnnotation(&annotations, "load vtable+0x%x from %s", vtableOffset, source)
									// Store info for BLR to use
									state.vtableOffsets[dstName] = vtableOffset
									state.objectSources[dstName] = source
								}
							} else if !hasOffset || memOffset == 0 {
								// Regular dereference with no offset - might be loading vtable pointer
								if source, ok := state.objectSources[baseName]; ok {
									// Loading vtable pointer from object
									state.objectSources[dstName] = source
									state.isVtablePtr[dstName] = true // Mark as vtable pointer
									state.addAnnotation(&annotations, "load vtable pointer")
								}
							}
						}
					} // Close the else block for non-SIMD registers
				}
			}

		case arm64asm.BLR:
			// Indirect call (virtual function call)
			if reg, ok := inst.Args[0].(arm64asm.Reg); ok {
				regName := strings.ToLower(reg.String())

				// Store register state for the reverse tool to use
				callArgs := resolveCallParams(state, img)

				// Try to resolve std::string parameters from stack
				callArgs = enrichWithStdStringParams(callArgs, regName, result.Listing, state)

				vtableOffset := state.vtableOffsets[regName]
				objectSource := state.objectSources[regName]

				var resolvedSymbol string

				// First try vtable resolution if we have the offset
				if vtableResolver != nil && vtableOffset != 0 {
					// Let the resolver try to find the class from the source annotation
					className := ""
					if objectSource != "" {
						// Use the resolver's built-in logic to find the class
						className = vtableResolver.FindVTableForObject(objectSource)
					}

					// If we still don't have a class name, try "Unknown" which the resolver
					// will attempt to match based on common offset patterns
					if className == "" {
						className = "Unknown"
					}

					_, symbol := vtableResolver.ResolveVirtualCall(className, vtableOffset)
					if symbol != "" {
						resolvedSymbol = demangleSymbol(symbol)
					}
				}

				// Build the target name and extra annotations based on what we resolved
				var targetName string
				extraAnnotations := []string{}

				// Determine target name and annotations based on what we found
				switch {
				case resolvedSymbol != "":
					// We successfully resolved the virtual call through vtable
					targetName = resolvedSymbol
					switch {
					case objectSource != "" && vtableOffset != 0:
						extraAnnotations = append(extraAnnotations, fmt.Sprintf("vtable+0x%x from %s", vtableOffset, objectSource))
					case vtableOffset != 0:
						extraAnnotations = append(extraAnnotations, fmt.Sprintf("vtable+0x%x", vtableOffset))
					}

				case vtableOffset != 0:
					// We found the vtable pattern but couldn't resolve the symbol
					targetName = fmt.Sprintf("[virtual] vtable+0x%x", vtableOffset)
					if objectSource != "" {
						extraAnnotations = append(extraAnnotations, fmt.Sprintf("object from %s", objectSource))
					}

				case objectSource != "":
					// We have an object source but no vtable offset
					targetName = fmt.Sprintf("[indirect] via %s", regName)
					extraAnnotations = append(extraAnnotations, fmt.Sprintf("object from %s", objectSource))

				default:
					// No vtable information found - just show it's indirect
					targetName = fmt.Sprintf("[indirect] via %s", regName)
				}

				finding := CallFinding{
					CallVA:    pc,
					Target:    targetName,
					TraceMax:  pc,
					Args:      callArgs,
					Backtrace: backtrace,
				}

				// Compute TraceMin based on actual parameters used
				var minTrace uint64
				for _, arg := range finding.Args {
					if arg.TraceVA != 0 && (minTrace == 0 || arg.TraceVA < minTrace) {
						minTrace = arg.TraceVA
					}
				}
				if minTrace == 0 {
					minTrace = pc // Fall back to the call itself
				}
				finding.TraceMin = minTrace

				// Add only the main target annotation to the BLR line
				state.addAnnotation(&annotations, "%s", finding.Target)
				result.Findings = append(result.Findings, finding)

				// Add the BLR instruction to the listing
				annotated.Annotations = annotations
				result.Listing = append(result.Listing, annotated)

				// Add vtable/object source info as a separate comment line if present
				if len(extraAnnotations) > 0 {
					commentInst := AnnotatedInst{
						VA:          pc,
						Mnemonic:    "",
						Operands:    "",
						Annotations: extraAnnotations,
					}
					result.Listing = append(result.Listing, commentInst)
				}

				// Instead of clearing x0 immediately, mark it as return-value and allow MOV propagation
				state.regs["x0"] = "return-value"
				state.sources["x0"] = pc
				state.x0ValidUntil = pc + 8 // Give more time for MOV to propagate

				// Clear x1-x7 parameter/caller-saved registers
				for i := 1; i <= 7; i++ {
					xReg := fmt.Sprintf("x%d", i)
					wReg := fmt.Sprintf("w%d", i)
					delete(state.regs, xReg)
					delete(state.sources, xReg)
					delete(state.regs, wReg)
					delete(state.sources, wReg)
				}

				// Skip the default adding at the end since we've already added the instruction
				pc += 4
				continue
			}

		case arm64asm.EOR:
			// XOR operation - always annotate it
			annotations = append(annotations, "[XOR detected]")

			// Also check for obfuscation pattern details
			if len(inst.Args) >= 3 {
				// EOR dst, src, src2 - can be register or immediate
				if dst, ok := inst.Args[0].(arm64asm.Reg); ok {
					dstName := strings.ToLower(dst.String())

					var xorKey uint64
					var hasXorKey bool

					// Check if third argument is immediate or register
					switch arg2 := inst.Args[2].(type) {
					case arm64asm.Imm:
						// Immediate XOR value
						xorKey = uint64(arg2.Imm)
						hasXorKey = true
					case arm64asm.Reg:
						// Register XOR - try to show register value if known
						reg2Name := strings.ToLower(arg2.String())
						if val, ok := state.regs[reg2Name]; ok {
							if intVal, ok := val.(uint64); ok {
								xorKey = intVal
								hasXorKey = true
								// Add annotation showing the XOR key value
								state.addAnnotation(&annotations, "XOR key: 0x%x", xorKey)
							} else if intVal, ok := val.(int64); ok && intVal > 0 {
								xorKey = uint64(intVal)
								hasXorKey = true
								// Add annotation showing the XOR key value
								state.addAnnotation(&annotations, "XOR key: 0x%x", xorKey)
							}
						} else {
							// Even if we don't know the exact value, note which register is the key
							state.addAnnotation(&annotations, "XOR with %s", reg2Name)
						}
					}

					// Try to decrypt if we have both the XOR key and the source value
					if hasXorKey && len(inst.Args) >= 2 {
						if srcReg, ok := inst.Args[1].(arm64asm.Reg); ok {
							srcName := strings.ToLower(srcReg.String())
							// Check if we know the source value (from LDRSB)
							if srcVal, ok := state.regs[srcName]; ok {
								var byteVal byte
								switch v := srcVal.(type) {
								case int64:
									// Sign-extended byte from LDRSB
									byteVal = byte(v & 0xFF)
								case uint64:
									byteVal = byte(v & 0xFF)
								}

								// Perform XOR decryption
								decrypted := byteVal ^ byte(xorKey&0xFF)

								// Use proper escape function for the decrypted byte
								escapedStr := EscapeUnprintable([]byte{decrypted})

								state.addAnnotation(&annotations, "decrypted: \"%s\" (0x%02x ^ 0x%02x = 0x%02x)",
									escapedStr, byteVal, byte(xorKey&0xFF), decrypted)
							}
						}
					}

					// Track that this register has been XORed
					if hasXorKey {
						if state.xorTransformed == nil {
							state.xorTransformed = make(map[string]uint64)
						}
						state.xorTransformed[dstName] = xorKey
					}

					// If we're XORing a value we previously loaded, note it
					if srcReg, ok := inst.Args[1].(arm64asm.Reg); ok {
						srcName := strings.ToLower(srcReg.String())
						// Check if this is sign-extended byte data (from LDRSB)
						if _, wasSignExtended := state.signExtendLoads[srcName]; wasSignExtended {
							state.addAnnotation(&annotations, "[XOR_OBFUSCATION: transforming sign-extended byte]")
						} else if val, hasVal := state.regs[srcName]; hasVal {
							// Check if this looks like character data being transformed
							if intVal, ok := val.(int64); ok && intVal >= -128 && intVal <= 127 {
								state.addAnnotation(&annotations, "[XOR_OBFUSCATION: transforming byte data]")
							}
						}
					}
				}
			}

		case arm64asm.LDRSB, arm64asm.LDRB:
			// Load signed/unsigned byte - often used in XOR obfuscation loops
			if len(inst.Args) >= 2 {
				if dst, ok := inst.Args[0].(arm64asm.Reg); ok {
					dstName := strings.ToLower(dst.String())

					// Always annotate LDRSB as it's commonly used in XOR loops
					if inst.Op == arm64asm.LDRSB {
						state.addAnnotation(&annotations, "[sign-extended byte load - XOR pattern]")

						// Track that we're doing sign-extended loads (common in XOR patterns)
						if state.signExtendLoads == nil {
							state.signExtendLoads = make(map[string]bool)
						}
						state.signExtendLoads[dstName] = true
					}

					// Check different memory addressing modes
					switch mem := inst.Args[1].(type) {
					case arm64asm.MemImmediate:
						baseName := strings.ToLower(mem.Base.String())

						// If the base register points to a string we know about
						if addr, ok := state.regs[baseName].(uint64); ok {
							if str, ok := TryResolveCString(img, addr); ok && str != "" {
								state.addAnnotation(&annotations, "loading from \"%s\"", EscapeUnprintable([]byte(str)))
							}
						}
					case arm64asm.MemExtend:
						// Register offset addressing like [x26,x19]
						// Common in loops iterating over arrays/strings
						if inst.Op == arm64asm.LDRSB {
							state.addAnnotation(&annotations, "[array/string access]")
						}

						// Try to resolve the base address and offset
						baseName := strings.ToLower(mem.Base.String())
						offsetName := strings.ToLower(mem.Index.String())

						// If base register points to a string
						if addr, ok := state.regs[baseName].(uint64); ok {
							if str, ok := TryResolveCString(img, addr); ok && str != "" {
								state.addAnnotation(&annotations, "from string \"%s\"", EscapeUnprintable([]byte(str)))

								// If we also know the offset value
								if offsetVal, ok := state.regs[offsetName]; ok {
									var offset int64
									switch v := offsetVal.(type) {
									case int64:
										offset = v
									case uint64:
										offset = int64(v)
									}

									if offset >= 0 && offset < int64(len(str)) {
										loadedByte := str[offset]
										if inst.Op == arm64asm.LDRSB {
											// Sign-extend for LDRSB
											state.regs[dstName] = int64(int8(loadedByte))
										} else {
											state.regs[dstName] = uint64(loadedByte)
										}
										state.addAnnotation(&annotations, "loaded: '%c' (0x%02x) at offset %d",
											loadedByte, loadedByte, offset)
									}
								}
							}
						}
					}
				}
			}

		case arm64asm.RET:
			// Return - stop here
			annotated.Annotations = annotations
			result.Listing = append(result.Listing, annotated)
			return result, nil

		case arm64asm.B:
			// Unconditional branch - check if it's a tail call
			if pcRel, ok := inst.Args[0].(arm64asm.PCRel); ok {
				targetAddr := uint64(int64(pc) + int64(pcRel))

				// Check if this is likely a tail call (branch to another function)
				// We'll follow it if it's not a local branch (outside our current function range)
				if targetAddr < startVA || targetAddr >= startVA+uint64(maxInsns*4) {
					// This looks like a tail call to another function
					// Try to resolve the target function name
					targetName := ""
					if sym, exists := symMap[targetAddr]; exists {
						targetName = CachedDemangle(sym)
					} else {
						targetName = fmt.Sprintf("sub_%x", targetAddr)
					}

					// Add the branch instruction to our listing
					annotated.Annotations = append(annotations, fmt.Sprintf("[TAIL CALL to %s]", targetName))
					result.Listing = append(result.Listing, annotated)

					// Build the new backtrace for the tail call
					newBacktrace := append([]string{}, backtrace...)
					if len(newBacktrace) == 0 {
						// First function in the chain - try to get the current function name
						if currentFunc := findFunctionAt(img, startVA); currentFunc != nil {
							newBacktrace = append(newBacktrace, CachedDemangle(currentFunc.Name))
						} else {
							// Try to find the function by searching for the closest symbol
							closestSym := ""
							closestAddr := uint64(0)
							for addr, name := range symMap {
								if addr <= startVA && addr > closestAddr {
									closestAddr = addr
									closestSym = name
								}
							}
							if closestSym != "" {
								newBacktrace = append(newBacktrace, CachedDemangle(closestSym))
							} else {
								newBacktrace = append(newBacktrace, fmt.Sprintf("sub_%x", startVA))
							}
						}
					}
					newBacktrace = append(newBacktrace, targetName)

					// Follow the tail call by recursively analyzing the target
					// Limit recursion depth to avoid infinite loops
					remainingInsns := maxInsns - len(result.Listing)
					if remainingInsns > SearchWindowMedium { // Only follow if we have space for more instructions
						// Pass the current register state to the tail-called function
						// This preserves parameter registers (x0-x7) across the tail call
						tailResult, err := TraceDisasmWithState(img, targetAddr, remainingInsns, newBacktrace, state)
						if err == nil && tailResult != nil {
							// Append the tail call's instructions to our result
							result.Listing = append(result.Listing, tailResult.Listing...)
							// Update findings with the backtrace
							for _, finding := range tailResult.Findings {
								if len(finding.Backtrace) == 0 {
									finding.Backtrace = newBacktrace
								}
								result.Findings = append(result.Findings, finding)
							}
						}
					}
					return result, nil
				}
			}

		case arm64asm.STUR:
			// Store unscaled (can use negative offsets)
			// STUR q0, [sp, #97] - store SIMD register to stack
			if len(inst.Args) >= 2 {
				if reg, ok := inst.Args[0].(arm64asm.Reg); ok {
					regName := strings.ToLower(reg.String())
					if strings.HasPrefix(regName, "q") {
						// Storing SIMD register
						if mem, ok := inst.Args[1].(arm64asm.MemImmediate); ok {
							baseName := strings.ToLower(mem.Base.String())

							// Get the offset from the instruction
							memStr := inst.Args[1].String()
							stackOffset := uint64(0)
							if idx := strings.Index(memStr, "#"); idx >= 0 {
								offsetStr := memStr[idx+1:]
								if endIdx := strings.Index(offsetStr, "]"); endIdx >= 0 {
									offsetStr = offsetStr[:endIdx]
								}
								if strings.HasPrefix(offsetStr, "0x") {
									fmt.Sscanf(offsetStr[2:], "%x", &stackOffset)
								} else {
									fmt.Sscanf(offsetStr, "%d", &stackOffset)
								}
							}

							// Check if we have a string in this SIMD register
							if str, ok := state.regs[regName].(string); ok {
								// Store the string at this stack location
								state.stdStrings[stackOffset] = str
								if srcVA, ok := state.sources[regName]; ok {
									state.stdStringSrcs[stackOffset] = srcVA
								}

								// Also store at offset-1 for std::string small string optimization
								// The std::string object starts 1 byte before where the actual string data is stored
								if stackOffset > 0 {
									state.stdStrings[stackOffset-1] = str
									if srcVA, ok := state.sources[regName]; ok {
										state.stdStringSrcs[stackOffset-1] = srcVA
									}
								}

								state.addAnnotation(&annotations, "store \"%s\" → [%s+#0x%x]",
									EscapeUnprintable([]byte(str)), baseName, stackOffset)
							}
						}
					}
				}
			}

		}

		annotated.Annotations = annotations
		result.Listing = append(result.Listing, annotated)

		pc += 4
	}

	return result, nil
}

// buildSymbolMap creates address -> symbol name mapping
func buildSymbolMap(img *elfx.Image) map[uint64]string {
	symMap := make(map[uint64]string)

	// Add dynamic symbols
	for _, sym := range img.Dynsyms {
		if sym.Addr != 0 && sym.Name != "" {
			symMap[sym.Addr] = sym.Name
		}
	}

	// Add static symbols (may override dynamic)
	for _, sym := range img.Syms {
		if sym.Addr != 0 && sym.Name != "" {
			symMap[sym.Addr] = sym.Name
		}
	}

	// Add PLT entries - this is crucial for XXTEA detection
	for _, pltRel := range img.PLTRels {
		if pltRel.PLTAddr != 0 && pltRel.SymName != "" {
			symMap[pltRel.PLTAddr] = pltRel.SymName
		}
	}

	return symMap
}

// resolveCallParams attempts to resolve function call parameters for first 5 args
// Following ARM64 calling convention: x0-x7 for integer/pointer args
func resolveCallParams(state *RegisterState, img *elfx.Image) []ParamValue {
	params := []ParamValue{}

	// Check first 5 parameters (x0/w0 through x4/w4)
	// We try both x and w versions since either could be used
	for i := 0; i < 5; i++ {
		xReg := fmt.Sprintf("x%d", i)
		wReg := fmt.Sprintf("w%d", i)

		// Check if we have a value for the x register
		if val, hasX := state.regs[xReg]; hasX {
			traceVA := state.sources[xReg]

			// Check what type of value we have
			switch v := val.(type) {
			case string:
				switch {
				case strings.HasPrefix(v, "ptr_to:"):
					// .c_str() case
					actualStr := v[7:]
					params = append(params, ParamValue{
						Reg:     xReg,
						Value:   actualStr,
						From:    "std::string .c_str()",
						TraceVA: traceVA,
					})
				case strings.HasPrefix(v, "extracted:"):
					// Extracted string literal case
					actualStr := v[10:]
					params = append(params, ParamValue{
						Reg:     xReg,
						Value:   actualStr,
						From:    "std::string extracted",
						TraceVA: traceVA,
					})
				case strings.HasPrefix(v, "member_string:"):
					// Member std::string case - we know it's a std::string but don't know the value
					// Mark it as std::string for signature detection
					params = append(params, ParamValue{
						Reg:     xReg,
						Value:   "[std::string member]",
						From:    "std::string member",
						TraceVA: traceVA,
					})
				default:
					// Fallback for other markers
					params = append(params, ParamValue{
						Reg:     xReg,
						Value:   v,
						From:    "unknown",
						TraceVA: traceVA,
					})
				}
			case uint64:
				// Check if this is a stack offset with a std::string
				if isStackOffset(v) {
					// This looks like a stack offset
					if str, ok := state.stdStrings[v]; ok {
						// We have a std::string at this stack location
						params = append(params, ParamValue{
							Reg:     xReg,
							Value:   str,
							From:    "std::string&",
							TraceVA: traceVA,
						})
					} else {
						// Just a stack address without known content
						params = append(params, ParamValue{
							Reg:     xReg,
							Value:   v,
							From:    "stack addr",
							TraceVA: traceVA,
						})
					}
				} else {
					// Pointer value - try to resolve as string
					if s, ok := TryResolveCString(img, v); ok {
						// Determine source type based on how we got the value
						sourceType := "stack_ref"
						if _, hasPage := state.pages[xReg]; hasPage {
							sourceType = "adrp+add"
						}
						params = append(params, ParamValue{
							Reg:     xReg,
							Value:   s,
							From:    sourceType,
							TraceVA: traceVA,
						})
					} else {
						// Just an address/pointer
						params = append(params, ParamValue{
							Reg:     xReg,
							Value:   v,
							From:    "pointer",
							TraceVA: traceVA,
						})
					}
				}
			default:
				// Other types (like "return-value")
				params = append(params, ParamValue{
					Reg:     xReg,
					Value:   v,
					From:    "unknown",
					TraceVA: traceVA,
				})
			}
		} else if val, hasW := state.regs[wReg]; hasW {
			// 32-bit integer value
			traceVA := state.sources[wReg]
			params = append(params, ParamValue{
				Reg:     wReg,
				Value:   val,
				From:    "immediate",
				TraceVA: traceVA,
			})
		}
	}

	return params
}

// demangleSymbol attempts to demangle a C++ symbol name
func demangleSymbol(symbol string) string {
	demangled := CachedDemangle(symbol)
	if demangled == "" {
		return symbol
	}
	return demangled
}

// GlobalStringLocation tracks where a string literal is stored globally
type GlobalStringLocation struct {
	StringAddr  uint64
	StringValue string
	GlobalAddr  uint64 // Where the string address is stored
}

// FindGlobalStringMappings scans the entire binary for ADRP+ADD+STR patterns
// that create string literals and store them to global memory locations
func FindGlobalStringMappings(img *elfx.Image) map[uint64]GlobalStringLocation {
	mappings := make(map[uint64]GlobalStringLocation)

	// Scan all executable sections for the pattern
	sections := []struct {
		data []byte
		va   uint64
	}{}

	// Add .text section
	if img.Text.Size > 0 && img.Text.Off+img.Text.Size <= uint64(len(img.All)) {
		sections = append(sections, struct {
			data []byte
			va   uint64
		}{
			data: img.All[img.Text.Off : img.Text.Off+img.Text.Size],
			va:   img.Text.VA,
		})
	}

	// Add executable LOAD segments
	for _, seg := range img.Loads {
		if seg.Flags&0x1 != 0 && seg.Off+seg.Filesz <= uint64(len(img.All)) { // Executable
			sections = append(sections, struct {
				data []byte
				va   uint64
			}{
				data: img.All[seg.Off : seg.Off+seg.Filesz],
				va:   seg.Vaddr,
			})
		}
	}

	for _, section := range sections {
		data := section.data
		baseVA := section.va

		// Track register state across instructions
		regValues := make(map[string]uint64)

		// Scan through instructions looking for ADRP+ADD+STR pattern
		for offset := uint64(0); offset+12 <= uint64(len(data)); offset += 4 {
			pc := baseVA + offset

			// Decode current instruction
			inst, err := arm64asm.Decode(data[offset : offset+4])
			if err != nil {
				continue
			}

			switch inst.Op {
			case arm64asm.ADRP:
				// Track page addresses
				if len(inst.Args) >= 2 {
					if dst, ok := inst.Args[0].(arm64asm.Reg); ok {
						if imm, ok := inst.Args[1].(arm64asm.PCRel); ok {
							pageAddr := (pc &^ 0xFFF) + uint64(imm)
							regValues[strings.ToLower(dst.String())] = pageAddr
						}
					}
				}

			case arm64asm.ADD:
				// Look for ADD that completes ADRP+ADD for string literal
				if len(inst.Args) >= 3 {
					if dst, ok := inst.Args[0].(arm64asm.Reg); ok {
						if src, ok := inst.Args[1].(arm64asm.Reg); ok {
							dstName := strings.ToLower(dst.String())
							srcName := strings.ToLower(src.String())

							// Check if source register has a page value from ADRP
							if pageVal, hasPage := regValues[srcName]; hasPage {
								// Get the add offset
								addOffset, gotOffset := parseImmediate(inst.Args[2])
								if gotOffset && addOffset > 0 {
									stringAddr := pageVal + addOffset

									// Try to read string at this address
									if str, ok := TryResolveCString(img, stringAddr); ok && str != "" {
										// Update register to point to this string
										regValues[dstName] = stringAddr

										// Look ahead for STR instruction that stores this to memory
										if offset+8 <= uint64(len(data)) {
											storeInst, err := arm64asm.Decode(data[offset+4 : offset+8])
											if err == nil && storeInst.Op == arm64asm.STR {
												// Check if it's storing our register
												if len(storeInst.Args) >= 2 {
													if storeReg, ok := storeInst.Args[0].(arm64asm.Reg); ok &&
														strings.ToLower(storeReg.String()) == dstName {
														// This is storing the string address to memory
														// We found the pattern: ADRP+ADD+STR
														mappings[stringAddr] = GlobalStringLocation{
															StringAddr:  stringAddr,
															StringValue: str,
															GlobalAddr:  pc + 4, // Address of the STR instruction (approximation)
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return mappings
}

// FindStringLiteralsNearCall searches for string literals near a specific call site
// by looking backwards from the call for ADRP+ADD patterns that load strings
func FindStringLiteralsNearCall(img *elfx.Image, callAddr uint64) []string {
	var foundStrings []string

	// Search backwards from the call site
	const searchWindow = SearchWindowMedium
	startAddr := callAddr
	if callAddr > searchWindow*4 {
		startAddr = callAddr - searchWindow*4
	}

	// Read the code section around the call
	off, ok := img.VA2Off(startAddr)
	if !ok || off+searchWindow*4 > uint64(len(img.All)) {
		return foundStrings // Return empty if we can't read
	}
	data := img.All[off : off+searchWindow*4]

	// Track ADRP page values
	pageRegs := make(map[string]uint64)

	// Scan instructions looking for ADRP+ADD patterns
	for i := 0; i < len(data)-3 && startAddr+uint64(i) < callAddr; i += 4 {
		pc := startAddr + uint64(i)

		// Decode the instruction
		inst, err := arm64asm.Decode(data[i : i+4])
		if err != nil {
			continue
		}

		switch inst.Op {
		case arm64asm.ADRP:
			// ADRP loads a page address
			if len(inst.Args) >= 2 {
				if reg, ok := inst.Args[0].(arm64asm.Reg); ok {
					if pcRel, ok := inst.Args[1].(arm64asm.PCRel); ok {
						page := uint64(int64(pc) + int64(pcRel))
						page &= ^uint64(0xfff) // Page align
						pageRegs[strings.ToLower(reg.String())] = page
					}
				}
			}

		case arm64asm.ADD:
			// ADD might complete an ADRP+ADD pattern
			if len(inst.Args) >= 3 {
				if dst, ok := inst.Args[0].(arm64asm.Reg); ok {
					if src, ok := inst.Args[1].(arm64asm.Reg); ok {
						dstName := strings.ToLower(dst.String())
						srcName := strings.ToLower(src.String())

						// Check if source has a page value from ADRP
						if pageVal, hasPage := pageRegs[srcName]; hasPage {
							// Get the offset using parseImmediate
							offset, ok := parseImmediate(inst.Args[2])
							if !ok {
								continue
							}

							// Try to read string at this address
							addr := pageVal + offset
							if str, ok := TryResolveCString(img, addr); ok && str != "" {
								foundStrings = append(foundStrings, str)
								// Also track this for the destination register
								pageRegs[dstName] = addr
							}
						}
					}
				}
			}
		}
	}

	return foundStrings
}
