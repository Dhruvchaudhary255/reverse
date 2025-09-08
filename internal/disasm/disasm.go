// Package disasm defines a common instruction representation used
// across architecture-specific disassemblers.
package disasm

// Inst is a simplified decoded instruction.
type Inst struct {
	VA   uint64  // virtual address of instruction
	Text string  // formatted disassembly string
	Op   string  // mnemonic in lowercase
	Raw  [4]byte // raw encoding (for BL target calc)
}

// Stream is a linear sequence of instructions.
type Stream []Inst
