// Package elfx provides helpers for opening ELF binaries, locating sections, and mapping virtual addresses to file offsets.
package elfx

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
	"syscall"
)

type Image struct {
	Path      string
	File      *elf.File
	All       []byte
	Loads     []Seg
	Text      Section
	Rodata    Section
	Data      Section
	DataRelRo Section
	PLT       Section
	Dynsyms   []DynSym
	Syms      []DynSym
	PLTStubs  []PLTStub
	PLTRels   []PLTRel
	f         *os.File
}

type Seg struct {
	Vaddr, Off, Filesz uint64
	Flags              elf.ProgFlag
}

type Section struct {
	Name          string
	VA, Off, Size uint64
}

type DynSym struct {
	Name  string
	Addr  uint64
	IsPLT bool
}

type PLTStub struct {
	Addr    uint64
	GOTAddr uint64
	Index   int
}

type PLTRel struct {
	Offset   uint64
	SymIndex uint32
	SymName  string
	PLTAddr  uint64
}

func Open(path string) (*Image, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open elf: %w", err)
	}

	of, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("open file: %w", err)
	}

	fi, err := of.Stat()
	if err != nil {
		of.Close()
		f.Close()
		return nil, fmt.Errorf("stat file: %w", err)
	}

	all, err := syscall.Mmap(int(of.Fd()), 0, int(fi.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		of.Close()
		f.Close()
		return nil, fmt.Errorf("mmap file: %w", err)
	}

	im := &Image{Path: path, File: f, All: all, f: of}
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		im.Loads = append(im.Loads, Seg{
			Vaddr:  uint64(p.Vaddr),
			Off:    uint64(p.Off),
			Filesz: uint64(p.Filesz),
			Flags:  p.Flags,
		})
	}

	// Use true sections if present.
	for _, s := range f.Sections {
		switch s.Name {
		case ".text":
			im.Text = Section{s.Name, s.Addr, s.Offset, s.Size}
		case ".rodata", ".rodata.rel.ro":
			if im.Rodata.Size == 0 {
				im.Rodata = Section{s.Name, s.Addr, s.Offset, s.Size}
			}
		case ".data":
			im.Data = Section{s.Name, s.Addr, s.Offset, s.Size}
		case ".data.rel.ro":
			im.DataRelRo = Section{s.Name, s.Addr, s.Offset, s.Size}
			if im.Rodata.Size == 0 {
				im.Rodata = Section{s.Name, s.Addr, s.Offset, s.Size}
			}
		case ".plt":
			im.PLT = Section{s.Name, s.Addr, s.Offset, s.Size}
		}
	}

	// Load dynamic symbols for PLT resolution
	im.loadDynamicSymbols()

	// Load static symbols as fallback for stripped binaries
	im.loadStaticSymbols()

	// Parse PLT stubs first to build PLT address → GOT mapping
	im.parsePLTStubs()

	// Parse PLT relocations and match them to PLT stubs
	im.parsePLTRelocations()

	// Fallbacks if stripped.
	if im.Text.Size == 0 {
		for _, l := range im.Loads {
			if l.Flags&elf.PF_X != 0 && l.Filesz > 0 {
				im.Text = Section{"LOAD(exec)", l.Vaddr, l.Off, l.Filesz}
				break
			}
		}
	}
	if im.Rodata.Size == 0 {
		for _, l := range im.Loads {
			if (l.Flags&elf.PF_R != 0) && (l.Flags&elf.PF_W == 0) && l.Filesz > 0 {
				im.Rodata = Section{"LOAD(ro)", l.Vaddr, l.Off, l.Filesz}
				break
			}
		}
	}
	return im, nil
}

// Close unmaps the memory and closes the underlying files.
func (im *Image) Close() error {
	var err1, err2 error
	if im.All != nil {
		err1 = syscall.Munmap(im.All)
		im.All = nil
	}
	if im.f != nil {
		err2 = im.f.Close()
		im.f = nil
	}
	if im.File != nil {
		err3 := im.File.Close()
		if err3 != nil && err2 == nil {
			err2 = err3
		}
		im.File = nil
	}
	if err1 != nil {
		return err1
	}
	return err2
}

// VA2Off translates a virtual address into a file offset
// using PT_LOAD segments. It returns false if VA is unmapped.
func (im *Image) VA2Off(va uint64) (uint64, bool) {
	for _, l := range im.Loads {
		if va >= l.Vaddr && va < l.Vaddr+l.Filesz {
			return l.Off + (va - l.Vaddr), true
		}
	}
	return 0, false
}

// SliceVA returns a subslice of the mapped file corresponding to the virtual address range [va, va+size).
// It returns (nil, false) if the VA is unmapped or the range is out of bounds.
func (im *Image) SliceVA(va uint64, size uint64) ([]byte, bool) {
	off, ok := im.VA2Off(va)
	if !ok {
		return nil, false
	}
	if size == 0 {
		return []byte{}, true
	}
	end := off + size
	if end > uint64(len(im.All)) {
		return nil, false
	}
	return im.All[off:end], true
}

// ReadBytesVA reads exactly size bytes from a virtual address.
// Returns false if VA is unmapped or size extends beyond file bounds.
func (im *Image) ReadBytesVA(va uint64, size int) ([]byte, bool) {
	if size <= 0 {
		return []byte{}, true
	}
	return im.SliceVA(va, uint64(size))
}

// InRodata reports whether the VA lies within the chosen
// read-only data region.
func (im *Image) InRodata(va uint64) bool {
	return im.Rodata.Size != 0 && va >= im.Rodata.VA && va < im.Rodata.VA+im.Rodata.Size
}

// InData reports whether VA lies in .data
func (im *Image) InData(va uint64) bool {
	return im.Data.Size != 0 && va >= im.Data.VA && va < im.Data.VA+im.Data.Size
}

// InDataRelRo reports whether VA lies in .data.rel.ro
func (im *Image) InDataRelRo(va uint64) bool {
	return im.DataRelRo.Size != 0 && va >= im.DataRelRo.VA && va < im.DataRelRo.VA+im.DataRelRo.Size
}

// loadDynamicSymbols loads dynamic symbols from .dynsym section
// to enable PLT resolution.
func (im *Image) loadDynamicSymbols() {
	if im.File == nil {
		return
	}

	dynsymSection := im.File.Section(".dynsym")
	if dynsymSection == nil {
		return
	}

	dynsyms, err := im.File.DynamicSymbols()
	if err != nil {
		return
	}

	for _, sym := range dynsyms {
		// Check if this is a PLT entry by looking for @plt suffix
		isPLT := strings.HasSuffix(sym.Name, "@plt")

		im.Dynsyms = append(im.Dynsyms, DynSym{
			Name:  sym.Name,
			Addr:  sym.Value,
			IsPLT: isPLT,
		})
	}
}

// loadStaticSymbols loads static symbols from .symtab section as fallback
// for stripped binaries where .dynsym doesn't contain PLT symbols.
func (im *Image) loadStaticSymbols() {
	if im.File == nil {
		return
	}

	syms, err := im.File.Symbols()
	if err != nil {
		return // .symtab not available or stripped
	}

	for _, sym := range syms {
		// Skip undefined symbols
		if sym.Value == 0 {
			continue
		}

		// Check if this is a PLT entry by looking for @plt suffix
		isPLT := strings.HasSuffix(sym.Name, "@plt")

		im.Syms = append(im.Syms, DynSym{
			Name:  sym.Name,
			Addr:  sym.Value,
			IsPLT: isPLT,
		})
	}
}

// parsePLTRelocations parses .rela.plt relocations to map PLT entries to symbols.
// This is the proper way to resolve PLT entries in ELF binaries.
func (im *Image) parsePLTRelocations() {
	if im.File == nil {
		return
	}

	// Look for .rela.plt section (ARM64 uses RELA relocations)
	relaPltSection := im.File.Section(".rela.plt")
	if relaPltSection == nil {
		// Fallback to .rel.plt (though ARM64 typically uses RELA)
		relPltSection := im.File.Section(".rel.plt")
		if relPltSection == nil {
			return // No PLT relocations found
		}
		// Handle REL relocations (8 bytes each on 32-bit, 8 bytes on 64-bit)
		im.parseRELPLTRelocations(relPltSection)
		return
	}

	// Handle RELA relocations (24 bytes each on 64-bit ARM)
	im.parseRELAPLTRelocations(relaPltSection)
}

// parseRELAPLTRelocations parses .rela.plt section (24-byte RELA entries)
func (im *Image) parseRELAPLTRelocations(section *elf.Section) {
	data, err := section.Data()
	if err != nil {
		return
	}

	// Each RELA entry is 24 bytes: r_offset(8) + r_info(8) + r_addend(8)
	entrySize := 24
	numEntries := len(data) / entrySize

	// Get dynamic symbols for name resolution
	dynsyms, err := im.File.DynamicSymbols()
	if err != nil {
		return
	}

	for i := 0; i < numEntries; i++ {
		offset := i * entrySize

		// Parse RELA entry
		r_offset := uint64(data[offset]) | uint64(data[offset+1])<<8 | uint64(data[offset+2])<<16 | uint64(data[offset+3])<<24 |
			uint64(data[offset+4])<<32 | uint64(data[offset+5])<<40 | uint64(data[offset+6])<<48 | uint64(data[offset+7])<<56

		r_info := uint64(data[offset+8]) | uint64(data[offset+9])<<8 | uint64(data[offset+10])<<16 | uint64(data[offset+11])<<24 |
			uint64(data[offset+12])<<32 | uint64(data[offset+13])<<40 | uint64(data[offset+14])<<48 | uint64(data[offset+15])<<56

		// Extract symbol index from r_info (upper 32 bits on 64-bit)
		symIndex := uint32(r_info >> 32)

		// Get symbol name
		var symName string
		if int(symIndex) < len(dynsyms) && symIndex > 0 {
			symName = dynsyms[symIndex-1].Name // Symbols are 1-indexed in relocations
		}

		// Find corresponding PLT stub by matching GOT address
		var pltAddr uint64
		for _, stub := range im.PLTStubs {
			if stub.GOTAddr == r_offset {
				pltAddr = stub.Addr
				break
			}
		}

		im.PLTRels = append(im.PLTRels, PLTRel{
			Offset:   r_offset,
			SymIndex: symIndex,
			SymName:  symName,
			PLTAddr:  pltAddr,
		})
	}
}

// parseRELPLTRelocations parses .rel.plt section (16-byte REL entries on 64-bit)
func (im *Image) parseRELPLTRelocations(section *elf.Section) {
	data, err := section.Data()
	if err != nil {
		return
	}

	// Each REL entry is 16 bytes: r_offset(8) + r_info(8)
	entrySize := 16
	numEntries := len(data) / entrySize

	// Get dynamic symbols for name resolution
	dynsyms, err := im.File.DynamicSymbols()
	if err != nil {
		return
	}

	for i := 0; i < numEntries; i++ {
		offset := i * entrySize

		// Parse REL entry
		r_offset := uint64(data[offset]) | uint64(data[offset+1])<<8 | uint64(data[offset+2])<<16 | uint64(data[offset+3])<<24 |
			uint64(data[offset+4])<<32 | uint64(data[offset+5])<<40 | uint64(data[offset+6])<<48 | uint64(data[offset+7])<<56

		r_info := uint64(data[offset+8]) | uint64(data[offset+9])<<8 | uint64(data[offset+10])<<16 | uint64(data[offset+11])<<24 |
			uint64(data[offset+12])<<32 | uint64(data[offset+13])<<40 | uint64(data[offset+14])<<48 | uint64(data[offset+15])<<56

		// Extract symbol index from r_info
		symIndex := uint32(r_info >> 32)

		// Get symbol name
		var symName string
		if int(symIndex) < len(dynsyms) && symIndex > 0 {
			symName = dynsyms[symIndex-1].Name
		}

		// Find corresponding PLT stub by matching GOT address
		var pltAddr uint64
		for _, stub := range im.PLTStubs {
			if stub.GOTAddr == r_offset {
				pltAddr = stub.Addr
				break
			}
		}

		im.PLTRels = append(im.PLTRels, PLTRel{
			Offset:   r_offset,
			SymIndex: symIndex,
			SymName:  symName,
			PLTAddr:  pltAddr,
		})
	}
}

// parsePLTStubs scans the .plt section and parses all PLT stubs to build
// a mapping of PLT addresses to GOT entries. This enables PLT resolution
// even when symbol information is stripped.
func (im *Image) parsePLTStubs() {
	if im.PLT.Size == 0 {
		return // No PLT section
	}

	// ARM64 PLT layout:
	// PLT[0] = PLT resolver stub (16 bytes)
	// PLT[1], PLT[2], ... = function stubs (16 bytes each)

	stubSize := uint64(16) // Each ARM64 PLT stub is 16 bytes

	// Skip PLT[0] (resolver) and parse function stubs
	for i := uint64(1); i*stubSize < im.PLT.Size; i++ {
		stubAddr := im.PLT.VA + i*stubSize

		// Try to parse this stub
		if gotAddr, ok := im.parsePLTStub(stubAddr); ok {
			im.PLTStubs = append(im.PLTStubs, PLTStub{
				Addr:    stubAddr,
				GOTAddr: gotAddr,
				Index:   int(i),
			})
		}
	}
}

// IsPLTEntry returns true if the given virtual address lies within
// the PLT section, indicating it's a dynamically linked function stub.
func (im *Image) IsPLTEntry(va uint64) bool {
	if im.PLT.Size == 0 {
		return false
	}
	return va >= im.PLT.VA && va < im.PLT.VA+im.PLT.Size
}

// ResolvePLTTarget attempts to resolve a PLT entry to its actual function address.
// For PLT entries that correspond to functions within the same binary,
// this returns the real function address. For external functions,
// it returns the original address and false.
func (im *Image) ResolvePLTTarget(pltAddr uint64) (uint64, bool) {
	// First try relocation-based resolution (most accurate)
	if resolved, ok := im.resolvePLTFromRelocations(pltAddr); ok {
		return resolved, true
	}

	// Fallback to dynamic symbol-based resolution
	if resolved, ok := im.resolvePLTFromSymbols(pltAddr, im.Dynsyms); ok {
		return resolved, true
	}

	// Fallback to static symbols for stripped binaries
	if resolved, ok := im.resolvePLTFromSymbols(pltAddr, im.Syms); ok {
		return resolved, true
	}

	// Fallback to pattern-based PLT stub resolution
	if resolved, ok := im.resolvePLTFromStubs(pltAddr); ok {
		return resolved, true
	}

	// Final fallback: try parsing the PLT stub directly
	gotAddr, ok := im.parsePLTStub(pltAddr)
	if !ok {
		return pltAddr, false
	}

	// Read the GOT entry
	targetAddr, ok := im.readGOTEntry(gotAddr)
	if !ok {
		return pltAddr, false
	}

	// Check if this points to a valid function within our binary
	if targetAddr != 0 && im.isValidFunctionAddress(targetAddr) {
		return targetAddr, true
	}

	return pltAddr, false
}

// resolvePLTFromRelocations resolves a PLT entry using relocation information.
// This is the most accurate method as it uses the actual relocation data.
func (im *Image) resolvePLTFromRelocations(pltAddr uint64) (uint64, bool) {
	// Find the relocation entry for this PLT address
	for _, rel := range im.PLTRels {
		if rel.PLTAddr == pltAddr {
			// We found the relocation entry for this PLT stub
			// The symbol name tells us what function this resolves to

			// Look for the actual function implementation
			for _, sym := range im.Dynsyms {
				if sym.Name == rel.SymName && !sym.IsPLT && sym.Addr != 0 {
					return sym.Addr, true
				}
			}

			// Also check static symbols
			for _, sym := range im.Syms {
				if sym.Name == rel.SymName && !sym.IsPLT && sym.Addr != 0 {
					return sym.Addr, true
				}
			}

			// If we can't find the function, at least we know the symbol name
			// This happens for external functions that aren't defined in this binary
			return 0, false
		}
	}

	return 0, false
}

// resolvePLTFromSymbols attempts to resolve a PLT entry using symbol table.
// This works for binaries where symbol information is available.
func (im *Image) resolvePLTFromSymbols(pltAddr uint64, symbols []DynSym) (uint64, bool) {
	// Look for matching PLT symbol
	for _, sym := range symbols {
		if sym.Addr == pltAddr && sym.IsPLT {
			// Extract function name without @plt suffix
			baseName := strings.TrimSuffix(sym.Name, "@plt")

			// Look for actual function implementation in both symbol tables
			for _, realSym := range im.Dynsyms {
				if realSym.Name == baseName && !realSym.IsPLT && realSym.Addr != 0 {
					return realSym.Addr, true
				}
			}
			for _, realSym := range im.Syms {
				if realSym.Name == baseName && !realSym.IsPLT && realSym.Addr != 0 {
					return realSym.Addr, true
				}
			}
			break
		}
	}
	return 0, false
}

// resolvePLTFromStubs attempts to resolve a PLT entry using pattern matching
// against parsed PLT stubs. This works for stripped binaries where symbols
// are not available but we can pattern-match GOT entries to known functions.
func (im *Image) resolvePLTFromStubs(pltAddr uint64) (uint64, bool) {
	// First, find the PLT stub for this address
	var targetGOT uint64
	for _, stub := range im.PLTStubs {
		if stub.Addr == pltAddr {
			targetGOT = stub.GOTAddr
			break
		}
	}

	if targetGOT == 0 {
		return 0, false // PLT stub not found
	}

	// Read the GOT entry to see what it currently points to
	gotTarget, ok := im.readGOTEntry(targetGOT)
	if !ok {
		return 0, false
	}

	// For stripped binaries, the GOT entry typically points to the PLT resolver
	// In this case, we need to infer the target function through other means

	// Strategy 1: Look for functions that might be called through this PLT entry
	// by analyzing the GOT entry index and matching it to known import patterns

	// Calculate PLT stub index (unused for now, but could be useful for heuristics)
	_ = (pltAddr-im.PLT.VA)/16 - 1 // Skip PLT[0] resolver

	// Strategy 2: Use heuristics based on common function signatures
	// For now, we'll return the GOT target if it looks like a valid function
	if im.isValidFunctionAddress(gotTarget) && gotTarget != pltAddr {
		return gotTarget, true
	}

	// For debugging: if the GOT target is the PLT resolver, we know this is
	// an unresolved import. In a complete implementation, we would try to
	// match this against known import signatures or relocation information.

	return 0, false
}

// parsePLTStub parses an ARM64 PLT stub to extract the GOT address.
// Standard ARM64 PLT stub format:
//
//	adrp x16, <page>     ; Load page address
//	ldr  x17, [x16, #offset] ; Load GOT entry
//	add  x16, x16, #offset   ; Prepare GOT entry address
//	br   x17             ; Branch to target
func (im *Image) parsePLTStub(pltAddr uint64) (uint64, bool) {
	// Read the PLT stub (16 bytes = 4 instructions)
	stubData, ok := im.SliceVA(pltAddr, 16)
	if !ok || len(stubData) < 16 {
		return 0, false
	}

	// Parse first instruction: adrp x16, <page>
	adrpInsn := uint32(stubData[0]) | uint32(stubData[1])<<8 | uint32(stubData[2])<<16 | uint32(stubData[3])<<24
	if (adrpInsn & 0x9f00001f) != 0x90000010 { // adrp x16 pattern
		return 0, false
	}

	// Extract immediate from adrp instruction
	immLo := (adrpInsn >> 29) & 3
	immHi := (adrpInsn >> 5) & 0x7ffff
	pageOffset := int64((immHi << 2) | immLo)
	if pageOffset&(1<<20) != 0 { // Sign extend
		pageOffset |= ^((1 << 21) - 1)
	}
	pageOffset <<= 12 // adrp works on 4KB pages

	pageBase := int64(pltAddr&^0xfff) + pageOffset

	// Parse second instruction: ldr x17, [x16, #offset]
	ldrInsn := uint32(stubData[4]) | uint32(stubData[5])<<8 | uint32(stubData[6])<<16 | uint32(stubData[7])<<24
	if (ldrInsn & 0xffc003ff) != 0xf9400211 { // ldr x17, [x16, #imm] pattern
		return 0, false
	}

	// Extract offset from ldr instruction
	offset := (ldrInsn >> 10) & 0xfff
	offset <<= 3 // Scale by 8 for 64-bit load

	gotAddr := uint64(pageBase) + uint64(offset)
	return gotAddr, true
}

// readGOTEntry reads an 8-byte address from a GOT entry.
func (im *Image) readGOTEntry(gotAddr uint64) (uint64, bool) {
	data, ok := im.SliceVA(gotAddr, 8)
	if !ok || len(data) < 8 {
		return 0, false
	}

	// Read as little-endian 64-bit address
	addr := uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 |
		uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56

	return addr, true
}

// isValidFunctionAddress checks if an address looks like a valid function address.
// This excludes PLT resolver stubs and other special addresses.
func (im *Image) isValidFunctionAddress(addr uint64) bool {
	// Must be within a loaded segment
	if _, ok := im.VA2Off(addr); !ok {
		return false
	}

	// Must not be within the PLT section (avoid PLT resolver)
	if im.PLT.Size > 0 && addr >= im.PLT.VA && addr < im.PLT.VA+im.PLT.Size {
		return false
	}

	// Check if it's a known function from symbol table
	for _, sym := range im.Dynsyms {
		if sym.Addr == addr && !sym.IsPLT {
			return true
		}
	}

	// If no exact symbol match, allow addresses in executable segments
	for _, seg := range im.Loads {
		if seg.Flags&elf.PF_X != 0 && addr >= seg.Vaddr && addr < seg.Vaddr+seg.Filesz {
			return true
		}
	}

	return false
}

// FindFunctionByName searches for a function by name in the symbol tables.
// This is useful for finding actual function addresses when we know the name.
func (im *Image) FindFunctionByName(name string) (uint64, bool) {
	// First try dynamic symbols
	for _, sym := range im.Dynsyms {
		if sym.Name == name && !sym.IsPLT && sym.Addr != 0 {
			return sym.Addr, true
		}
	}

	// Fallback to static symbols
	for _, sym := range im.Syms {
		if sym.Name == name && !sym.IsPLT && sym.Addr != 0 {
			return sym.Addr, true
		}
	}

	return 0, false
}

// InDataOrRodata returns true if the VA is inside .rodata or .data/.data.rel.ro
func (im *Image) InDataOrRodata(va uint64) bool {
	return im.InRodata(va) || im.InData(va) || im.InDataRelRo(va)
}
