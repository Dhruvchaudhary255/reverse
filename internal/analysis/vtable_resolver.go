package analysis

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"strings"

	"reverse/internal/elfx"
	"reverse/internal/logging"
)

// VTableResolver resolves virtual function calls through vtables
type VTableResolver struct {
	img         *elfx.Image
	relocations map[uint64]uint64 // address -> target after relocation
	vtables     map[string]uint64 // class name -> vtable base address
}

// NewVTableResolver creates a new vtable resolver
func NewVTableResolver(img *elfx.Image) *VTableResolver {
	resolver := &VTableResolver{
		img:         img,
		relocations: make(map[uint64]uint64),
		vtables:     make(map[string]uint64),
	}
	resolver.loadRelocations()
	resolver.findVTables()
	return resolver
}

// loadRelocations loads R_AARCH64_RELATIVE relocations
func (r *VTableResolver) loadRelocations() {
	// Access the underlying ELF file
	if r.img.File == nil {
		return
	}

	// Find relocation sections
	for _, section := range r.img.File.Sections {
		if section.Type == elf.SHT_RELA {
			// Read relocations
			data, err := section.Data()
			if err != nil {
				continue
			}

			// Parse RELA entries (24 bytes each on ARM64)
			for i := 0; i < len(data); i += 24 {
				if i+24 > len(data) {
					break
				}

				// RELA entry structure:
				// offset: 8 bytes
				// info: 8 bytes
				// addend: 8 bytes
				offset := binary.LittleEndian.Uint64(data[i : i+8])
				info := binary.LittleEndian.Uint64(data[i+8 : i+16])
				addend := int64(binary.LittleEndian.Uint64(data[i+16 : i+24]))

				// Check if it's R_AARCH64_RELATIVE (type 1027)
				relType := info & 0xffffffff
				if relType == 1027 { // R_AARCH64_RELATIVE
					// For RELATIVE relocations, the target is base + addend
					// Since we're analyzing statically, we use addend as the target
					if addend > 0 {
						r.relocations[offset] = uint64(addend)
					}
				}
			}
		}
	}

	if logging.IsDebug() {
		lg := logging.NewLogger()
		lg.Debug("loaded relocations", "count", len(r.relocations))
	}
}

// findVTables finds vtable symbols
func (r *VTableResolver) findVTables() {
	// Look for vtable symbols (start with _ZTV)
	for _, sym := range r.img.Dynsyms {
		if strings.HasPrefix(sym.Name, "_ZTV") {
			// Extract class name from mangled symbol
			// _ZTVN7cocos2d8LuaStackE -> LuaStack
			className := extractClassName(sym.Name)
			if className != "" {
				// Vtables have 16-byte RTTI header, actual function pointers start at +16
				r.vtables[className] = sym.Addr + 16

				if logging.IsDebug() {
					lg := logging.NewLogger()
					lg.Debug("found vtable",
						"class", className,
						"symbol", sym.Name,
						"base", fmt.Sprintf("0x%x", sym.Addr+16))
				}
			}
		}
	}
}

// ResolveVirtualCall resolves a virtual function call
// Returns the target function address and symbol name if found
func (r *VTableResolver) ResolveVirtualCall(className string, vtableOffset uint64) (uint64, string) {
	// Get vtable base for the class
	vtableBase, ok := r.vtables[className]
	if !ok {
		// Try various forms of the class name
		possibleNames := []string{
			className,
			"cocos2d::" + className,
			strings.TrimPrefix(className, "cocos2d::"),
		}

		// If Unknown, we can't resolve without proper type information
		// Don't guess based on offsets as they vary between builds

		for _, name := range possibleNames {
			if base, exists := r.vtables[name]; exists {
				vtableBase = base
				ok = true
				className = name // Update to the found name
				break
			}
		}

		// Also try suffix matching
		if !ok {
			for class, base := range r.vtables {
				for _, name := range possibleNames {
					if strings.HasSuffix(class, "::"+name) || strings.HasSuffix(name, "::"+strings.TrimPrefix(class, "cocos2d::")) {
						vtableBase = base
						ok = true
						className = class
						goto found
					}
				}
			}
		found:
		}

		if !ok {
			return 0, ""
		}
	}

	// Calculate the actual address in the vtable
	vtableEntry := vtableBase + vtableOffset

	// Look up the relocation at this address
	targetAddr, ok := r.relocations[vtableEntry]
	if !ok {
		if logging.IsDebug() {
			lg := logging.NewLogger()
			lg.Debug("no relocation found",
				"class", className,
				"offset", fmt.Sprintf("0x%x", vtableOffset),
				"entry", fmt.Sprintf("0x%x", vtableEntry))
		}
		return 0, ""
	}

	// Try to resolve the target address to a symbol
	symbolName := r.resolveSymbol(targetAddr)

	if logging.IsDebug() {
		lg := logging.NewLogger()
		lg.Debug("resolved virtual call",
			"class", className,
			"offset", fmt.Sprintf("0x%x", vtableOffset),
			"target", fmt.Sprintf("0x%x", targetAddr),
			"symbol", symbolName)
	}

	return targetAddr, symbolName
}

// resolveSymbol resolves an address to a symbol name
func (r *VTableResolver) resolveSymbol(addr uint64) string {
	// Check dynamic symbols
	for _, sym := range r.img.Dynsyms {
		if sym.Addr == addr {
			return sym.Name
		}
	}

	// Check static symbols
	for _, sym := range r.img.Syms {
		if sym.Addr == addr {
			return sym.Name
		}
	}

	return ""
}

// extractClassName extracts the class name from a mangled vtable symbol
func extractClassName(mangledName string) string {
	// _ZTVN7cocos2d8LuaStackE format:
	// _ZTV = vtable prefix
	// N = nested name
	// 7cocos2d = namespace (7 chars)
	// 8LuaStack = class (8 chars)
	// E = end

	if !strings.HasPrefix(mangledName, "_ZTVN") {
		// Try without N for non-nested names
		if strings.HasPrefix(mangledName, "_ZTV") && len(mangledName) > 4 {
			// Simple format like _ZTV8LuaStack
			rest := mangledName[4:]
			// Parse the length-prefixed name
			if len(rest) > 0 && rest[0] >= '1' && rest[0] <= '9' {
				length := int(rest[0] - '0')
				if len(rest) > length {
					return rest[1 : 1+length]
				}
			}
		}
		return ""
	}

	parts := []string{}
	rest := mangledName[5:] // Skip _ZTVN

	// Parse nested names
	for len(rest) > 0 && rest[0] != 'E' {
		// Check for template arguments or special cases
		if rest[0] == 'I' {
			// Template arguments, skip for now
			break
		}

		// Parse length-prefixed component
		if rest[0] >= '1' && rest[0] <= '9' {
			// Single digit length
			length := int(rest[0] - '0')
			if len(rest) > length {
				parts = append(parts, rest[1:1+length])
				rest = rest[1+length:]
			} else {
				break
			}
		} else if rest[0] == '0' {
			// Skip
			rest = rest[1:]
		} else {
			// Multi-digit length or other
			break
		}
	}

	if len(parts) > 0 {
		// Return full qualified name
		return strings.Join(parts, "::")
	}

	return ""
}

// FindVTableForObject attempts to find the vtable for an object based on context
func (r *VTableResolver) FindVTableForObject(context string) string {
	// Common patterns
	if strings.Contains(context, "LuaStack") || strings.Contains(context, "getLuaStack") {
		return "cocos2d::LuaStack"
	}
	if strings.Contains(context, "LuaEngine") {
		return "cocos2d::LuaEngine"
	}
	if strings.Contains(context, "Director") {
		return "cocos2d::Director"
	}

	return ""
}
