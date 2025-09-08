package analysis

import (
	"fmt"
	"reverse/internal/elfx"
	"strings"
	"sync"

	"github.com/ianlancetaylor/demangle"
)

// SymbolScanResult holds both entrypoints and setters found in a single scan
type SymbolScanResult struct {
	Entrypoints []SetterSymbol
	Setters     []SetterSymbol
}

type SetterSymbol struct {
	VA         uint64
	Name       string
	Demangled  string
	SymbolType string
}

// symbolCache provides thread-safe caching for symbol operations.
// NOTE: Currently not goroutine-safe - use only in single-threaded contexts.
type symbolCache struct {
	mu               sync.RWMutex
	scanGuard        map[string]bool
	demangleCache    map[string]string
	demangledHitCount map[string]int
	cacheEnabled     bool
}

var cache = &symbolCache{
	scanGuard:        make(map[string]bool),
	demangleCache:    make(map[string]string),
	demangledHitCount: make(map[string]int),
	cacheEnabled:     true, // Enable cache by default for performance
}

// EnableDemangleCache enables the demangle cache for performance.
func EnableDemangleCache() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.cacheEnabled = true
}

// CachedDemangle performs demangling with caching support.
func CachedDemangle(mangled string) string {
	cache.mu.RLock()
	if !cache.cacheEnabled {
		cache.mu.RUnlock()
		return demangle.Filter(mangled, demangle.NoClones)
	}
	if cached, exists := cache.demangleCache[mangled]; exists {
		cache.demangledHitCount[mangled]++
		cache.mu.RUnlock()
		return cached
	}
	cache.mu.RUnlock()

	demangled := demangle.Filter(mangled, demangle.NoClones)

	cache.mu.Lock()
	cache.demangleCache[mangled] = demangled
	cache.demangledHitCount[mangled] = 1
	cache.mu.Unlock()
	return demangled
}

// GetDemangleCacheStats returns statistics about the demangle cache.
func GetDemangleCacheStats() (totalSymbols int, cacheHits int, topSymbols []string) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	
	totalHits := 0
	for _, count := range cache.demangledHitCount {
		totalHits += count
	}

	type symbolHit struct {
		symbol string
		count  int
	}
	var symbols []symbolHit
	for sym, count := range cache.demangledHitCount {
		symbols = append(symbols, symbolHit{sym, count})
	}

	for i := 0; i < len(symbols)-1; i++ {
		for j := i + 1; j < len(symbols); j++ {
			if symbols[j].count > symbols[i].count {
				symbols[i], symbols[j] = symbols[j], symbols[i]
			}
		}
	}

	var top []string
	for i := 0; i < 5 && i < len(symbols); i++ {
		top = append(top, fmt.Sprintf("%s (%d hits)", symbols[i].symbol, symbols[i].count))
	}

	return len(cache.demangleCache), totalHits - len(cache.demangleCache), top
}

// ScanSymbols scans an ELF image for entrypoints and setter symbols.
// Returns error if called multiple times for the same binary.
func ScanSymbols(im *elfx.Image) (SymbolScanResult, error) {
	cache.mu.Lock()
	if cache.scanGuard[im.Path] {
		cache.mu.Unlock()
		return SymbolScanResult{}, fmt.Errorf("scanSymbols called twice for same binary: %s", im.Path)
	}
	cache.scanGuard[im.Path] = true
	cache.mu.Unlock()

	var entrypoints, setters []SetterSymbol
	seen := make(map[uint64]bool)

	// Single pass through all symbols (dynamic + static)
	allSyms := append(im.Dynsyms, im.Syms...)

	for _, sym := range allSyms {
		if seen[sym.Addr] {
			continue // Skip duplicates
		}
		seen[sym.Addr] = true

		// Demangle with caching
		demangled := CachedDemangle(sym.Name)
		lowerName := strings.ToLower(sym.Name)
		lowerDemangled := strings.ToLower(demangled)

		// Check for entry points
		if IsEntryPoint(sym.Name, demangled, lowerName, lowerDemangled) {
			entrypoints = append(entrypoints, SetterSymbol{
				VA:         sym.Addr,
				Name:       sym.Name,
				Demangled:  demangled,
				SymbolType: "EntryPoint",
			})
		}

		// Check for setters
		if IsSetter(lowerName) {
			setters = append(setters, SetterSymbol{
				VA:         sym.Addr,
				Name:       sym.Name,
				Demangled:  demangled,
				SymbolType: "setter",
			})
		}
	}

	return SymbolScanResult{
		Entrypoints: entrypoints,
		Setters:     setters,
	}, nil
}

// IsEntryPoint checks if a symbol is an entry point using cached lowercase strings
func IsEntryPoint(name, demangled, lowerName, lowerDemangled string) bool {
	switch {
	case strings.Contains(name, "cocos_android_app_init"):
		return true
	case strings.Contains(lowerName, "didfinishlaunching"):
		return true
	case demangled != name && strings.Contains(lowerDemangled, "didfinishlaunching"):
		return true
	// BaseGame::init pattern - check demangled form
	case strings.Contains(demangled, "BaseGame::init"):
		return true
	// Game::init pattern
	case strings.Contains(demangled, "Game::init"):
		return true
	// cocos_main pattern
	case strings.Contains(name, "cocos_main"):
		return true
	default:
		return false
	}
}

// IsSetter checks if a symbol is a setter using cached lowercase string
func IsSetter(lowerName string) bool {
	// Fast pattern matching: (set|add|edit) + (cryptokey|xxtea)
	hasAction := strings.Contains(lowerName, "set") ||
		strings.Contains(lowerName, "add") ||
		strings.Contains(lowerName, "edit")

	hasTarget := strings.Contains(lowerName, "cryptokey") ||
		strings.Contains(lowerName, "xxtea")

	return hasAction && hasTarget
}

// FindXXTEASetters discovers all XXTEA setter functions in the binary
// DEPRECATED: Use ScanSymbols for better performance
func FindXXTEASetters(im *elfx.Image) []SetterSymbol {
	result, _ := ScanSymbols(im)
	return result.Setters
}

// FindAppDelegateEntrypoints discovers application entry points
// DEPRECATED: Use ScanSymbols for better performance
func FindAppDelegateEntrypoints(im *elfx.Image) []SetterSymbol {
	result, _ := ScanSymbols(im)
	return result.Entrypoints
}

// isEntryPointSymbol checks if a symbol name matches entry point patterns
// DEPRECATED: Use ScanSymbols for better performance
func isEntryPointSymbol(name string) bool {
	demangled := CachedDemangle(name)
	lowerName := strings.ToLower(name)
	lowerDemangled := strings.ToLower(demangled)
	return IsEntryPoint(name, demangled, lowerName, lowerDemangled)
}
