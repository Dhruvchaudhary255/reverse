// Package analysis provides tools for analyzing ARM64 binaries.
// It includes string extraction, symbol scanning, and instruction tracing.
package analysis

// Constants for analysis operations
const (
	// MaxStringLength is the maximum length for string extraction
	MaxStringLength = 256
	
	// SearchWindowSmall is used for local instruction searches (e.g., ADRP+ADD patterns)
	SearchWindowSmall = 32
	
	// SearchWindowMedium is used for medium-range searches
	SearchWindowMedium = 100
	
	// SearchWindowLarge is used for extended instruction analysis
	SearchWindowLarge = 150
	
	// MaxTraceInstructions is the maximum number of instructions to trace
	MaxTraceInstructions = 1000
	
	// MaxSetterInstructions is the maximum instructions for setter analysis
	MaxSetterInstructions = 500
	
	// MaxRegionInstructions is the maximum instructions for region analysis  
	MaxRegionInstructions = 300
)