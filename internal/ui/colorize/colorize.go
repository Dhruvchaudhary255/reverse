package colorize

import (
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
)

// getAssemblyLexer returns an appropriate assembly lexer with fallbacks
func getAssemblyLexer() chroma.Lexer {
	// Try lexers in order of preference (ARM assembly first)
	candidates := []string{"armasm", "gas", "GAS", "Gas", "nasm"}
	for _, name := range candidates {
		if lexer := lexers.Get(name); lexer != nil {
			return lexer
		}
	}
	return nil
}

// getDisasmStyle returns the disassembly style with fallbacks
func getDisasmStyle() *chroma.Style {
	// Try our custom style first, then fallbacks
	candidates := []string{"disasm-dark", "dracula", "monokai"}
	for _, name := range candidates {
		if style := styles.Get(name); style != nil {
			return style
		}
	}
	return styles.Fallback
}

// getTerminalFormatter returns an appropriate terminal formatter
func getTerminalFormatter() chroma.Formatter {
	// Try high-color first, then fallback
	candidates := []string{"terminal16m", "terminal256"}
	for _, name := range candidates {
		if formatter := formatters.Get(name); formatter != nil {
			return formatter
		}
	}
	return formatters.Fallback
}

// ColorizeAssemblyGAS uses the GAS lexer specifically for ARM assembly
func ColorizeAssemblyGAS(code string) (string, error) {
	// Check if colors are disabled
	if os.Getenv("REVERSE_NO_COLOR") != "" {
		return code, nil
	}

	lexer := getAssemblyLexer()
	if lexer == nil {
		// Return plain text if no assembly lexer available
		return code, nil
	}

	style := getDisasmStyle()
	formatter := getTerminalFormatter()

	// Tokenize the code
	iterator, err := lexer.Tokenise(nil, code)
	if err != nil {
		return code, err
	}

	// Format the tokens
	var buf strings.Builder
	if err := formatter.Format(&buf, style, iterator); err != nil {
		return code, err
	}

	return buf.String(), nil
}

// ColorizeAssembly applies syntax highlighting to ARM assembly code (generic)
func ColorizeAssembly(code string) (string, error) {
	// Check if colors are disabled
	if os.Getenv("REVERSE_NO_COLOR") != "" {
		return code, nil
	}

	lexer := getAssemblyLexer()
	if lexer == nil {
		// Return plain text if no assembly lexer available
		return code, nil
	}

	style := getDisasmStyle()
	formatter := getTerminalFormatter()

	// Tokenize the code
	iterator, err := lexer.Tokenise(nil, code)
	if err != nil {
		return code, err
	}

	// Format the tokens
	var buf strings.Builder
	if err := formatter.Format(&buf, style, iterator); err != nil {
		return code, err
	}

	return buf.String(), nil
}

// ColorizeInstructionLine colorizes a single instruction line while preserving formatting
func ColorizeInstructionLine(line string) string {
	// Check if colors are disabled
	if os.Getenv("REVERSE_NO_COLOR") != "" {
		return line
	}

	// The input line is already formatted with proper spacing from trace_disasm
	// Format: "0xaddress  mnemonic operands                    ; comment"
	// Or:     "                                               ; vtable info"

	// Check if this is a comment-only line (starts with spaces and has semicolon)
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, ";") {
		// Comment-only line, but still highlight function names
		return highlightFunctionNamesInComments(fmt.Sprintf("\033[38;2;235;194;237m%s\033[0m", line))
	}

	// Parse the address separately since we want it in gray
	// Address is hex digits (without 0x prefix)
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		// Not a valid instruction line, try full line colorization
		return colorizeFullLine(line)
	}

	// Check if the first part looks like an address (hex digits)
	for _, ch := range parts[0] {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return colorizeFullLine(line)
		}
	}

	addr := parts[0]
	remaining := parts[1]

	// Color address in gray (79, 79, 79)
	addrColored := fmt.Sprintf("\033[38;2;79;79;79m%s\033[0m", addr)

	// Use Chroma for the rest of the line
	colorized := colorizeFullLine(remaining)

	return fmt.Sprintf("%s %s", addrColored, colorized)
}

// isHexChar checks if a character is a hexadecimal digit
func isHexChar(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// isFunctionName checks if a string looks like a function/method name
func isFunctionName(s string) bool {
	// Check for sub_ prefix
	if strings.HasPrefix(s, "sub_") {
		return true
	}

	// Check for C++ style names with ::
	if strings.Contains(s, "::") {
		return true
	}

	// Check for function names ending with ()
	if strings.HasSuffix(s, "()") {
		return true
	}

	// Check for common function name patterns (camelCase or snake_case)
	// Must start with letter or underscore, contain only alphanumeric and underscore
	if len(s) == 0 {
		return false
	}

	// Check first character
	if !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z') || s[0] == '_') {
		return false
	}

	// Check if it looks like a function name (has some mix of cases or underscores)
	hasUpper := false
	hasLower := false
	hasUnderscore := false

	for _, ch := range s {
		if ch >= 'A' && ch <= 'Z' {
			hasUpper = true
		} else if ch >= 'a' && ch <= 'z' {
			hasLower = true
		} else if ch == '_' {
			hasUnderscore = true
		} else if !(ch >= '0' && ch <= '9') {
			// Contains invalid character for function name
			return false
		}
	}

	// It's a function name if it has mixed case (camelCase) or underscores (snake_case)
	// or if it has common function prefixes
	if hasUnderscore || (hasUpper && hasLower) {
		return true
	}
	// Common function name patterns (even without mixed case)
	if strings.HasPrefix(s, "set") || strings.HasPrefix(s, "get") ||
		strings.HasPrefix(s, "is") || strings.HasPrefix(s, "has") {
		return true
	}

	return false
}

// highlightFunctionNamesInComments detects and highlights function names in comment sections
func highlightFunctionNamesInComments(line string) string {
	// This function is complex because it needs to work with already-colored text
	// We should only process lines that have comments

	// For now, just return the line as-is to avoid breaking existing colors
	// TODO: Implement proper ANSI-aware parsing to highlight function names in comments
	// The challenge is that the line already contains ANSI escape sequences from Chroma
	// and we need to parse through those to find and highlight function names
	return line
}

// colorizeFullLine uses Chroma to colorize an assembly line
func colorizeFullLine(line string) string {
	// Check if colors are disabled
	if os.Getenv("REVERSE_NO_COLOR") != "" {
		return line
	}

	// Use nasm lexer which handles comments well
	lexer := lexers.Get("nasm")
	if lexer == nil {
		lexer = lexers.Get("armasm")
		if lexer == nil {
			// Return plain text if no lexer available
			return line
		}
	}

	// Make sure our custom style is registered
	_ = DisasmDark // Force registration

	style := getDisasmStyle()
	formatter := getTerminalFormatter()

	// Tokenize the line
	iterator, err := lexer.Tokenise(nil, line)
	if err != nil {
		return line
	}

	// Format the tokens
	var buf strings.Builder
	err = formatter.Format(&buf, style, iterator)
	if err != nil {
		return line
	}

	// Post-process to highlight function names in comments
	colorized := buf.String()
	colorized = highlightFunctionNamesInComments(colorized)

	// Return the colorized line
	return colorized
}

// stripANSIStr removes ANSI codes and returns the plain string
func stripANSIStr(s string) string {
	var result strings.Builder
	inEscape := false

	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
		} else if inEscape {
			if r == 'm' {
				inEscape = false
			}
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// stripANSI removes ANSI escape codes and returns visible character count
func stripANSI(s string) int {
	// Simple visible character counter that skips ANSI escape sequences
	visible := 0
	inEscape := false

	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
		} else if inEscape {
			if r == 'm' {
				inEscape = false
			}
		} else {
			visible++
		}
	}

	return visible
}
