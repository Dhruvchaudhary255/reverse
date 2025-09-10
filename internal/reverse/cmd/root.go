package cmd

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	pathpkg "path/filepath"
	"runtime/pprof"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/v2/list"
	"github.com/charmbracelet/bubbles/v2/spinner"
	"github.com/charmbracelet/bubbles/v2/viewport"
	tea "github.com/charmbracelet/bubbletea/v2"
	"github.com/charmbracelet/fang"
	"github.com/charmbracelet/lipgloss/v2"
	"github.com/charmbracelet/x/term"
	"github.com/ianlancetaylor/demangle"
	"github.com/spf13/cobra"
	"golang.org/x/arch/arm64/arm64asm"

	"reverse/internal/analysis"
	"reverse/internal/detectors"
	"reverse/internal/elfx"
	"reverse/internal/reverse/styles"
	"reverse/internal/ui/colorize"
	"reverse/internal/xxtea"
)

type viewMode int

const (
	viewReverse viewMode = iota // Renamed from viewInfo
	viewSymbols
	viewDetails // Renamed from viewDetector
)

// JSONOutput represents the JSON output structure for regression testing
type JSONOutput struct {
	Digest      string            `json:"digest"`
	EntryPoints []string          `json:"entry_points"`
	Setters     []XXTEASetterInfo `json:"setters"`
}

// XXTEASetterInfo represents XXTEA setter information in JSON output
type XXTEASetterInfo struct {
	Address   string `json:"address"`
	Function  string `json:"function"`
	Key       string `json:"key,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// sanitizeForJSON cleans a string to be valid UTF-8 and safe for JSON encoding
func sanitizeForJSON(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	// Convert invalid UTF-8 to valid UTF-8 by replacing invalid bytes
	return strings.ToValidUTF8(s, "�")
}

type symbolInfo struct {
	address uint64
	name    string
}

type symbolItem struct {
	address    uint64
	original   string
	demangled  string
	filterTerm string // Pre-computed filter value
}

func (i symbolItem) Title() string {
	// This is used for filtering - return plain text
	return fmt.Sprintf("%x  %s", i.address, i.demangled)
}

func (i symbolItem) FilterValue() string {
	// Return the pre-computed filter term
	return i.filterTerm
}

// Custom item delegate for symbols list
type itemDelegate struct{}

func (d itemDelegate) Height() int                               { return 1 }
func (d itemDelegate) Spacing() int                              { return 0 }
func (d itemDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd { return nil }

func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(symbolItem)
	if !ok {
		return
	}

	// Style the address differently for selected items
	var addrStyle lipgloss.Style
	var indicator string

	if index == m.Index() {
		// Selected item
		indicator = ">"
		addrStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("170")) // Purple for selected address
	} else {
		// Normal item
		indicator = " "
		addrStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240")) // Gray for normal address
	}

	// Colorize the C++ signature
	colorized := colorizeCppSignature(i.demangled)

	// Build the complete line with fixed positions
	str := fmt.Sprintf(" %s  %s  %s",
		indicator,
		addrStyle.Render(fmt.Sprintf("%x", i.address)),
		colorized)

	fmt.Fprint(w, str)
}

// colorizeCppSignature applies syntax highlighting to C++ function signatures
func colorizeCppSignature(sig string) string {
	// Define styles
	typeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("81"))     // Cyan for types
	funcStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))    // Orange for function names
	nsStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("250"))      // Light gray for namespaces
	keywordStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("141")) // Purple for keywords

	// If it's a simple symbol without parentheses, it's likely a variable
	if !strings.Contains(sig, "(") {
		// Check for namespace
		if strings.Contains(sig, "::") {
			parts := strings.Split(sig, "::")
			var result []string
			for i, part := range parts {
				if i < len(parts)-1 {
					result = append(result, nsStyle.Render(part))
				} else {
					result = append(result, funcStyle.Render(part))
				}
			}
			return strings.Join(result, nsStyle.Render("::"))
		}
		return funcStyle.Render(sig)
	}

	// Parse function signature
	// Find the function name (before the opening parenthesis)
	parenIdx := strings.Index(sig, "(")
	if parenIdx == -1 {
		return sig
	}

	preFunc := sig[:parenIdx]
	postFunc := sig[parenIdx:]

	// Color the return type and function name
	var coloredPre string
	lastSpace := strings.LastIndex(preFunc, " ")
	if lastSpace != -1 {
		returnType := preFunc[:lastSpace]
		funcName := preFunc[lastSpace+1:]

		// Color return type with keywords
		returnType = strings.ReplaceAll(returnType, "const", keywordStyle.Render("const"))
		returnType = strings.ReplaceAll(returnType, "virtual", keywordStyle.Render("virtual"))
		returnType = strings.ReplaceAll(returnType, "static", keywordStyle.Render("static"))
		returnType = strings.ReplaceAll(returnType, "void", typeStyle.Render("void"))
		returnType = strings.ReplaceAll(returnType, "int", typeStyle.Render("int"))
		returnType = strings.ReplaceAll(returnType, "bool", typeStyle.Render("bool"))
		returnType = strings.ReplaceAll(returnType, "char", typeStyle.Render("char"))
		returnType = strings.ReplaceAll(returnType, "float", typeStyle.Render("float"))
		returnType = strings.ReplaceAll(returnType, "double", typeStyle.Render("double"))
		returnType = strings.ReplaceAll(returnType, "unsigned", typeStyle.Render("unsigned"))

		// Handle namespace in function name
		if strings.Contains(funcName, "::") {
			parts := strings.Split(funcName, "::")
			var result []string
			for i, part := range parts {
				if i < len(parts)-1 {
					result = append(result, nsStyle.Render(part))
				} else {
					result = append(result, funcStyle.Render(part))
				}
			}
			funcName = strings.Join(result, nsStyle.Render("::"))
		} else {
			funcName = funcStyle.Render(funcName)
		}

		coloredPre = returnType + " " + funcName
	} else {
		// No return type, just function name
		if strings.Contains(preFunc, "::") {
			parts := strings.Split(preFunc, "::")
			var result []string
			for i, part := range parts {
				if i < len(parts)-1 {
					result = append(result, nsStyle.Render(part))
				} else {
					result = append(result, funcStyle.Render(part))
				}
			}
			coloredPre = strings.Join(result, nsStyle.Render("::"))
		} else {
			coloredPre = funcStyle.Render(preFunc)
		}
	}

	// Color the parameters
	postFunc = strings.ReplaceAll(postFunc, "const", keywordStyle.Render("const"))
	postFunc = strings.ReplaceAll(postFunc, "void", typeStyle.Render("void"))
	postFunc = strings.ReplaceAll(postFunc, "int", typeStyle.Render("int"))
	postFunc = strings.ReplaceAll(postFunc, "bool", typeStyle.Render("bool"))
	postFunc = strings.ReplaceAll(postFunc, "char", typeStyle.Render("char"))
	postFunc = strings.ReplaceAll(postFunc, "float", typeStyle.Render("float"))
	postFunc = strings.ReplaceAll(postFunc, "double", typeStyle.Render("double"))
	postFunc = strings.ReplaceAll(postFunc, "unsigned", typeStyle.Render("unsigned"))

	return coloredPre + postFunc
}
func (i symbolItem) Description() string { return "" }

type model struct {
	viewport          viewport.Model
	symbolsList       list.Model
	detectorView      viewport.Model
	spinner           spinner.Model
	mode              viewMode
	filepath          string
	digest            string
	fileType          string
	fileKind          string // "library", "executable", etc
	symbols           []symbolInfo
	symbolCount       int
	detectorProcessed bool
	xxteaDetection    string // XXTEA detection results for info panel
	loadingSymbols    bool
	loadingDigest     bool
	width             int
	height            int
	elfImage          *elfx.Image // Keep ELF image open for reading data
}

// Message types
type digestCalculatedMsg struct {
	digest string
}

type fileTypeMsg struct {
	fileType string
}

type symbolsMsg struct {
	symbols  []symbolInfo
	elfImage *elfx.Image
	err      error
}

// Commands
func calculateDigestCmd(filepath string) tea.Cmd {
	return func() tea.Msg {
		// Check if file exists first
		if _, err := os.Stat(filepath); err != nil {
			return digestCalculatedMsg{digest: fmt.Sprintf("file not found: %s", filepath)}
		}

		file, err := os.Open(filepath)
		if err != nil {
			return digestCalculatedMsg{digest: fmt.Sprintf("error: %v", err)}
		}
		defer file.Close()

		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			return digestCalculatedMsg{digest: fmt.Sprintf("error: %v", err)}
		}

		return digestCalculatedMsg{digest: fmt.Sprintf("%x", hash.Sum(nil))}
	}
}

func getFileTypeCmd(filepath string) tea.Cmd {
	return func() tea.Msg {
		cmd := exec.Command("file", "-b", filepath)
		output, err := cmd.Output()
		if err != nil {
			return fileTypeMsg{fileType: "unknown"}
		}

		// Trim whitespace and newlines
		fileType := strings.TrimSpace(string(output))
		return fileTypeMsg{fileType: fileType}
	}
}

func readSymbolsCmd(filepath string) tea.Cmd {
	return func() tea.Msg {
		// Only read symbols for .so files
		ext := strings.ToLower(pathpkg.Ext(filepath))
		if ext != ".so" {
			return symbolsMsg{symbols: nil, elfImage: nil, err: nil}
		}

		// Open the ELF file using elfx
		img, err := elfx.Open(filepath)
		if err != nil {
			return symbolsMsg{symbols: nil, elfImage: nil, err: err}
		}
		// Don't close img here - we'll keep it open in the model

		// Collect unique symbols with addresses
		symbolMap := make(map[string]symbolInfo)

		// Get dynamic symbols
		for _, sym := range img.Dynsyms {
			// Skip empty names, internal symbols, and undefined symbols (address 0)
			if sym.Name != "" && !strings.HasPrefix(sym.Name, "__") && sym.Addr != 0 {
				// Use the symbol name as key to avoid duplicates, keep the one with lowest address
				if existing, exists := symbolMap[sym.Name]; !exists || sym.Addr < existing.address {
					symbolMap[sym.Name] = symbolInfo{
						address: sym.Addr,
						name:    sym.Name,
					}
				}
			}
		}

		// Get static symbols if available
		for _, sym := range img.Syms {
			// Skip empty names, internal symbols, and undefined symbols (address 0)
			if sym.Name != "" && !strings.HasPrefix(sym.Name, "__") && sym.Addr != 0 {
				// Use the symbol name as key to avoid duplicates, keep the one with lowest address
				if existing, exists := symbolMap[sym.Name]; !exists || sym.Addr < existing.address {
					symbolMap[sym.Name] = symbolInfo{
						address: sym.Addr,
						name:    sym.Name,
					}
				}
			}
		}

		// Convert to slice and sort by address
		var symbols []symbolInfo
		for _, sym := range symbolMap {
			symbols = append(symbols, sym)
		}
		sort.Slice(symbols, func(i, j int) bool {
			return symbols[i].address < symbols[j].address
		})

		// Keep all symbols - no filtering
		return symbolsMsg{symbols: symbols, elfImage: img, err: nil}
	}
}

func NewModel(filepath string) model {
	vp := viewport.New()
	vp.SetWidth(80)
	vp.SetHeight(24)

	// Create custom item delegate
	delegate := itemDelegate{}

	symbolsList := list.New([]list.Item{}, delegate, 80, 24)
	symbolsList.SetShowStatusBar(false)
	symbolsList.SetFilteringEnabled(true)
	symbolsList.Title = "Symbols"
	symbolsList.Styles.Title = lipgloss.NewStyle().
		Foreground(lipgloss.Color("99")).
		MarginLeft(2)
	symbolsList.SetShowHelp(true)

	// Create spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("170"))

	// Detect file kind based on extension
	fileKind := detectFileKind(filepath)

	// Set loading flags
	loadingSymbols := (fileKind == "library")

	// Create detector viewport for summary
	dvp := viewport.New()
	dvp.SetWidth(80)
	dvp.SetHeight(24)

	m := model{
		viewport:       vp,
		symbolsList:    symbolsList,
		detectorView:   dvp,
		spinner:        s,
		mode:           viewReverse,
		filepath:       filepath,
		digest:         "",
		fileKind:       fileKind,
		loadingSymbols: loadingSymbols,
		loadingDigest:  true,
		width:          80,
		height:         24,
		elfImage:       nil, // Explicitly initialize to nil
	}

	// Set initial content
	m.updateContent()

	return m
}

func detectFileKind(filepath string) string {
	ext := strings.ToLower(pathpkg.Ext(filepath))

	switch ext {
	case ".so":
		return "library"
	default:
		// Check if it has no extension (common for Unix executables)
		if ext == "" {
			return "executable"
		}
		// For unsupported file types
		return "unknown"
	}
}

func (m model) Init() tea.Cmd {
	// Start calculating the digest, getting file type, reading symbols, and spinner
	return tea.Batch(
		calculateDigestCmd(m.filepath),
		getFileTypeCmd(m.filepath),
		readSymbolsCmd(m.filepath),
		m.spinner.Tick,
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case digestCalculatedMsg:
		m.digest = msg.digest
		m.loadingDigest = false
		// Update the content with the digest
		m.updateContent()
		return m, nil

	case fileTypeMsg:
		m.fileType = msg.fileType
		// Update the content with the file type
		m.updateContent()
		return m, nil

	case symbolsMsg:
		if msg.err == nil && msg.symbols != nil {
			m.symbols = msg.symbols
			m.symbolCount = len(msg.symbols)
			m.elfImage = msg.elfImage // Store the ELF image
			// Update symbols list
			m.updateSymbolsList()
			// Automatically run detector for XXTEA analysis
			if !m.detectorProcessed && m.elfImage != nil {
				m.runCocosDetector()
			}
		}
		m.loadingSymbols = false
		// Update the content with symbols
		m.updateContent()
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		// Only continue spinner if we're still loading something
		if m.loadingDigest || m.loadingSymbols {
			m.updateContent()
			return m, cmd
		}
		return m, nil

	case tea.WindowSizeMsg:
		if msg.Width != m.width || msg.Height != m.height {
			m.width = msg.Width
			m.height = msg.Height
			m.viewport.SetWidth(msg.Width)
			m.viewport.SetHeight(msg.Height - 2)
			m.symbolsList.SetWidth(msg.Width)
			m.symbolsList.SetHeight(msg.Height - 2)
			m.detectorView.SetWidth(msg.Width)
			m.detectorView.SetHeight(msg.Height - 2)

			m.updateContent()
		}

	case tea.KeyMsg:
		// If we're in symbols view and the list is filtering, let it handle the keys first
		if m.mode == viewSymbols && m.symbolsList.FilterState() == list.Filtering {
			// Only handle essential keys that should work even during filtering
			switch msg.String() {
			case "q", "ctrl+c":
				// Clean up the ELF image if it's open
				if m.elfImage != nil {
					m.elfImage.Close()
				}
				return m, tea.Quit
			case "esc":
				// Let the list handle ESC to exit filtering
				break
			default:
				// Pass all other keys to the list when filtering
				break
			}
		} else {
			// Normal key handling when not filtering
			switch msg.String() {
			case "q", "ctrl+c":
				// Clean up the ELF image if it's open
				if m.elfImage != nil {
					m.elfImage.Close()
				}
				return m, tea.Quit
			case "r":
				// Show reverse view
				m.mode = viewReverse
				return m, nil
			case "s":
				// Show symbols view if we have symbols
				if m.symbolCount > 0 {
					m.mode = viewSymbols
				}
				return m, nil
			case "d":
				// Show details view if we have symbols
				if m.symbolCount > 0 {
					m.mode = viewDetails
					// Run detector if not already done
					if !m.detectorProcessed {
						m.runCocosDetector()
					}
				}
				return m, nil
			case "enter":
				// If in symbols view, show assembly for selected symbol
				if m.mode == viewSymbols {
					if selectedItem := m.symbolsList.SelectedItem(); selectedItem != nil {
						if symbol, ok := selectedItem.(symbolItem); ok && m.elfImage != nil {
							// Generate assembly view for the symbol
							assemblyContent := m.generateSymbolAssembly(symbol)
							if assemblyContent != "" {
								// Switch to reverse view and display the assembly
								m.mode = viewReverse
								m.viewport.SetContent(assemblyContent)
								m.viewport.GotoTop()
							}
						}
					}
				}
				return m, nil
			case "tab":
				// Cycle forward through views
				switch m.mode {
				case viewReverse:
					if m.symbolCount > 0 {
						m.mode = viewSymbols
					}
				case viewSymbols:
					m.mode = viewDetails
					if !m.detectorProcessed {
						m.runCocosDetector()
					}
				case viewDetails:
					m.mode = viewReverse
				}
				return m, nil
			case "shift+tab":
				// Cycle backward through views
				switch m.mode {
				case viewReverse:
					if m.symbolCount > 0 {
						m.mode = viewDetails
						if !m.detectorProcessed {
							m.runCocosDetector()
						}
					}
				case viewSymbols:
					m.mode = viewReverse
				case viewDetails:
					if m.symbolCount > 0 {
						m.mode = viewSymbols
					}
				}
				return m, nil
			}
		}
	}

	// Update the active view
	switch m.mode {
	case viewSymbols:
		m.symbolsList, cmd = m.symbolsList.Update(msg)
	case viewDetails:
		m.detectorView, cmd = m.detectorView.Update(msg)
	default:
		m.viewport, cmd = m.viewport.Update(msg)
	}
	return m, cmd
}

func (m model) View() string {
	var content string
	switch m.mode {
	case viewSymbols:
		content = m.symbolsList.View()
	case viewDetails:
		content = m.detectorView.View()
	default:
		content = m.viewport.View()
	}

	// Add menu bar at the bottom
	var menu string
	switch m.mode {
	case viewSymbols:
		menu = " Enter: view assembly • R: reverse • D: details • Tab: cycle • Q: quit "
	case viewDetails:
		menu = " R: reverse • S: symbols • Tab: cycle • Q: quit "
	default: // viewReverse
		if m.symbolCount > 0 {
			menu = " S: symbols • D: details • Tab: cycle • Q: quit "
		} else {
			menu = " Q: quit "
		}
	}

	// Style the menu bar
	menuStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("235")).
		Foreground(lipgloss.Color("252")).
		Padding(0, 1).
		Width(m.width)

	return content + "\n" + menuStyle.Render(menu)
}

func (m *model) updateContent() {
	// Get relative path from current directory
	relPath := m.filepath
	if cwd, err := os.Getwd(); err == nil {
		if rel, err := pathpkg.Rel(cwd, m.filepath); err == nil {
			relPath = rel
		}
	}

	// Create markdown content
	var markdown string
	var lines []string

	// Split path into directory and filename
	dir := pathpkg.Dir(relPath)
	base := pathpkg.Base(relPath)

	// Add directory path
	if dir != "." {
		lines = append(lines, fmt.Sprintf("; %s/", dir))
	}

	// Add filename with kind indicator
	if m.fileKind != "" && m.fileKind != "binary" {
		lines = append(lines, fmt.Sprintf("; %s (%s)", base, m.fileKind))
	} else {
		lines = append(lines, fmt.Sprintf("; %s", base))
	}

	// Add digest
	if m.digest != "" {
		lines = append(lines, fmt.Sprintf("; %s", m.digest))
	} else if m.loadingDigest {
		lines = append(lines, "; Calculating digest...")
	}

	// Add blank line separator
	lines = append(lines, "")

	// Add file type if available (no wrapping)
	if m.fileType != "" {
		// Add "; " prefix to the file type description
		lines = append(lines, fmt.Sprintf("; %s", m.fileType))
	}

	markdown = fmt.Sprintf("# Reverse\n\n```\n%s\n```", strings.Join(lines, "\n"))

	// Add XXTEA detection results if available
	if m.xxteaDetection != "" {
		markdown += "\n\n## XXTEA Detection\n\n"
		markdown += m.xxteaDetection
	}

	// Add loading spinner after the code block if needed
	if m.loadingSymbols && m.fileKind == "library" {
		markdown += fmt.Sprintf("\n\n%s Loading symbols...", m.spinner.View())
	}
	if m.loadingDigest && m.digest == "" {
		markdown += fmt.Sprintf("\n\n%s Calculating digest...", m.spinner.View())
	}

	// Render markdown using glamour
	width := m.width
	if width == 0 {
		width = 80
	}
	renderer := styles.GetMarkdownRenderer(width - 2)
	rendered, _ := renderer.Render(markdown)
	m.viewport.SetContent(strings.TrimSuffix(rendered, "\n"))
}

func (m *model) updateSymbolsList() {
	// Convert symbols to list items with demangling
	items := make([]list.Item, 0, len(m.symbols))
	for _, sym := range m.symbols {
		// Demangle the symbol
		demangled := demangle.Filter(sym.name)
		if demangled == "" {
			demangled = sym.name
		}
		items = append(items, symbolItem{
			address:    sym.address,
			original:   sym.name,
			demangled:  demangled,
			filterTerm: fmt.Sprintf("%x %s", sym.address, demangled),
		})
	}

	// Update the list
	m.symbolsList.SetItems(items)
	m.symbolsList.Title = fmt.Sprintf("Symbols (%d total)", m.symbolCount)
}

// disassembleUntilReturn disassembles from startVA until it hits a return instruction
func (m *model) disassembleUntilReturn(img *elfx.Image, startVA uint64, maxInsns int) string {
	// Just use the static version - no need for duplicate code
	return disassembleUntilReturnStatic(img, startVA, maxInsns)
}

// generateSymbolAssembly generates assembly view for a selected symbol
func (m *model) generateSymbolAssembly(symbol symbolItem) string {
	var sb strings.Builder

	// Add header with symbol information
	sb.WriteString(fmt.Sprintf("## Assembly for %s\n\n", symbol.demangled))
	sb.WriteString(fmt.Sprintf("Address: 0x%x\n", symbol.address))
	if symbol.original != symbol.demangled {
		sb.WriteString(fmt.Sprintf("Mangled: %s\n", symbol.original))
	}
	sb.WriteString("\n")

	// Check if this is an XXTEA-related function
	if isXXTEAFunction(symbol.demangled) || isXXTEAFunction(symbol.original) {
		sb.WriteString("**XXTEA-related function detected**\n\n")
	}

	sb.WriteString("```arm\n")

	// Use TraceDisasm to get annotated assembly with XXTEA detection
	// This is what disassembleUntilReturn does internally
	assembly := m.disassembleUntilReturn(m.elfImage, symbol.address, 500)
	if assembly == "" {
		assembly = "Failed to disassemble function"
	}
	sb.WriteString(assembly)
	sb.WriteString("```\n")

	return sb.String()
}

// isHexChar checks if a character is a valid hex digit
func isHexChar(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// stripFunctionParams removes parameters from a C++ function signature
func stripFunctionParams(sig string) string {
	// Find the opening parenthesis
	parenIdx := strings.Index(sig, "(")
	if parenIdx == -1 {
		return sig // No parameters to strip
	}
	return sig[:parenIdx]
}

// colorizeAnnotationUnified applies colors to annotation text for both ANSI and lipgloss
func colorizeAnnotationUnified(annotation string, useANSI bool, gray, white, red, reset string) string {
	if !useANSI {
		// Use the existing lipgloss version
		commentStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
		stringStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
		hexAddrStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
		return colorizeAnnotation(annotation, commentStyle, stringStyle, hexAddrStyle)
	}

	// ANSI version with proper C++ signature coloring
	var result strings.Builder
	i := 0

	for i < len(annotation) {
		// Check for quoted strings
		if annotation[i] == '"' {
			start := i
			i++ // Skip opening quote
			for i < len(annotation) && annotation[i] != '"' {
				if annotation[i] == '\\' && i+1 < len(annotation) {
					i += 2 // Skip escaped character
				} else {
					i++
				}
			}
			if i < len(annotation) {
				i++ // Include closing quote
			}
			// Color the entire quoted string white
			result.WriteString(white + annotation[start:i] + reset)
		} else if i < len(annotation) && isHexChar(annotation[i]) {
			// Check for hex addresses
			start := i
			for i < len(annotation) && isHexChar(annotation[i]) {
				i++
			}
			// Check if followed by " = " to see if it's an address
			if i+3 < len(annotation) && annotation[i:i+3] == " = " {
				result.WriteString(red + annotation[start:i] + reset)
			} else {
				result.WriteString(gray + annotation[start:i] + reset)
			}
		} else {
			// Regular comment text - no special coloring for C++ signatures
			start := i
			for i < len(annotation) && annotation[i] != '"' && !isHexChar(annotation[i]) {
				i++
			}
			text := annotation[start:i]
			result.WriteString(white + text + reset) // Use white for all comment text
		}
	}

	return result.String()
}

// colorizeCppSignatureANSI applies ANSI colors to C++ signatures to match colorizeCppSignature
func colorizeCppSignatureANSI(sig string, white, orange, pink, reset string) string {
	// Parse and colorize similar to colorizeCppSignature
	// Use orange for function names, light gray for namespaces
	orangeColor := "\033[38;5;214m" // Orange for function names
	grayColor := "\033[38;5;250m"   // Light gray for namespaces

	// Handle sub_ labels
	if strings.HasPrefix(sig, "sub_") {
		return orangeColor + sig + reset
	}

	if strings.Contains(sig, "::") {
		parts := strings.Split(sig, "::")
		var result []string
		for i, part := range parts {
			if i < len(parts)-1 {
				// Namespace part
				result = append(result, grayColor+part+reset)
			} else {
				// Function name part (may include parameters)
				if parenIdx := strings.Index(part, "("); parenIdx != -1 {
					// Split function name from parameters
					funcName := part[:parenIdx]
					params := part[parenIdx:]
					result = append(result, orangeColor+funcName+reset+white+params+reset)
				} else {
					result = append(result, orangeColor+part+reset)
				}
			}
		}
		// Join with colored :: separator
		output := ""
		for i, part := range result {
			if i > 0 {
				output += grayColor + "::" + reset
			}
			output += part
		}
		return output
	}
	// Simple function without namespace
	return orangeColor + sig + reset
}

// colorizeAnnotation applies colors to annotation text, particularly for strings
func colorizeAnnotation(annotation string, commentStyle, stringStyle, hexAddrStyle lipgloss.Style) string {
	var result strings.Builder
	i := 0

	for i < len(annotation) {
		// Check for quoted strings
		if annotation[i] == '"' {
			// Find the closing quote
			start := i
			i++ // Skip opening quote
			for i < len(annotation) && annotation[i] != '"' {
				if annotation[i] == '\\' && i+1 < len(annotation) {
					i += 2 // Skip escaped character
				} else {
					i++
				}
			}
			if i < len(annotation) {
				i++ // Include closing quote
			}
			// Color the entire quoted string green
			result.WriteString(stringStyle.Render(annotation[start:i]))
		} else if i < len(annotation)-1 && annotation[i:i+2] == "0x" {
			// Color hex addresses
			start := i
			i += 2 // Skip "0x"
			for i < len(annotation) && isHexChar(annotation[i]) {
				i++
			}
			result.WriteString(hexAddrStyle.Render(annotation[start:i]))
		} else {
			// Regular comment text
			start := i
			for i < len(annotation) && annotation[i] != '"' && !(i < len(annotation)-1 && annotation[i:i+2] == "0x") {
				i++
			}
			// Just use comment style for all text (no special coloring for C++ signatures in comments)
			text := annotation[start:i]
			result.WriteString(commentStyle.Render(text))
		}
	}

	return result.String()
}

// wrapAnnotations wraps long annotation text at word boundaries with proper indentation
func wrapAnnotations(annotations []string, maxWidth int, indentStr string) string {
	if len(annotations) == 0 {
		return ""
	}

	// Join all annotations
	fullText := strings.Join(annotations, ", ")

	// If it fits on one line, return as-is
	if len(fullText) <= maxWidth {
		return fullText
	}

	// Wrap at word boundaries
	var result strings.Builder
	words := strings.Fields(fullText)
	currentLine := strings.Builder{}
	lineNum := 0

	for i, word := range words {
		// Check if adding this word would exceed the width
		potentialLen := currentLine.Len() + len(word)
		if i > 0 {
			potentialLen++ // for the space
		}

		if potentialLen > maxWidth && currentLine.Len() > 0 {
			// Write current line
			if lineNum > 0 {
				result.WriteString("\n")
				result.WriteString(indentStr)
			}
			result.WriteString(currentLine.String())
			currentLine.Reset()
			lineNum++
		}

		if currentLine.Len() > 0 {
			currentLine.WriteString(" ")
		}
		currentLine.WriteString(word)
	}

	// Write remaining content
	if currentLine.Len() > 0 {
		if lineNum > 0 {
			result.WriteString("\n")
			result.WriteString(indentStr)
		}
		result.WriteString(currentLine.String())
	}

	return result.String()
}

// formatAssemblyLine formats an assembly line with colors
func formatAssemblyLine(inst analysis.AnnotatedInst, useANSI bool) string {
	// Always use Chroma colorization for consistent styling
	plain := inst.String()
	// Apply colorization in the presentation layer
	colorized := colorize.ColorizeInstructionLine(plain)
	// Add one space indentation for consistency in details page
	return " " + colorized
}

// colorizeOperands colors operands with ANSI codes
func colorizeOperands(operands string, red, white, blue, reset string, stripHexPrefix bool) string {
	colored := ""
	i := 0

	for i < len(operands) {
		switch {
		// Hex numbers (0x... or #0x...)
		case i < len(operands)-2 && operands[i:i+2] == "0x":
			if stripHexPrefix {
				i += 2 // Skip "0x"
				colored += red
				for i < len(operands) && isHexChar(operands[i]) {
					colored += string(operands[i])
					i++
				}
				colored += reset
			} else {
				colored += red + operands[i:i+2]
				i += 2
				for i < len(operands) && isHexChar(operands[i]) {
					colored += string(operands[i])
					i++
				}
				colored += reset
			}

		case i < len(operands)-3 && operands[i:i+3] == "#0x":
			colored += white + "#" + reset
			i += 1 // Skip #
			if stripHexPrefix {
				i += 2 // Skip "0x"
				colored += red
				for i < len(operands) && isHexChar(operands[i]) {
					colored += string(operands[i])
					i++
				}
				colored += reset
			} else {
				colored += red
				for i < len(operands)-1 && (operands[i:i+2] == "0x" || isHexChar(operands[i])) {
					colored += string(operands[i])
					i++
				}
				colored += reset
			}

		// Immediate decimal (#123)
		case operands[i] == '#':
			colored += white + "#" + reset
			i++
			if i < len(operands) && (operands[i] >= '0' && operands[i] <= '9' || operands[i] == '-') {
				colored += red
				for i < len(operands) && ((operands[i] >= '0' && operands[i] <= '9') || operands[i] == '-') {
					colored += string(operands[i])
					i++
				}
				colored += reset
			}

		// Special characters
		case operands[i] == '.' || operands[i] == '+' || operands[i] == '-' ||
			operands[i] == '[' || operands[i] == ']' || operands[i] == ',' ||
			operands[i] == '!' || operands[i] == '{' || operands[i] == '}':
			colored += white + string(operands[i]) + reset
			i++

		// Spaces
		case operands[i] == ' ':
			colored += " "
			i++

		// Default: registers and labels in blue
		default:
			start := i
			for i < len(operands) &&
				operands[i] != '.' && operands[i] != '+' && operands[i] != '-' &&
				operands[i] != '[' && operands[i] != ']' && operands[i] != ',' &&
				operands[i] != '!' && operands[i] != '#' && operands[i] != ' ' &&
				!(i < len(operands)-1 && operands[i:i+2] == "0x") {
				i++
			}
			if start < i {
				colored += blue + operands[start:i] + reset
			}
		}
	}

	return colored
}

// colorizeOperandsLipgloss colors operands with lipgloss styles for TUI
func colorizeOperandsLipgloss(operands string, mnemonicStyle, operandStyle, hexAddrStyle lipgloss.Style) string {
	output := ""
	i := 0

	for i < len(operands) {
		// Check for + sign before hex addresses
		if operands[i] == '+' && i+1 < len(operands) {
			output += mnemonicStyle.Render("+")
			i++
		} else if i < len(operands)-2 && operands[i:i+2] == "0x" {
			// Found hex value, collect all hex digits
			i += 2 // Skip "0x"
			hexStart := i
			for i < len(operands) && isHexChar(operands[i]) {
				i++
			}
			// Color the hex value red (without 0x)
			output += hexAddrStyle.Render(operands[hexStart:i])
		} else if i < len(operands)-3 && operands[i:i+3] == "#0x" {
			// ARM immediate with hex: #0x...
			output += operandStyle.Render("#")
			i += 3 // Skip "#0x"
			hexStart := i
			for i < len(operands) && isHexChar(operands[i]) {
				i++
			}
			output += hexAddrStyle.Render(operands[hexStart:i])
		} else if i >= 4 && operands[i-4:i] == "loc_" {
			// Local label like loc_xxxxx
			labelEnd := i
			for labelEnd < len(operands) && isHexChar(operands[labelEnd]) {
				labelEnd++
			}
			output += hexAddrStyle.Render(operands[i:labelEnd])
			i = labelEnd
		} else {
			// Regular character - find next special sequence
			nextHex := strings.Index(operands[i:], "0x")
			nextImm := strings.Index(operands[i:], "#0x")
			nextLoc := strings.Index(operands[i:], "loc_")
			nextStop := len(operands) - i

			// Find the nearest special sequence
			if nextImm >= 0 && (nextHex < 0 || nextImm < nextHex) && (nextLoc < 0 || nextImm < nextLoc) {
				nextStop = nextImm
			} else if nextHex >= 0 && (nextLoc < 0 || nextHex < nextLoc) {
				nextStop = nextHex
			} else if nextLoc >= 0 {
				nextStop = nextLoc
			}

			output += operandStyle.Render(operands[i : i+nextStop])
			i += nextStop
		}
	}

	return output
}

// escapeBackticks escapes backticks in strings for markdown display
func escapeBackticks(s string) string {
	return strings.ReplaceAll(s, "`", "\\`")
}

// isXXTEAFunction checks if a symbol is XXTEA-related
func isXXTEAFunction(symbol string) bool {
	lower := strings.ToLower(symbol)
	// Only match actual setter functions, not getters or singletons
	return (strings.Contains(lower, "set") && strings.Contains(lower, "xxtea")) ||
		strings.Contains(lower, "setcryptokey")
}

// analyzeXXTEACalls analyzes a function for XXTEA calls and formats the results
// Returns the formatted string and a map of additional functions that were traced
func analyzeXXTEACalls(img *elfx.Image, funcName string, funcAddr uint64) (string, map[uint64]string) {
	var result strings.Builder
	tracedFunctions := make(map[uint64]string)

	// Use TraceDisasm to analyze the function (increased limit for complex functions)
	traceResult, err := analysis.TraceDisasm(img, funcAddr, 1000)
	if err != nil {
		return "", tracedFunctions
	}

	// Apply XXTEA detector to enrich findings
	if len(traceResult.Findings) > 0 {
		detector := detectors.NewXXTEADetector()
		traceResult.Findings = detector.Detect(traceResult.Findings)
	}

	if len(traceResult.Findings) == 0 {
		return "", tracedFunctions
	}

	// Count and process all XXTEA-related findings
	// Track seen addresses and targets to avoid duplicates
	seenAddresses := make(map[uint64]bool)
	seenTargets := make(map[string]uint64) // target -> last address we saw it at
	seenParams := make(map[string]bool)    // track parameter combinations we've seen
	xxteaCallCount := 0
	for _, finding := range traceResult.Findings {

		// Skip if we've already processed this call address
		if seenAddresses[finding.CallVA] {
			continue
		}

		// Skip duplicate calls to the same target that are very close together (within 16 bytes)
		// This handles cases where consecutive calls are made for c_str() operations
		if lastAddr, seen := seenTargets[finding.Target]; seen {
			if finding.CallVA > lastAddr && finding.CallVA-lastAddr <= 16 {
				// This is likely a duplicate call for getting another parameter
				continue
			}
		}
		seenTargets[finding.Target] = finding.CallVA

		// Create a signature based on the function AND parameter values to detect duplicates
		// We want to show different functions even if they have the same parameters
		var paramSig string
		// Include the target function in the signature to distinguish different functions
		paramSig = finding.Target + ":"
		for _, arg := range finding.Args {
			if arg.Reg == "x1" || arg.Reg == "x3" {
				if str, ok := arg.Value.(string); ok {
					paramSig += str + "|"
				}
			}
		}
		if paramSig != "" && seenParams[paramSig] {
			// Skip if we've already seen this exact function with these exact parameters
			continue
		}
		if paramSig != "" {
			seenParams[paramSig] = true
		}

		// Check if this is a direct XXTEA function
		isDirectXXTEA := isXXTEAFunction(finding.Symbol) || isXXTEAFunction(finding.Target)

		// Don't skip indirect calls - they can be virtual XXTEA methods!
		// The vtable offset #232 is specifically setXXTEAKeyAndSign
		// We detect XXTEA calls based on the function being called, not the register used

		// For XXTEA functions, check if we have actual string parameters
		var hasValidParams bool
		if isDirectXXTEA {
			// For direct XXTEA functions, check if we have at least one string parameter
			for _, arg := range finding.Args {
				if arg.Reg == "x1" || arg.Reg == "x3" {
					if str, ok := arg.Value.(string); ok && len(str) >= 4 {
						hasValidParams = true
						break
					}
				}
			}
			if !hasValidParams {
				// For XXTEA functions where we only have stack addresses, not actual values,
				// we still want to show them but indicate we couldn't extract params
				// Track the function for Assembly Details
				tracedFunctions[funcAddr] = funcName

				// Still generate output but indicate params couldn't be extracted
				// We'll mark this finding and process it below with special handling
				// Don't skip - let it continue to be processed
			}
		} else {
			// For sub_ functions, check if they have XXTEA-like parameters
			// These might be PLT entries or simple wrappers
			// Only accept sub_ functions that have the full XXTEA signature
			if strings.HasPrefix(finding.Target, "sub_") {
				var hasKeyStr, hasKeyLen, hasSignStr, hasSignLen bool

				for _, arg := range finding.Args {
					switch arg.Reg {
					case "x1":
						if str, ok := arg.Value.(string); ok && len(str) >= 4 && len(str) <= 64 {
							hasKeyStr = true
						}
					case "w2", "x2":
						if _, ok := arg.Value.(int64); ok {
							hasKeyLen = true
						} else if _, ok := arg.Value.(uint64); ok {
							hasKeyLen = true
						}
					case "x3":
						if str, ok := arg.Value.(string); ok && len(str) >= 4 && len(str) <= 64 {
							hasSignStr = true
						}
					case "w4", "x4":
						if _, ok := arg.Value.(int64); ok {
							hasSignLen = true
						} else if _, ok := arg.Value.(uint64); ok {
							hasSignLen = true
						}
					}
				}

				// Only accept sub_ functions with full XXTEA signature (4 params)
				// This filters out std::string constructors and other non-XXTEA functions
				if !(hasKeyStr && hasKeyLen && hasSignStr && hasSignLen) {
					continue
				}
				// This looks like an XXTEA call (possibly through PLT)
			} else {
				// Not a sub_ function and not a direct XXTEA function
				continue
			}
		}

		// Mark this address as seen
		seenAddresses[finding.CallVA] = true

		xxteaCallCount++

		// Track this function as having XXTEA findings
		tracedFunctions[funcAddr] = funcName

		// Format the discovery - build the complete sentence first
		var sentence strings.Builder

		// Use backtrace if available to show the call chain
		if len(finding.Backtrace) > 0 {
			// Show the complete call chain
			if len(finding.Backtrace) == 1 {
				// Direct call from the entry point
				sentence.WriteString(fmt.Sprintf("`%s`", finding.Backtrace[0]))
			} else {
				// Multiple functions in the chain
				sentence.WriteString(fmt.Sprintf("`%s`", finding.Backtrace[0]))
				for i := 1; i < len(finding.Backtrace); i++ {
					if i == len(finding.Backtrace)-1 {
						sentence.WriteString(fmt.Sprintf(" tail-calls to `%s` which", finding.Backtrace[i]))
					} else {
						sentence.WriteString(fmt.Sprintf(" tail-calls to `%s` which", finding.Backtrace[i]))
					}
				}
			}
		} else if strings.HasPrefix(funcName, "tail_call_from_") {
			// Fallback to old logic if no backtrace
			// Extract the original function and target function names
			// Format: tail_call_from_<original>_to_<target>
			parts := strings.SplitN(strings.TrimPrefix(funcName, "tail_call_from_"), "_to_", 2)
			if len(parts) == 2 {
				originalFunc := parts[0]
				targetFunc := parts[1]
				sentence.WriteString(fmt.Sprintf("`%s` tail-calls to `%s` which", originalFunc, targetFunc))
			} else {
				// Fallback for old format
				originalFunc := strings.TrimPrefix(funcName, "tail_call_from_")
				sentence.WriteString(fmt.Sprintf("`%s` tail-calls to a function that", originalFunc))
			}
		} else {
			sentence.WriteString(fmt.Sprintf("`%s`", funcName))
		}
		sentence.WriteString(" makes a ")

		// Add call type
		if strings.Contains(finding.Comment, "vtable") {
			sentence.WriteString("vtable dispatch to ")
		} else {
			sentence.WriteString("call to ")
		}

		// Determine target function name
		targetName := finding.Target
		// For sub_ functions with XXTEA parameters, indicate they might be PLT entries
		// These are often PLT stubs for the actual XXTEA functions
		if strings.HasPrefix(finding.Target, "sub_") && !isDirectXXTEA {
			// This is likely a PLT entry for an XXTEA function
			// Check if we can identify which XXTEA function based on parameters
			hasKey := false
			hasKeyLen := false
			hasSign := false
			hasSignLen := false

			for _, arg := range finding.Args {
				switch arg.Reg {
				case "x1":
					if str, ok := arg.Value.(string); ok && str != "" && !strings.HasPrefix(str, "0x") {
						hasKey = true
					}
				case "w2", "x2":
					if _, ok := arg.Value.(int64); ok {
						hasKeyLen = true
					}
				case "x3":
					if str, ok := arg.Value.(string); ok && str != "" && !strings.HasPrefix(str, "0x") {
						hasSign = true
					}
				case "w4", "x4":
					if _, ok := arg.Value.(int64); ok {
						hasSignLen = true
					}
				}
			}

			// If we have all 4 XXTEA parameters, this is setXXTEAKeyAndSign
			// Or if we have both key and sign strings (lengths might be computed in the PLT)
			if (hasKey && hasKeyLen && hasSign && hasSignLen) || (hasKey && hasSign) {
				targetName = "setXXTEAKeyAndSign@PLT"
			} else {
				// Generic PLT entry
				targetName = fmt.Sprintf("%s@PLT", finding.Target)
			}
		}

		// Add target name to sentence
		sentence.WriteString(fmt.Sprintf("`%s`", targetName))

		// Format the parameters
		if len(finding.Args) > 0 {
			sentence.WriteString(", with")

			// Look for key and sign parameters
			var keyValue, signValue string
			var keyLen, signLen int
			var hasLengths bool
			var sourceType string

			// Check if XOR obfuscation was detected in the trace
			var hasXORObfuscation bool
			for _, inst := range traceResult.Listing {
				for _, annotation := range inst.Annotations {
					if strings.Contains(annotation, "[XOR_OBFUSCATION") || strings.Contains(annotation, "[XOR with") {
						hasXORObfuscation = true
						break
					}
				}
				if hasXORObfuscation {
					break
				}
			}

			// Check if the detector has populated metadata
			if finding.Metadata != nil {
				if key, ok := finding.Metadata["key"].(string); ok && key != "" {
					keyValue = fmt.Sprintf("`%s`", escapeBackticks(key))
					keyLen = len(key)
				}
				if kl, ok := finding.Metadata["key_len"].(int64); ok && kl > 0 {
					keyLen = int(kl)
				}
				if sign, ok := finding.Metadata["sign"].(string); ok && sign != "" {
					signValue = fmt.Sprintf("`%s`", escapeBackticks(sign))
					signLen = len(sign)
				}
				if sl, ok := finding.Metadata["sign_len"].(int64); ok && sl > 0 {
					signLen = int(sl)
				}
			}

			// Only parse args if we didn't get the values from comment
			for _, arg := range finding.Args {
				switch arg.Reg {
				case "x1": // key parameter (for regular XXTEA functions)
					if arg.Value != nil && keyValue == "" {
						if str, ok := arg.Value.(string); ok {
							keyValue = fmt.Sprintf("`%s`", escapeBackticks(str))
							keyLen = len(str)
						}
						if sourceType == "" && arg.From != "" {
							sourceType = arg.From
						}
					}
				case "x2": // Could be key length OR signature (for std::string& functions)
					if arg.Value != nil {
						if str, ok := arg.Value.(string); ok {
							// x2 has a string - this is the signature for std::string& functions
							signValue = fmt.Sprintf("`%s`", escapeBackticks(str))
							signLen = len(str)
						} else if val, ok := arg.Value.(uint64); ok && val > 0 {
							// x2 has an integer - this is the key length
							hasLengths = true
						} else if val, ok := arg.Value.(int); ok && val > 0 {
							hasLengths = true
						}
					}
				case "w2": // key length (32-bit)
					if val, ok := arg.Value.(uint64); ok && val > 0 {
						hasLengths = true
					} else if val, ok := arg.Value.(int); ok && val > 0 {
						hasLengths = true
					}
				case "x3": // sign parameter (for regular XXTEA functions)
					if arg.Value != nil && signValue == "" {
						if str, ok := arg.Value.(string); ok {
							signValue = fmt.Sprintf("`%s`", escapeBackticks(str))
							signLen = len(str)
						}
						if sourceType == "" && arg.From != "" {
							sourceType = arg.From
						}
					}
				case "w4", "x4": // sign length
					if val, ok := arg.Value.(uint64); ok && val > 0 {
						hasLengths = true
					} else if val, ok := arg.Value.(int); ok && val > 0 {
						hasLengths = true
					}
				}
			}

			if keyValue != "" || signValue != "" {
				// We have at least one parameter
				if keyValue != "" {
					sentence.WriteString(fmt.Sprintf(" key %s", keyValue))
					// Add computed length if we don't have explicit lengths
					if keyLen > 0 && !hasLengths {
						sentence.WriteString(fmt.Sprintf(" (len=%d)", keyLen))
					}
					// Add XOR warning if detected
					if hasXORObfuscation {
						sentence.WriteString(" **[XOR-obfuscated]**")
					}
				} else {
					sentence.WriteString(" key (unknown)")
					if hasXORObfuscation {
						sentence.WriteString(" **[XOR-obfuscated]**")
					}
				}

				if signValue != "" {
					sentence.WriteString(fmt.Sprintf(" and signature %s", signValue))
					// Add computed length if we don't have explicit lengths
					if signLen > 0 && !hasLengths {
						sentence.WriteString(fmt.Sprintf(" (len=%d)", signLen))
					}
				} else if isDirectXXTEA {
					// Only show "signature (unknown)" if the function actually expects a signature
					// Functions that take std::string (like jsb_set_xxtea_key) only have a key, no signature
					// Check if this is a function that expects both key and signature (x1 and x3 parameters)
					hasX3Param := false
					for _, arg := range finding.Args {
						if arg.Reg == "x3" || arg.Reg == "w4" || arg.Reg == "x4" {
							hasX3Param = true
							break
						}
					}

					// Only show signature if the function signature expects it
					if hasX3Param && !strings.Contains(strings.ToLower(targetName), "keygroup") {
						sentence.WriteString(" and signature (unknown)")
					}
				}

				if sourceType != "" {
					sentence.WriteString(fmt.Sprintf(" using %s", sourceType))
				}
			} else if isDirectXXTEA {
				// No parameters could be extracted for a direct XXTEA function
				sentence.WriteString(" (parameters could not be extracted)")
			}
		}

		// Write the complete sentence - let glamour handle wrapping
		result.WriteString(sentence.String())
		result.WriteString(".\n\n")

		// Compute the actual trace range for XXTEA calls
		// Only consider x1 (key) and x3 (sign) parameters, not x0, x2, x4
		var xxteaTraceMin uint64
		for _, arg := range finding.Args {
			// Only track x1 and x3 for XXTEA functions
			if arg.Reg == "x1" || arg.Reg == "x3" {
				if arg.TraceVA != 0 && (xxteaTraceMin == 0 || arg.TraceVA < xxteaTraceMin) {
					xxteaTraceMin = arg.TraceVA
				}
			}
		}
		if xxteaTraceMin == 0 {
			xxteaTraceMin = finding.CallVA // Fall back to the call itself
		}

		// Add the actual assembly code from the trace range
		// For XXTEA calls, we want to show only the relevant instructions for THIS specific call
		if finding.CallVA != 0 {
			result.WriteString("```arm\n")

			// Collect important instructions to show for THIS specific call
			importantVAs := make(map[uint64]bool)

			// Extract the key and signature values from the finding
			var keyValue, signValue string
			for _, arg := range finding.Args {
				if arg.Reg == "x1" {
					if str, ok := arg.Value.(string); ok {
						keyValue = str
					}
				} else if arg.Reg == "x3" {
					if str, ok := arg.Value.(string); ok {
						signValue = str
					}
				}
			}

			// Find where these strings appear in annotations and include everything from there to the call
			// We need to find the FIRST occurrence, including in STRING annotations and STD::STRING PREP
			var firstStringVA uint64
			var callVA uint64

			// First pass: find the call and any string references
			for _, inst := range traceResult.Listing {
				// Mark the call
				if inst.VA == finding.CallVA {
					importantVAs[inst.VA] = true
					callVA = inst.VA
				}

				// Check if this instruction has our key or signature in its annotations
				// Look for the string in any context (STRING, STD::STRING PREP, STD::STRING LOAD, etc.)
				for _, annotation := range inst.Annotations {
					if (keyValue != "" && strings.Contains(annotation, fmt.Sprintf("\"%s\"", keyValue))) ||
						(keyValue != "" && strings.Contains(annotation, fmt.Sprintf("'%s'", keyValue))) ||
						(signValue != "" && strings.Contains(annotation, fmt.Sprintf("\"%s\"", signValue))) ||
						(signValue != "" && strings.Contains(annotation, fmt.Sprintf("'%s'", signValue))) {
						if firstStringVA == 0 || inst.VA < firstStringVA {
							firstStringVA = inst.VA
						}
						break
					}
				}
			}

			// Second pass: include all instructions from first string to call
			if firstStringVA != 0 && callVA != 0 {
				for _, inst := range traceResult.Listing {
					if inst.VA >= firstStringVA && inst.VA <= callVA {
						importantVAs[inst.VA] = true
					}
				}
			}

			// If we still don't have enough context (less than 10 instructions), expand the window
			if len(importantVAs) < 10 && callVA != 0 {
				// Find the call instruction index
				callIndex := -1
				for i, inst := range traceResult.Listing {
					if inst.VA == callVA {
						callIndex = i
						break
					}
				}

				if callIndex >= 0 {
					// Include up to 20 instructions before the call
					start := callIndex - 20
					if start < 0 {
						start = 0
					}
					for i := start; i <= callIndex && i < len(traceResult.Listing); i++ {
						importantVAs[traceResult.Listing[i].VA] = true
					}
				}
			}

			// For std::string& calls, if we have very few instructions, show more context
			isStringRefCall := strings.Contains(finding.Target, "std::string const&")
			if isStringRefCall && len(importantVAs) <= 2 {
				// Find the call instruction index
				callIndex := -1
				for i, inst := range traceResult.Listing {
					if inst.VA == finding.CallVA {
						callIndex = i
						break
					}
				}

				if callIndex >= 0 {
					// Include up to 30 instructions before the call to show string setup
					// std::string& parameters are often loaded much earlier
					start := callIndex - 30
					if start < 0 {
						start = 0
					}

					// Get the key from the finding to look for it in the assembly
					var keyToFind string
					for _, arg := range finding.Args {
						if arg.Reg == "x1" && arg.From == "std::string&" {
							if str, ok := arg.Value.(string); ok {
								keyToFind = str
								break
							}
						}
					}

					for i := start; i < callIndex; i++ {
						inst := traceResult.Listing[i]
						// Include instructions that might be setting up string parameters
						includeInst := false

						// Always include control flow and parameter setup
						if strings.Contains(inst.Mnemonic, "adrp") ||
							strings.Contains(inst.Mnemonic, "add") ||
							strings.Contains(inst.Mnemonic, "mov") ||
							strings.Contains(inst.Mnemonic, "str") ||
							strings.Contains(inst.Mnemonic, "bl") {
							includeInst = true
						}

						// If we know the key, include instructions that reference it
						if keyToFind != "" {
							for _, annotation := range inst.Annotations {
								if strings.Contains(annotation, keyToFind) {
									includeInst = true
									break
								}
							}
						}

						if includeInst {
							importantVAs[inst.VA] = true
						}
					}
				}
			}

			// Display only the important instructions in order
			for _, inst := range traceResult.Listing {
				if importantVAs[inst.VA] {
					// Format without ANSI colors for clean markdown
					line := formatAssemblyLine(inst, false)
					result.WriteString(line + "\n")
				}
			}

			result.WriteString("```\n")
		}

		result.WriteString("\n")
	}

	return result.String(), tracedFunctions
}

// formatXXTEACallParams formats just the parameter values for XXTEA functions
func formatXXTEACallParams(symbol string, args []analysis.ParamValue) []string {
	lower := strings.ToLower(symbol)

	if len(args) == 0 {
		return nil
	}

	// Map args by register to values
	argMap := make(map[string]analysis.ParamValue)
	for _, arg := range args {
		argMap[arg.Reg] = arg
	}

	// Check if we have sign parameters (x3/w4)
	hasSign := false
	if _, hasX3 := argMap["x3"]; hasX3 {
		if _, hasW4 := argMap["w4"]; hasW4 {
			hasSign = true
		}
	}

	// Determine if this is a full key+sign call
	hasKeyAndSign := (strings.Contains(lower, "keyandsign") || strings.Contains(lower, "setcryptokey") || hasSign)

	var lines []string

	// Special formatting for setXXTEAKeyAndSign - combine key and sign into one line
	if hasKeyAndSign {
		// Has both key and sign
		_, hasKey := argMap["x1"]
		_, hasSign := argMap["x3"]

		if hasKey && hasSign {
			// Removed the details line with key and signature at user's request
			return lines
		}
	}

	// Don't show parameter annotations in the details page
	// The parameters are already shown in the summary

	return lines
}

// formatXXTEACall formats an XXTEA function call with signature
func formatXXTEACall(demangledName, symbol string, args []analysis.ParamValue) []string {
	lower := strings.ToLower(symbol)

	// If we have no args, just return the function with a generic XXTEA signature
	if len(args) == 0 {
		if strings.Contains(lower, "keyandsign") || strings.Contains(lower, "setcryptokey") {
			return []string{fmt.Sprintf("%s(const char* key, int keyLen, const char* sign, int signLen)", demangledName)}
		}
		return []string{fmt.Sprintf("%s(const char* key, int keyLen)", demangledName)}
	}

	// Map args by register to values
	argMap := make(map[string]analysis.ParamValue)
	for _, arg := range args {
		argMap[arg.Reg] = arg
	}

	// Determine signature based on function name AND available parameters
	var signature string
	var paramNames []string
	var expectedRegs []string

	// Check if we have sign parameters (x3/w4)
	hasSign := false
	if _, hasX3 := argMap["x3"]; hasX3 {
		if _, hasW4 := argMap["w4"]; hasW4 {
			hasSign = true
		}
	}

	// setXXTEAKeyAndSign or setCryptoKey always have sign
	if strings.Contains(lower, "keyandsign") || strings.Contains(lower, "setcryptokey") {
		// Full signature with key and sign
		signature = fmt.Sprintf("%s(const char* key, int keyLen, const char* sign, int signLen)", demangledName)
		paramNames = []string{"key", "keyLen", "sign", "signLen"}
		expectedRegs = []string{"x1", "w2", "x3", "w4"}
	} else if hasSign {
		// setXXTEAKey with sign parameters detected
		signature = fmt.Sprintf("%s(const char* key, int keyLen, const char* sign, int signLen)", demangledName)
		paramNames = []string{"key", "keyLen", "sign", "signLen"}
		expectedRegs = []string{"x1", "w2", "x3", "w4"}
	} else {
		// setXXTEAKey with just key
		signature = fmt.Sprintf("%s(const char* key, int keyLen)", demangledName)
		paramNames = []string{"key", "keyLen"}
		expectedRegs = []string{"x1", "w2"}
	}

	lines := []string{signature}

	// Format values based on expected signature
	for i, name := range paramNames {
		if i < len(expectedRegs) {
			reg := expectedRegs[i]
			if arg, ok := argMap[reg]; ok {
				var value string
				switch v := arg.Value.(type) {
				case string:
					value = fmt.Sprintf("\"%s\"", v)
				case uint64:
					value = fmt.Sprintf("0x%x", v)
				default:
					value = fmt.Sprintf("%v", v)
				}
				lines = append(lines, fmt.Sprintf("    %s = %s", name, value))
			} else {
				lines = append(lines, fmt.Sprintf("    %s = ?", name))
			}
		}
	}

	return lines
}

// findSymbolAtAddress looks up a symbol at the given address
func (m *model) findSymbolAtAddress(addr uint64) *symbolInfo {
	for i := range m.symbols {
		if m.symbols[i].address == addr {
			return &m.symbols[i]
		}
	}
	return nil
}

// isPrintableString checks if byte data is mostly printable ASCII
func isPrintableString(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printableCount := 0
	for _, b := range data {
		if (b >= 32 && b < 127) || b == '\n' || b == '\r' || b == '\t' {
			printableCount++
		}
	}
	// Consider it a string if at least 75% is printable
	return float64(printableCount)/float64(len(data)) >= 0.75
}

func (m *model) runCocosDetector() {
	if len(m.symbols) == 0 {
		m.detectorProcessed = true
		return
	}

	// Get .rodata range from the stored ELF image
	var rodataStart, rodataEnd uint64
	if m.elfImage != nil {
		rodataStart = m.elfImage.Rodata.VA
		rodataEnd = m.elfImage.Rodata.VA + m.elfImage.Rodata.Size
	}

	// Categories
	var entryPoints []symbolInfo
	var setters []symbolInfo
	var xxteaMethods []symbolInfo
	var xxteaFunctions []symbolInfo
	var xxteaVariables []symbolInfo
	var xxteaRodata []symbolInfo // Symbols in .rodata section

	for _, sym := range m.symbols {
		nameLower := strings.ToLower(sym.name)
		demangled := demangle.Filter(sym.name)
		demangledLower := strings.ToLower(demangled)

		// Categorize symbol by type
		switch {
		case analysis.IsEntryPoint(sym.name, demangled, nameLower, demangledLower):
			entryPoints = append(entryPoints, sym)

		case analysis.IsSetter(nameLower):
			setters = append(setters, sym)

		case strings.Contains(nameLower, "xxtea") || strings.Contains(demangledLower, "xxtea"):
			// XXTEA-related symbol - further categorize by type
			switch {
			case rodataStart > 0 && sym.address >= rodataStart && sym.address < rodataEnd:
				// In .rodata section
				xxteaRodata = append(xxteaRodata, sym)
			case !strings.Contains(demangled, "("):
				// Variable (no parentheses)
				xxteaVariables = append(xxteaVariables, sym)
			case strings.Contains(demangled, "::") || strings.HasPrefix(sym.name, "_ZN"):
				// Method (contains :: or starts with _ZN for mangled C++)
				xxteaMethods = append(xxteaMethods, sym)
			default:
				// Standalone function
				xxteaFunctions = append(xxteaFunctions, sym)
			}
		}
	}

	// Build plain text view
	var result strings.Builder

	// Styles
	addressStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))

	result.WriteString(headerStyle.Render("Cocos") + "\n\n")

	// Analyze entry points for XXTEA calls and store for info panel
	var xxteaFindings strings.Builder
	if len(entryPoints) > 0 && m.elfImage != nil {
		for _, sym := range entryPoints {
			demangled := demangle.Filter(sym.name)
			if demangled == "" {
				demangled = sym.name
			}

			// Analyze this entry point for XXTEA calls
			findings, _ := analyzeXXTEACalls(m.elfImage, demangled, sym.address)
			if findings != "" {
				xxteaFindings.WriteString(findings)
			}
		}
	}

	// Store XXTEA findings for the info panel
	if xxteaFindings.Len() > 0 {
		m.xxteaDetection = xxteaFindings.String()
		// Update the info panel content
		m.updateContent()
	}

	// Then show entry points with disassembly
	if len(entryPoints) > 0 {
		result.WriteString(headerStyle.Render("Entry Points") + "\n\n")
		for _, sym := range entryPoints {
			demangled := demangle.Filter(sym.name)
			if demangled == "" {
				demangled = sym.name
			}

			// Show address and symbol name as a label (without parameters)
			funcName := stripFunctionParams(demangled)
			colorized := colorizeCppSignature(funcName)
			result.WriteString(fmt.Sprintf("%s  %s:\n",
				addressStyle.Render(fmt.Sprintf("%x", sym.address)),
				colorized))

			// Add disassembly for this entry point
			if m.elfImage != nil {
				disasm := m.disassembleUntilReturn(m.elfImage, sym.address, 500) // Max 500 instructions (same as --full mode)
				if disasm != "" {
					result.WriteString(disasm)
					result.WriteString("\n") // Add blank line after disassembly
				}
			}
		}
		result.WriteString("\n")
	}

	// Setters
	if len(setters) > 0 {
		for _, sym := range setters {
			demangled := demangle.Filter(sym.name)
			if demangled == "" {
				demangled = sym.name
			}
			colorized := colorizeCppSignature(demangled)
			result.WriteString(fmt.Sprintf(" %s  %s\n",
				addressStyle.Render(fmt.Sprintf("%x", sym.address)),
				colorized))
		}
		result.WriteString("\n")
	}

	// Methods (class member functions)
	if len(xxteaMethods) > 0 {
		for _, sym := range xxteaMethods {
			demangled := demangle.Filter(sym.name)
			if demangled == "" {
				demangled = sym.name
			}
			colorized := colorizeCppSignature(demangled)
			result.WriteString(fmt.Sprintf(" %s  %s\n",
				addressStyle.Render(fmt.Sprintf("%x", sym.address)),
				colorized))
		}
		result.WriteString("\n")
	}

	// Functions (standalone)
	if len(xxteaFunctions) > 0 {
		for _, sym := range xxteaFunctions {
			demangled := demangle.Filter(sym.name)
			if demangled == "" {
				demangled = sym.name
			}
			colorized := colorizeCppSignature(demangled)
			result.WriteString(fmt.Sprintf(" %s  %s\n",
				addressStyle.Render(fmt.Sprintf("%x", sym.address)),
				colorized))
		}
		result.WriteString("\n")
	}

	// Variables
	if len(xxteaVariables) > 0 {
		for _, sym := range xxteaVariables {
			demangled := demangle.Filter(sym.name)
			if demangled == "" {
				demangled = sym.name
			}
			colorized := colorizeCppSignature(demangled)
			result.WriteString(fmt.Sprintf(" %s  %s\n",
				addressStyle.Render(fmt.Sprintf("%x", sym.address)),
				colorized))
		}
		result.WriteString("\n")
	}

	// .rodata section (if any) - read and display the actual data
	if len(xxteaRodata) > 0 {

		for _, sym := range xxteaRodata {
			// Get a simplified symbol name for the label
			symbolName := sym.name
			// Remove common prefixes/namespaces for cleaner labels
			if idx := strings.LastIndex(symbolName, "::"); idx >= 0 {
				symbolName = symbolName[idx+2:]
			}
			if idx := strings.LastIndex(symbolName, "."); idx >= 0 {
				symbolName = symbolName[idx+1:]
			}

			// Try to read data at this address using the stored ELF image
			if m.elfImage != nil {
				if data, ok := m.elfImage.ReadBytesVA(sym.address, 256); ok && len(data) > 0 {
					// Check if it looks like a string (has printable chars and null terminator)
					var stringData []byte
					hasNull := false
					for _, b := range data {
						if b == 0 {
							hasNull = true
							break // Found null terminator
						}
						stringData = append(stringData, b)
						if len(stringData) > 128 { // Limit string length
							break
						}
					}

					// Format like IDA: address label: db "string", 0
					if hasNull && len(stringData) > 0 && isPrintableString(stringData) {
						// IDA-style string display
						result.WriteString(fmt.Sprintf(" %x %s: db \"",
							sym.address,
							symbolName))

						// Debug: Show length and first few bytes in hex
						// Uncomment to debug string extraction
						// result.WriteString(fmt.Sprintf("[len=%d, first bytes: ", len(stringData)))
						// for i := 0; i < len(stringData) && i < 10; i++ {
						//     result.WriteString(fmt.Sprintf("%02x ", stringData[i]))
						// }
						// result.WriteString("] ")

						for _, b := range stringData {
							switch b {
							case '\n':
								result.WriteString("\\n")
							case '\r':
								result.WriteString("\\r")
							case '\t':
								result.WriteString("\\t")
							case '\\':
								result.WriteString("\\\\")
							case '"':
								result.WriteString("\\\"")
							default:
								if unicode.IsPrint(rune(b)) && b < 127 {
									result.WriteString(string(b))
								} else {
									result.WriteString(fmt.Sprintf("\\x%02x", b))
								}
							}
						}
						result.WriteString("\", 0\n")
					} else {
						// Display as hex bytes for binary data
						displayData := data
						if len(displayData) > 32 {
							displayData = displayData[:32]
						}

						result.WriteString(fmt.Sprintf(" %x %s: db ",
							sym.address,
							symbolName))

						for i, b := range displayData {
							if i > 0 {
								result.WriteString(", ")
							}
							result.WriteString(fmt.Sprintf("%02Xh", b))
						}
						if len(displayData) < len(data) {
							result.WriteString("...")
						}
						result.WriteString("\n")
					}
				} else {
					// No data available, just show the symbol
					result.WriteString(fmt.Sprintf("        %x %s\n",
						sym.address,
						symbolName))
				}
			}
		}
	}

	if len(entryPoints) == 0 && len(setters) == 0 && len(xxteaVariables) == 0 && len(xxteaMethods) == 0 && len(xxteaFunctions) == 0 && len(xxteaRodata) == 0 {
		result.WriteString("No XXTEA-related symbols found\n\n")
		result.WriteString("Press 'd' to view the details panel for entry point disassembly\n")
	}

	// Set plain content directly
	m.detectorView.SetContent(result.String())
	m.detectorProcessed = true
}

// runNoTUI runs the reverse tool in non-interactive mode
func runJSON(filePath string) error {
	// Load the ELF file
	img, err := elfx.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to load file: %v", err)
	}
	defer img.Close()

	// Calculate digest
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return fmt.Errorf("failed to calculate digest: %v", err)
	}
	digest := fmt.Sprintf("%x", h.Sum(nil))

	// Load symbols
	symbols := make([]elfx.DynSym, 0)
	// Try dynamic symbols first, then regular symbols
	if dynsyms := img.Dynsyms; len(dynsyms) > 0 {
		symbols = dynsyms
	} else if syms := img.Syms; len(syms) > 0 {
		symbols = syms
	}

	// Find entry points
	var entryPoints []symbolInfo
	var entryPointNames []string
	for _, sym := range symbols {
		nameLower := strings.ToLower(sym.Name)
		demangled := demangle.Filter(sym.Name)
		demangledLower := strings.ToLower(demangled)

		// Use the centralized IsEntryPoint function
		if analysis.IsEntryPoint(sym.Name, demangled, nameLower, demangledLower) {
			entryPoints = append(entryPoints, symbolInfo{
				address: sym.Addr,
				name:    sym.Name,
			})
			entryPointNames = append(entryPointNames, sym.Name)
		}
	}

	// Analyze XXTEA calls
	var setters []XXTEASetterInfo
	for _, sym := range entryPoints {
		demangled := demangle.Filter(sym.name)
		if demangled == "" {
			demangled = sym.name
		}

		// Extract XXTEA info using existing analysis
		xxteaInfo := extractXXTEAInfo(img, demangled, sym.address)
		setters = append(setters, xxteaInfo...)
	}

	// Create JSON output
	output := JSONOutput{
		Digest:      digest,
		EntryPoints: entryPointNames,
		Setters:     setters,
	}

	// Marshal to JSON with indentation
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

// extractXXTEAInfo extracts XXTEA setter information for JSON output
func extractXXTEAInfo(img *elfx.Image, funcName string, funcAddr uint64) []XXTEASetterInfo {
	var result []XXTEASetterInfo

	// Use TraceDisasm to analyze the function
	traceResult, err := analysis.TraceDisasm(img, funcAddr, 1000)
	if err != nil {
		return result
	}

	// Apply XXTEA detector to enrich findings
	if len(traceResult.Findings) > 0 {
		detector := detectors.NewXXTEADetector()
		traceResult.Findings = detector.Detect(traceResult.Findings)
	}

	if len(traceResult.Findings) == 0 {
		return result
	}

	// Process all XXTEA-related findings
	for _, finding := range traceResult.Findings {
		if !isXXTEAFunction(finding.Symbol) && !isXXTEAFunction(finding.Target) {
			continue
		}

		info := XXTEASetterInfo{
			Address:  fmt.Sprintf("0x%x", finding.CallVA),
			Function: finding.Target,
		}

		// First check metadata populated by detector
		if finding.Metadata != nil {
			if key, ok := finding.Metadata["key"].(string); ok {
				info.Key = sanitizeForJSON(key)
			}
			if sign, ok := finding.Metadata["sign"].(string); ok {
				info.Signature = sanitizeForJSON(sign)
			}
		}

		// Fallback to extracting from Args if metadata not populated
		if info.Key == "" || info.Signature == "" {
			for _, arg := range finding.Args {
				switch arg.Reg {
				case "x0": // jsb_set_xxtea_key uses x0 for std::string parameter
					if strings.Contains(strings.ToLower(finding.Target), "jsb_set_xxtea_key") {
						if arg.Value != nil && info.Key == "" {
							if str, ok := arg.Value.(string); ok && str != "" {
								info.Key = sanitizeForJSON(str)
							}
						}
					}
				case "x1": // key parameter for other functions
					if arg.Value != nil && info.Key == "" {
						if str, ok := arg.Value.(string); ok {
							info.Key = sanitizeForJSON(str)
						}
					}
				case "x2": // signature parameter for setCryptoKeyAndSign
					if arg.Value != nil && info.Signature == "" {
						if str, ok := arg.Value.(string); ok {
							info.Signature = sanitizeForJSON(str)
						}
					}
				case "x3": // signature parameter for other functions
					if arg.Value != nil && info.Signature == "" {
						if str, ok := arg.Value.(string); ok {
							info.Signature = sanitizeForJSON(str)
						}
					}
				}
			}
		}

		// Last resort: check the comment field which may contain extracted keys
		if info.Key == "" && finding.Comment != "" {
			// Parse key from comment like "key=b56d41f1-8905-45"
			if strings.HasPrefix(finding.Comment, "key=") {
				commentKey := strings.TrimPrefix(finding.Comment, "key=")
				// Handle case where there's also a sign
				if idx := strings.Index(commentKey, ", sign="); idx > 0 {
					signValue := commentKey[idx+7:]
					keyValue := commentKey[:idx]

					// Handle special markers
					if info.Signature == "" {
						if signValue == "(empty)" {
							info.Signature = "" // Empty string
						} else if signValue != "(unknown)" {
							info.Signature = signValue
						}
						// if signValue == "(unknown)", leave Signature as ""
					}
					if info.Key == "" {
						if keyValue == "(empty)" {
							info.Key = "" // Empty string
						} else if keyValue != "(unknown)" {
							info.Key = keyValue
						}
						// if keyValue == "(unknown)", leave Key as ""
					}
				} else if info.Key == "" {
					// Handle single key case
					if commentKey == "(empty)" {
						info.Key = "" // Empty string
					} else if commentKey != "(unknown)" {
						info.Key = commentKey
					}
					// if commentKey == "(unknown)", leave Key as ""
				}
			}
		}

		// If we couldn't extract keys through normal tracing, try searching for global strings
		// This handles cases where keys are passed through complex register setup or loaded from globals
		if (info.Key == "" || info.Signature == "") && isXXTEAFunction(info.Function) {
			globalStrings := analysis.FindStringLiteralsNearCall(img, finding.CallVA)

			// For now, just take the first two strings found
			// The analysis layer found these through the ADRP+ADD+STR pattern
			// so they should be relevant to this setXXTeaKey call
			if len(globalStrings) >= 1 && info.Key == "" {
				info.Key = globalStrings[0]
			}
			if len(globalStrings) >= 2 && info.Signature == "" {
				info.Signature = globalStrings[1]
			}
		}

		result = append(result, info)
	}

	return result
}

func runNoTUI(filePath string, showFull bool) error {
	// Load the ELF file
	img, err := elfx.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to load file: %v", err)
	}
	defer img.Close()

	// Calculate digest
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return fmt.Errorf("failed to calculate digest: %v", err)
	}
	digest := fmt.Sprintf("%x", h.Sum(nil))

	// Get file info
	stat, _ := file.Stat()
	_ = stat.Size() // size not currently used

	// Determine file kind
	fileKind := "executable"
	if img.File != nil && img.File.Type == elf.ET_DYN {
		fileKind = "library"
	}

	// Get file type description
	fileTypeCmd := exec.Command("file", "-b", filePath)
	fileTypeOutput, _ := fileTypeCmd.Output()
	fileType := strings.TrimSpace(string(fileTypeOutput))

	// Build summary
	fmt.Println("# Reverse")
	fmt.Println()
	fmt.Printf("; %s\n", filePath)
	fmt.Printf("; %s (%s)\n", pathpkg.Base(filePath), fileKind)
	fmt.Printf("; %s\n\n", digest)
	fmt.Printf("; %s\n\n", fileType)

	// Load symbols
	symbols := make([]elfx.DynSym, 0)
	// Try dynamic symbols first, then regular symbols
	if dynsyms := img.Dynsyms; len(dynsyms) > 0 {
		symbols = dynsyms
	} else if syms := img.Syms; len(syms) > 0 {
		symbols = syms
	}

	// Find entry points and analyze XXTEA
	var entryPoints []symbolInfo
	for _, sym := range symbols {
		nameLower := strings.ToLower(sym.Name)
		demangled := demangle.Filter(sym.Name)
		demangledLower := strings.ToLower(demangled)

		// Use the centralized IsEntryPoint function
		if analysis.IsEntryPoint(sym.Name, demangled, nameLower, demangledLower) {
			entryPoints = append(entryPoints, symbolInfo{
				address: sym.Addr,
				name:    sym.Name,
			})
		}
	}

	// Analyze XXTEA calls and collect all functions with findings
	allTracedFunctions := make(map[uint64]string)
	foundFromEntryPoints := false

	if len(entryPoints) > 0 {
		fmt.Println("## XXTEA Detection")
		fmt.Println()
		// Analyze from known entry points
		for _, sym := range entryPoints {
			demangled := demangle.Filter(sym.name)
			if demangled == "" {
				demangled = sym.name
			}

			findings, tracedFuncs := analyzeXXTEACalls(img, demangled, sym.address)
			if findings != "" {
				// Always output plain text in no-tui mode
				// No colors or glamour rendering
				fmt.Print(findings)
				foundFromEntryPoints = true
			}
			// Always merge traced functions, even if no findings text
			for addr, name := range tracedFuncs {
				allTracedFunctions[addr] = name
			}
		}

		// If no XXTEA found from entry points, also scan for direct calls
		if !foundFromEntryPoints {
			fmt.Println("No XXTEA calls found from entry points, scanning for direct calls...")
			fmt.Println()
		}
	}

	// Also scan for direct XXTEA calls if none were found from entry points
	if !foundFromEntryPoints {
		// Look for XXTEA functions and find their callers
		if len(entryPoints) == 0 {
			fmt.Println("## XXTEA Detection")
			fmt.Println()
			fmt.Println("No entry points found, scanning for direct XXTEA calls...")
		}
		fmt.Println()

		// Find XXTEA functions in the symbol table
		fmt.Printf("Scanning %d symbols for XXTEA functions...\n", len(symbols))
		xxteaTargets := make(map[uint64]string)
		for _, sym := range symbols {
			if isXXTEAFunction(sym.Name) {
				demangled := demangle.Filter(sym.Name)
				if demangled == "" {
					demangled = sym.Name
				}
				xxteaTargets[sym.Addr] = demangled
			}
		}

		if len(xxteaTargets) > 0 {
			fmt.Printf("Found %d XXTEA functions:\n", len(xxteaTargets))
			for addr, name := range xxteaTargets {
				fmt.Printf("  0x%x: %s\n", addr, name)
			}
			fmt.Println()

			// Scan .text section for calls to these functions
			textSec := img.Text
			fmt.Printf("Text section: VA=0x%x Size=0x%x\n\n", textSec.VA, textSec.Size)
			if textSec.Size > 0 {
				// Read the text section data
				data := img.All[textSec.Off : textSec.Off+textSec.Size]
				if len(data) > 0 {
					// Find all BL instructions
					for i := 0; i < len(data)-3; i += 4 {
						// Check for BL instruction (0x94 in high byte)
						if data[i+3] == 0x94 {
							// Calculate target address
							callAddr := textSec.VA + uint64(i)
							// Extract 26-bit signed immediate
							imm26 := uint32(data[i]) | (uint32(data[i+1]) << 8) | (uint32(data[i+2]) << 16) | ((uint32(data[i+3]) & 0x3) << 24)
							// Sign extend if negative
							var offset int64
							if imm26&0x2000000 != 0 {
								// Negative offset
								offset = int64(int32(imm26|0xfc000000)) * 4
							} else {
								// Positive offset
								offset = int64(imm26) * 4
							}
							targetAddr := uint64(int64(callAddr) + offset)

							// Check if this calls an XXTEA function
							if xxteaName, found := xxteaTargets[targetAddr]; found {
								// Found a call to XXTEA! Now trace back to analyze it
								// Start from 200 bytes before the call to capture parameter setup
								startAddr := callAddr - 0x200
								if startAddr < textSec.VA {
									startAddr = textSec.VA
								}

								// Analyze this region
								traceResult, err := analysis.TraceDisasm(img, startAddr, 300)
								if err == nil && traceResult != nil {
									// Apply XXTEA detector to enrich findings
									if len(traceResult.Findings) > 0 {
										detector := detectors.NewXXTEADetector()
										traceResult.Findings = detector.Detect(traceResult.Findings)
									}
									// Find the specific call in the trace
									for _, finding := range traceResult.Findings {
										if finding.CallVA == callAddr {
											// Format the result
											fmt.Printf("Found call at `0x%x` to\n", callAddr)
											fmt.Printf("`%s`", xxteaName)

											// Check parameters
											var keyStr, signStr string
											for _, arg := range finding.Args {
												if arg.Reg == "x1" {
													if str, ok := arg.Value.(string); ok {
														keyStr = str
													}
												} else if arg.Reg == "x3" {
													if str, ok := arg.Value.(string); ok {
														signStr = str
													}
												}
											}

											if keyStr != "" || signStr != "" {
												fmt.Printf(", with")
												if keyStr != "" {
													fmt.Printf(" key `%s`", keyStr)
												}
												if signStr != "" {
													if keyStr != "" {
														fmt.Printf(" and")
													}
													fmt.Printf(" signature `%s`", signStr)
												}
											}
											fmt.Println(".")
											fmt.Println()
											break
										}
									}
								}
							}
						}
					}
				}
			}
		} else {
			fmt.Println("No XXTEA functions found in symbol table.")
			fmt.Println()
		}
	}

	// If --full flag is set, show the assembly details
	if showFull && (len(entryPoints) > 0 || len(allTracedFunctions) > 0) {
		fmt.Println()
		fmt.Println("## Assembly Details")
		fmt.Println()

		// Create a combined map of all functions to show
		functionsToShow := make(map[uint64]string)

		// Add entry points
		for _, sym := range entryPoints {
			functionsToShow[sym.address] = sym.name
		}

		// Add all traced functions with XXTEA findings
		for addr, name := range allTracedFunctions {
			if _, exists := functionsToShow[addr]; !exists {
				functionsToShow[addr] = name
			}
		}

		// Sort addresses for consistent output
		var addresses []uint64
		for addr := range functionsToShow {
			addresses = append(addresses, addr)
		}
		sort.Slice(addresses, func(i, j int) bool {
			return addresses[i] < addresses[j]
		})

		// Show assembly for each function
		for _, addr := range addresses {
			name := functionsToShow[addr]
			demangled := demangle.Filter(name)
			if demangled == "" {
				demangled = name
			}

			funcName := stripFunctionParams(demangled)
			fmt.Printf("%x  %s:\n", addr, funcName)

			// Disassemble function
			asm := disassembleUntilReturnStatic(img, addr, 500)
			if asm != "" {
				fmt.Print(asm)
				fmt.Println()
			}
		}
	}

	return nil
}

// disassembleUntilReturnStatic is a static version of disassembleUntilReturn
func disassembleUntilReturnStatic(img *elfx.Image, startVA uint64, maxInsns int) string {
	// Use TraceDisasm for semantic analysis
	traceResult, err := analysis.TraceDisasm(img, startVA, maxInsns)
	if err != nil || traceResult == nil {
		return ""
	}

	// Apply XXTEA detector to enrich findings
	if len(traceResult.Findings) > 0 {
		detector := detectors.NewXXTEADetector()
		traceResult.Findings = detector.Detect(traceResult.Findings)
	}

	var result strings.Builder
	commentStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("242"))

	for _, annotated := range traceResult.Listing {
		// Use the unified formatAssemblyLine function without colorization for clean output
		line := formatAssemblyLine(annotated, false) // false = no colorization
		result.WriteString(line)

		// For XXTEA functions, add signature details on following lines
		if annotated.Mnemonic == "bl" && len(traceResult.Findings) > 0 {
			// Find the corresponding finding
			var finding *analysis.CallFinding
			for i := range traceResult.Findings {
				if traceResult.Findings[i].CallVA == annotated.VA {
					finding = &traceResult.Findings[i]
					break
				}
			}

			if finding != nil && isXXTEAFunction(finding.Symbol) && len(finding.Args) > 0 {
				// Format XXTEA call parameters
				lines := formatXXTEACallParams(finding.Symbol, finding.Args)

				if len(lines) > 0 {
					result.WriteString("\n")
					// Add parameter details as additional comment lines with single-space indentation
					for i, line := range lines {
						result.WriteString(" ") // Single space indentation to match assembly lines
						result.WriteString(commentStyle.Render(line))
						if i < len(lines)-1 {
							result.WriteString("\n")
						}
					}
				}
			}
		}

		result.WriteString("\n")

		// Stop at return
		if annotated.Inst.Op == arm64asm.RET {
			break
		}
	}

	return result.String()
}

func init() {
	rootCmd.PersistentFlags().StringP("cwd", "c", "", "Current working directory")
	rootCmd.PersistentFlags().StringP("data-dir", "D", "", "Custom reverse data directory")
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Debug")

	rootCmd.Flags().BoolP("help", "h", false, "Help")
	rootCmd.Flags().BoolP("no-tui", "n", false, "Show summary without TUI")
	rootCmd.Flags().BoolP("full", "f", false, "Show full assembly details (use with --no-tui)")
	rootCmd.Flags().BoolP("json", "j", false, "Output results as JSON for regression testing")
	rootCmd.Flags().String("cpuprofile", "", "Write CPU profile to file")
	rootCmd.Flags().String("memprofile", "", "Write memory profile to file")
	rootCmd.Flags().Bool("decrypt", false, "Decrypt a file using XXTEA with --key and --signature")
	rootCmd.Flags().String("key", "", "XXTEA encryption key for decryption")
	rootCmd.Flags().String("signature", "", "XXTEA signature for decryption")
	rootCmd.Flags().BoolP("write", "w", false, "Write decrypted output to file (.lua for .luac, .js for .jsc)")
	rootCmd.Flags().Bool("find-signature", false, "Find all files in directory with given signature")
	rootCmd.Flags().BoolP("recursive", "r", false, "Search recursively in subdirectories")
	rootCmd.Flags().Bool("bruteforce", false, "Brute force XXTEA key from rodata strings (use with --decrypt)")

	rootCmd.AddCommand(runCmd)
}

var rootCmd = &cobra.Command{
	Use:   "reverse [file]",
	Short: "Terminal-based reverse engineering tool",
	Long: `Reverse is a terminal-based reverse engineering tool for analyzing binary files.
It provides an interactive TUI interface for exploring and understanding executable files.`,
	Example: `
# Run in interactive mode on a file
reverse /path/to/binary

# Run with debug logging
reverse -d /path/to/binary
  `,
	Args: cobra.RangeArgs(1, 2), // 1 for normal mode, 2 for find-signature
	RunE: func(cmd *cobra.Command, args []string) error {
		// Setup CPU profiling if requested
		cpuprofile, _ := cmd.Flags().GetString("cpuprofile")
		if cpuprofile != "" {
			f, err := os.Create(cpuprofile)
			if err != nil {
				return fmt.Errorf("could not create CPU profile: %v", err)
			}
			defer f.Close()
			if err := pprof.StartCPUProfile(f); err != nil {
				return fmt.Errorf("could not start CPU profile: %v", err)
			}
			defer pprof.StopCPUProfile()
		}

		// Setup memory profiling if requested
		memprofile, _ := cmd.Flags().GetString("memprofile")
		if memprofile != "" {
			defer func() {
				f, err := os.Create(memprofile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "could not create memory profile: %v\n", err)
					return
				}
				defer f.Close()
				if err := pprof.WriteHeapProfile(f); err != nil {
					fmt.Fprintf(os.Stderr, "could not write memory profile: %v\n", err)
				}
			}()
		}

		// Check for find-signature mode first (it has different arg requirements)
		findSig, _ := cmd.Flags().GetBool("find-signature")
		if findSig {
			// Handle find-signature mode
			if len(args) < 2 {
				return fmt.Errorf("usage: reverse --find-signature <signature> <directory>")
			}
			signature := args[0]
			dirPath := args[1]
			
			// Default is recursive=true, unless explicitly set to false
			recursive := true
			if cmd.Flags().Changed("recursive") {
				recursive, _ = cmd.Flags().GetBool("recursive")
			}
			
			return runFindSignature(dirPath, signature, recursive)
		}

		// For all other modes, we need exactly one file argument
		if len(args) < 1 {
			return fmt.Errorf("usage: reverse <file>")
		}
		
		file := args[0]

		// Get absolute path
		absPath, err := pathpkg.Abs(file)
		if err != nil {
			return fmt.Errorf("failed to resolve path: %v", err)
		}

		// Check if file exists
		if _, err := os.Stat(absPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("file not found: %s", file)
			}
			return fmt.Errorf("cannot access file: %v", err)
		}

		// Check for flags
		noTUI, _ := cmd.Flags().GetBool("no-tui")
		showFull, _ := cmd.Flags().GetBool("full")
		jsonOutput, _ := cmd.Flags().GetBool("json")
		decrypt, _ := cmd.Flags().GetBool("decrypt")
		
		// --full implies --no-tui
		if showFull {
			noTUI = true
		}
		
		// Also use no-tui mode when output is being piped
		if !term.IsTerminal(os.Stdout.Fd()) {
			noTUI = true
			os.Setenv("REVERSE_NO_COLOR", "1")
		}
		
		// Disable coloring when using --no-tui to avoid garbled output
		if noTUI {
			os.Setenv("REVERSE_NO_COLOR", "1")
		}

		
		// Handle decryption mode
		if decrypt {
			key, _ := cmd.Flags().GetString("key")
			signature, _ := cmd.Flags().GetString("signature")
			writeFile, _ := cmd.Flags().GetBool("write")
			bruteforce, _ := cmd.Flags().GetBool("bruteforce")
			
			if bruteforce {
				// Extract .so file from first argument
				soPath := args[0]
				encryptedPath := ""
				if len(args) > 1 {
					encryptedPath = args[1]
				}
				return runBruteforce(soPath, encryptedPath, signature, writeFile)
			}
			
			if key == "" {
				return fmt.Errorf("--key is required when using --decrypt (unless using --bruteforce)")
			}
			
			return runDecrypt(absPath, key, signature, writeFile)
		}

		if jsonOutput {
			// JSON output mode
			return runJSON(absPath)
		}

		if noTUI {
			// Non-interactive mode
			return runNoTUI(absPath, showFull)
		}

		// Set up the TUI.
		program := tea.NewProgram(
			NewModel(absPath),
			tea.WithAltScreen(),
			tea.WithContext(cmd.Context()),
			// Mouse tracking disabled to allow native text selection
		)

		if _, err := program.Run(); err != nil {
			slog.Error("TUI run error", "error", err)
			return fmt.Errorf("TUI error: %v", err)
		}
		return nil
	},
}

// detectAndDecompress checks if the decrypted data is compressed and decompresses it
func detectAndDecompress(data []byte, filename string) ([]byte, error) {
	if len(data) < 2 {
		return data, nil
	}

	// Check for gzip magic number (0x1F 0x8B)
	if data[0] == 0x1f && data[1] == 0x8b {
		slog.Debug("Detected gzip compression", "file", filename)
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gzip reader creation failed: %v", err)
		}
		defer reader.Close()
		
		decompressed, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("gzip decompression failed: %v", err)
		}
		slog.Debug("Gzip decompression successful", "file", filename, 
			"original_size", len(data), "decompressed_size", len(decompressed))
		return decompressed, nil
	}

	// Check for ZIP archive (PK signature: 0x50 0x4B)
	if len(data) >= 4 && data[0] == 0x50 && data[1] == 0x4B {
		slog.Debug("Detected ZIP archive", "file", filename)
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("zip reader creation failed: %v", err)
		}
		
		if len(reader.File) == 0 {
			return nil, fmt.Errorf("zip archive is empty")
		}
		
		// For simplicity, extract the first file
		// In a real scenario, you might want to handle multiple files differently
		file := reader.File[0]
		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open file in zip: %v", err)
		}
		defer rc.Close()
		
		decompressed, err := io.ReadAll(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read file from zip: %v", err)
		}
		
		slog.Debug("ZIP decompression successful", "file", filename, 
			"archive_file", file.Name,
			"original_size", len(data), "decompressed_size", len(decompressed))
		return decompressed, nil
	}

	// No compression detected, return as-is
	return data, nil
}

// runDecrypt handles decryption of a file using XXTEA
func runDecrypt(filepath string, key string, signature string, writeFile bool) error {
	// Read the encrypted file
	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Decrypt the data
	var decrypted []byte
	if signature != "" {
		// Cocos2d-x files have the signature prepended to the encrypted data
		// Check if the file starts with the signature
		sigBytes := []byte(signature)
		if len(data) >= len(sigBytes) && string(data[:len(sigBytes)]) == signature {
			// Signature is at the beginning - strip it and decrypt the rest
			data = data[len(sigBytes):]
			decrypted, err = xxtea.Decrypt(data, []byte(key))
			if err != nil {
				return fmt.Errorf("decryption failed: %v", err)
			}
		} else {
			// Try the library's DecryptWithSignature which expects the signature
			// to be verified and removed after decryption
			decrypted, err = xxtea.DecryptWithSignature(data, []byte(key), sigBytes)
			if err != nil {
				return fmt.Errorf("decryption with signature failed: %v", err)
			}
		}
	} else {
		decrypted, err = xxtea.Decrypt(data, []byte(key))
		if err != nil {
			return fmt.Errorf("decryption failed: %v", err)
		}
	}

	// Check for and handle compression
	decrypted, err = detectAndDecompress(decrypted, filepath)
	if err != nil {
		return fmt.Errorf("decompression failed: %v", err)
	}

	// Handle output
	if writeFile {
		// Determine output filename based on input extension
		dir := pathpkg.Dir(filepath)
		filename := pathpkg.Base(filepath)
		ext := pathpkg.Ext(filename)
		extLower := strings.ToLower(ext)
		base := strings.TrimSuffix(filename, ext)
		
		var outputPath string
		switch extLower {
		case ".luac":
			outputPath = pathpkg.Join(dir, base + ".lua")
		case ".jsc":
			outputPath = pathpkg.Join(dir, base + ".js")
		default:
			// For other files, add -decrypted before the original extension
			outputPath = pathpkg.Join(dir, base + "-decrypted" + ext)
		}
		
		// Write to file
		err = os.WriteFile(outputPath, decrypted, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Successfully decrypted: %s\n", filepath)
		fmt.Fprintf(os.Stderr, "Output written to: %s\n", outputPath)
	} else {
		// Output to stdout
		_, err = os.Stdout.Write(decrypted)
		if err != nil {
			return fmt.Errorf("failed to write output: %v", err)
		}
	}

	return nil
}

// runFindSignature finds all files in a directory that start with the given signature
func runFindSignature(dirPath string, signature string, recursive bool) error {
	sigBytes := []byte(signature)
	sigLen := len(sigBytes)
	
	// Check if path is a directory
	info, err := os.Stat(dirPath)
	if err != nil {
		return fmt.Errorf("failed to stat path: %v", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", dirPath)
	}
	
	var foundFiles []string
	
	// Walk function
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Log error but continue walking
			fmt.Fprintf(os.Stderr, "Warning: error accessing %s: %v\n", path, err)
			return nil
		}
		
		// Skip directories
		if info.IsDir() {
			// If not recursive and not the root directory, skip
			if !recursive && path != dirPath {
				return pathpkg.SkipDir
			}
			return nil
		}
		
		// Skip files that are too small to contain the signature
		if info.Size() < int64(sigLen) {
			return nil
		}
		
		// Read the beginning of the file
		file, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: cannot open %s: %v\n", path, err)
			return nil
		}
		defer file.Close()
		
		// Read first bytes to check signature
		buf := make([]byte, sigLen)
		n, err := file.Read(buf)
		if err != nil || n < sigLen {
			return nil
		}
		
		// Check if it matches the signature
		if bytes.Equal(buf, sigBytes) {
			foundFiles = append(foundFiles, path)
		}
		
		return nil
	}
	
	// Walk the directory
	err = pathpkg.Walk(dirPath, walkFn)
	if err != nil {
		return fmt.Errorf("error walking directory: %v", err)
	}
	
	// Output results (just list files like 'find' command)
	for _, file := range foundFiles {
		fmt.Println(file)
	}
	
	return nil
}

func Execute() {
	// Don't auto-disable colors when piping - let user control with REVERSE_NO_COLOR env var
	
	// Check if --no-tui or --full flag is present, or if output is being piped
	// to bypass fang's markdown rendering
	noTUI := false
	for _, arg := range os.Args[1:] {
		if arg == "--no-tui" || arg == "-n" || arg == "--full" || arg == "-f" {
			noTUI = true
			break
		}
	}
	
	// Also bypass fang when output is being piped
	if !noTUI && !term.IsTerminal(os.Stdout.Fd()) {
		noTUI = true
	}
	
	if noTUI {
		// Use cobra directly to avoid fang's automatic markdown rendering
		if err := rootCmd.Execute(); err != nil {
			os.Exit(1)
		}
	} else {
		// Use fang for enhanced CLI experience with markdown rendering
		if err := fang.Execute(
			context.Background(),
			rootCmd,
			fang.WithNotifySignal(os.Interrupt),
		); err != nil {
			os.Exit(1)
		}
	}
}

func MaybePrependStdin(prompt string) (string, error) {
	if term.IsTerminal(os.Stdin.Fd()) {
		return prompt, nil
	}
	fi, err := os.Stdin.Stat()
	if err != nil {
		return prompt, err
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return prompt, nil
	}
	bts, err := io.ReadAll(os.Stdin)
	if err != nil {
		return prompt, err
	}
	return string(bts) + "\n\n" + prompt, nil
}

// runBruteforce attempts to find the XXTEA key by trying all strings from rodata
func runBruteforce(soPath, encryptedPath, signature string, writeToFile bool) error {
	// Open the ELF file
	file, err := elf.Open(soPath)
	if err != nil {
		return fmt.Errorf("failed to open ELF file: %v", err)
	}
	defer file.Close()

	// Find .rodata section
	rodata := file.Section(".rodata")
	if rodata == nil {
		return fmt.Errorf(".rodata section not found")
	}

	// Read rodata section
	rodataData, err := rodata.Data()
	if err != nil {
		return fmt.Errorf("failed to read .rodata: %v", err)
	}

	// Look for signature in rodata if provided
	var signatureOffset int = -1
	if signature != "" {
		sigBytes := []byte(signature)
		for i := 0; i <= len(rodataData)-len(sigBytes); i++ {
			if bytes.Equal(rodataData[i:i+len(sigBytes)], sigBytes) {
				signatureOffset = i
				fmt.Printf("Found signature %q at offset 0x%x in .rodata\n", signature, i)
				break
			}
		}
	}

	var potentialKeys []string
	
	// If we found the signature, first try strings within 1KB of it
	if signatureOffset >= 0 && encryptedPath != "" {
		fmt.Println("Searching for keys near signature...")
		
		// Define search window (1KB before and after signature)
		searchStart := max(0, signatureOffset-1024)
		searchEnd := min(len(rodataData), signatureOffset+1024)
		
		// Extract strings only in the nearby region
		var nearbyKeys []string
		start := searchStart
		for i := searchStart; i < searchEnd; i++ {
			if rodataData[i] == 0 {
				if i > start {
					str := string(rodataData[start:i])
					if utf8.ValidString(str) && isPrintableString([]byte(str)) {
						nearbyKeys = append(nearbyKeys, str)
					}
				}
				start = i + 1
			}
		}
		
		// Also try empty string as a key
		nearbyKeys = append(nearbyKeys, "")
		
		fmt.Printf("Found %d strings near signature, trying them first...\n", len(nearbyKeys))
		
		// Try nearby keys first
		data, err := os.ReadFile(encryptedPath)
		if err != nil {
			return fmt.Errorf("failed to read encrypted file: %v", err)
		}
		
		sigBytes := []byte(signature)
		for i, key := range nearbyKeys {
			if i%10 == 0 {
				fmt.Printf("Trying nearby key %d/%d...\r", i, len(nearbyKeys))
			}
			
			// Try the key and all its shifted versions
			for shift := 0; shift < len(key); shift++ {
				tryKey := key[shift:]
				
				var decrypted []byte
				
				// Try with signature
				if len(data) >= len(sigBytes) && bytes.Equal(data[:len(sigBytes)], sigBytes) {
					decrypted, err = xxtea.Decrypt(data[len(sigBytes):], []byte(tryKey))
				} else {
					decrypted, err = xxtea.DecryptWithSignature(data, []byte(tryKey), sigBytes)
				}
				
				if err == nil && isValidDecryption(decrypted, signature) {
					if shift > 0 {
						fmt.Printf("\n✓ Found key near signature (shifted by %d): %q\n", shift, tryKey)
					} else {
						fmt.Printf("\n✓ Found key near signature: %q\n", tryKey)
					}
					
					// Check for and handle compression
					decrypted, err = detectAndDecompress(decrypted, encryptedPath)
					if err != nil {
						fmt.Printf("Warning: decompression failed: %v\n", err)
					}
					
					// Output result
					outputDecrypted(decrypted, encryptedPath, writeToFile)
					return nil
				}
			}
		}
		
		fmt.Println("\nNo key found near signature, scanning entire .rodata...")
	}
	
	// Extract all null-terminated strings from rodata
	start := 0
	for i := 0; i < len(rodataData); i++ {
		if rodataData[i] == 0 {
			if i > start {
				str := string(rodataData[start:i])
				// Check if it's a valid UTF-8 string with printable characters
				if utf8.ValidString(str) && isPrintableString([]byte(str)) {
					potentialKeys = append(potentialKeys, str)
				}
			}
			start = i + 1
		}
	}
	
	// Also try empty string as a key
	potentialKeys = append(potentialKeys, "")

	fmt.Printf("Found %d total strings in .rodata\n", len(potentialKeys))

	// If encrypted file path provided, try to decrypt it
	if encryptedPath != "" {
		data, err := os.ReadFile(encryptedPath)
		if err != nil {
			return fmt.Errorf("failed to read encrypted file: %v", err)
		}

		sigBytes := []byte(signature)
		
		// Try each string as a key (including shifted versions)
		for i, key := range potentialKeys {
			if i%100 == 0 {
				fmt.Printf("Trying key %d/%d...\r", i, len(potentialKeys))
			}
			
			// Try the key and all its shifted versions
			for shift := 0; shift < len(key); shift++ {
				tryKey := key[shift:]
				
				var decrypted []byte
				var err error
				
				// Try with signature if provided
				if signature != "" {
					// Check if file starts with signature
					if len(data) >= len(sigBytes) && bytes.Equal(data[:len(sigBytes)], sigBytes) {
						// Strip signature and decrypt
						decrypted, err = xxtea.Decrypt(data[len(sigBytes):], []byte(tryKey))
					} else {
						// Try DecryptWithSignature
						decrypted, err = xxtea.DecryptWithSignature(data, []byte(tryKey), sigBytes)
					}
				} else {
					decrypted, err = xxtea.Decrypt(data, []byte(tryKey))
				}
				
				if err != nil {
					continue
				}
				
				// Check if decrypted data is valid
				if isValidDecryption(decrypted, signature) {
					if shift > 0 {
						fmt.Printf("\n✓ Found key (shifted by %d): %q\n", shift, tryKey)
					} else {
						fmt.Printf("\n✓ Found key: %q\n", tryKey)
					}
					
					// Check for and handle compression
					decrypted, err = detectAndDecompress(decrypted, encryptedPath)
					if err != nil {
						fmt.Printf("Warning: decompression failed: %v\n", err)
					}
					
					// Output result
					outputDecrypted(decrypted, encryptedPath, writeToFile)
					
					return nil
				}
			}
		}
		
		fmt.Printf("\nNo valid key found among %d strings\n", len(potentialKeys))
	} else {
		// Just list potential keys
		fmt.Println("Potential XXTEA keys from .rodata:")
		for _, s := range potentialKeys {
			// Filter to show only reasonable key candidates (4-64 chars)
			if len(s) >= 4 && len(s) <= 64 {
				fmt.Printf("  %q\n", s)
			}
		}
	}
	
	return nil
}


// isValidDecryption checks if decrypted data looks valid
func isValidDecryption(data []byte, signature string) bool {
	if len(data) == 0 {
		return false
	}
	
	// Check for signature if provided
	if signature != "" && len(data) >= len(signature) {
		if string(data[:len(signature)]) == signature {
			return true
		}
	}
	
	// Check for common file headers
	if len(data) >= 4 {
		// Lua bytecode header
		if data[0] == 0x1b && data[1] == 0x4c && data[2] == 0x75 && data[3] == 0x61 {
			return true
		}
		// JavaScript (might start with function or var)
		if utf8.Valid(data[:min(100, len(data))]) {
			start := string(data[:min(100, len(data))])
			if strings.Contains(start, "function") || strings.Contains(start, "var ") || 
			   strings.Contains(start, "const ") || strings.Contains(start, "let ") {
				return true
			}
		}
		// Gzip header
		if data[0] == 0x1f && data[1] == 0x8b {
			return true
		}
		// ZIP header
		if data[0] == 0x50 && data[1] == 0x4b {
			return true
		}
	}
	
	// Check if it's mostly printable text
	printableCount := 0
	sampleSize := min(1000, len(data))
	for i := 0; i < sampleSize; i++ {
		if data[i] >= 32 && data[i] <= 126 || data[i] == '\n' || data[i] == '\r' || data[i] == '\t' {
			printableCount++
		}
	}
	
	// If more than 80% is printable, consider it valid
	return float64(printableCount)/float64(sampleSize) > 0.8
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func outputDecrypted(decrypted []byte, encryptedPath string, writeFile bool) {
	if writeFile {
		outputPath := encryptedPath
		if pathpkg.Ext(outputPath) == ".luac" {
			outputPath = outputPath[:len(outputPath)-1] // Remove 'c'
		} else if pathpkg.Ext(outputPath) == ".jsc" {
			outputPath = outputPath[:len(outputPath)-1] // Remove 'c'
		} else {
			outputPath += ".decrypted"
		}
		
		if err := os.WriteFile(outputPath, decrypted, 0644); err != nil {
			fmt.Printf("Error: failed to write file: %v\n", err)
		} else {
			fmt.Printf("Decrypted file written to: %s\n", outputPath)
		}
	} else {
		fmt.Print(string(decrypted))
	}
}

func ResolveCwd(cmd *cobra.Command) (string, error) {
	cwd, _ := cmd.Flags().GetString("cwd")
	if cwd != "" {
		err := os.Chdir(cwd)
		if err != nil {
			return "", fmt.Errorf("failed to change directory: %v", err)
		}
		return cwd, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %v", err)
	}
	return cwd, nil
}
