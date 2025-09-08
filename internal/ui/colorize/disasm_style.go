package colorize

import (
	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/styles"
)

func init() {
	// Register our custom disassembly style on package initialization
	_ = DisasmDark
}

// DisasmDark is a custom style for disassembly matching our color scheme
var DisasmDark = styles.Register(chroma.MustNewStyle("disasm-dark", chroma.StyleEntries{
	chroma.Text:           "#FFFFFF",    // Default text white
	chroma.Background:     "bg:#1e1e1e", // Dark background
	chroma.Comment:        "#FFFFFF",    // White comments
	chroma.CommentPreproc: "#FFFFFF",    // Same for preprocessor comments

	// For NASM lexer mappings
	chroma.Keyword:       "#FFFFFF", // Instructions in white
	chroma.KeywordPseudo: "#FFFFFF", // Pseudo instructions in white
	chroma.Name:          "#7C9C9D", // Generic names (registers) in teal
	chroma.NameBuiltin:   "#7C9C9D", // Builtin names (sp, lr) in teal
	chroma.NameVariable:  "#7C9C9D", // Variables/registers in teal

	// Numbers
	chroma.LiteralNumber:        "#FF5F87", // Decimal numbers in pink
	chroma.LiteralNumberHex:     "#FF5F87", // Hex numbers in pink
	chroma.LiteralNumberBin:     "#FF5F87", // Binary numbers in pink
	chroma.LiteralNumberOct:     "#FF5F87", // Octal numbers in pink
	chroma.LiteralNumberInteger: "#FF5F87", // Integer literals in pink
	chroma.LiteralNumberFloat:   "#FF5F87", // Float literals in pink

	// Labels and symbols
	chroma.NameLabel:    "#FFD700", // Labels in gold
	chroma.NameFunction: "#FFFFFF", // Instructions are tokenized as functions, use white

	// Operators and punctuation
	chroma.Operator:    "#FFFFFF", // Operators in white
	chroma.Punctuation: "#FFFFFF", // Punctuation in white

	// Strings
	chroma.String: "#EACD53", // Strings in golden (234, 205, 83)
}))
