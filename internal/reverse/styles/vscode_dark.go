package styles

import (
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/ansi"
)

// VS Code Dark theme colors
const (
	// Normal text
	VSCodeForeground = "#D4D4D4" // Default light gray text

	// Links and file paths
	VSCodeLink = "#4FC1FF" // Light blue for links

	// Inline code
	VSCodeInlineCode = "#EACD53" // Golden color (234, 205, 83) for inline code

	// Functions and keywords
	VSCodeFunction = "#DCDCAA" // Yellow/gold for functions

	// Comments
	VSCodeComment = "#6A9955" // Green for comments

	// Headings
	VSCodeHeading = "#569CD6" // Blue for headings

	// Background colors
	VSCodeCodeBlockBg = "#1E1E1E" // Slightly darker for code blocks
	VSCodeBackground  = "#1E1E1E" // Editor background

	// Additional colors
	VSCodeString     = "#CE9178" // String literals
	VSCodeKeyword    = "#569CD6" // Keywords (blue)
	VSCodeVariable   = "#9CDCFE" // Variables (light blue)
	VSCodeNumber     = "#B5CEA8" // Numbers (light green)
	VSCodeOperator   = "#D4D4D4" // Operators (default text)
	VSCodeSelection  = "#264F78" // Selection background
	VSCodeLineNumber = "#858585" // Line numbers (gray)
)

// GetVSCodeDarkStyle returns a glamour style configuration matching VS Code dark theme
func GetVSCodeDarkStyle() ansi.StyleConfig {
	return ansi.StyleConfig{
		Document: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: stringPtr(VSCodeForeground),
			},
		},
		BlockQuote: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:  stringPtr(VSCodeComment),
				Italic: boolPtr(true),
			},
			Indent:      uintPtr(1),
			IndentToken: stringPtr("│ "),
		},
		List: ansi.StyleList{
			LevelIndent: 2,
		},
		Heading: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				BlockSuffix: "\n",
				Color:       stringPtr(VSCodeHeading),
				Bold:        boolPtr(true),
			},
		},
		H1: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "# ",
				Color:  stringPtr(VSCodeHeading),
				Bold:   boolPtr(true),
			},
		},
		H2: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "## ",
				Color:  stringPtr(VSCodeHeading),
				Bold:   boolPtr(true),
			},
		},
		H3: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "### ",
				Color:  stringPtr(VSCodeHeading),
				Bold:   boolPtr(true),
			},
		},
		H4: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "#### ",
				Color:  stringPtr(VSCodeHeading),
			},
		},
		H5: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "##### ",
				Color:  stringPtr(VSCodeHeading),
			},
		},
		H6: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Prefix: "###### ",
				Color:  stringPtr(VSCodeHeading),
			},
		},
		Strikethrough: ansi.StylePrimitive{
			CrossedOut: boolPtr(true),
		},
		Emph: ansi.StylePrimitive{
			Italic: boolPtr(true),
		},
		Strong: ansi.StylePrimitive{
			Bold:  boolPtr(true),
			Color: stringPtr(VSCodeForeground),
		},
		HorizontalRule: ansi.StylePrimitive{
			Color:  stringPtr(VSCodeLineNumber),
			Format: "\n────────────────────────────────────────\n",
		},
		Item: ansi.StylePrimitive{
			BlockPrefix: "• ",
		},
		Enumeration: ansi.StylePrimitive{
			BlockPrefix: ". ",
		},
		Task: ansi.StyleTask{
			StylePrimitive: ansi.StylePrimitive{},
			Ticked:         "[✓] ",
			Unticked:       "[ ] ",
		},
		Link: ansi.StylePrimitive{
			Color:     stringPtr(VSCodeLink),
			Underline: boolPtr(true),
		},
		LinkText: ansi.StylePrimitive{
			Color: stringPtr(VSCodeLink),
		},
		Image: ansi.StylePrimitive{
			Color:     stringPtr(VSCodeLink),
			Underline: boolPtr(true),
		},
		ImageText: ansi.StylePrimitive{
			Color:  stringPtr(VSCodeLink),
			Format: "Image: {{.text}} →",
		},
		Code: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: stringPtr(VSCodeInlineCode),
			},
		},
		CodeBlock: ansi.StyleCodeBlock{
			StyleBlock: ansi.StyleBlock{
				StylePrimitive: ansi.StylePrimitive{
					Color: stringPtr(VSCodeForeground),
				},
				Margin: uintPtr(1),
			},
		},
		Table: ansi.StyleTable{
			StyleBlock: ansi.StyleBlock{
				StylePrimitive: ansi.StylePrimitive{
					Color: stringPtr(VSCodeForeground),
				},
			},
		},
		Text: ansi.StylePrimitive{
			Color: stringPtr(VSCodeForeground),
		},
	}
}

// GetVSCodeDarkRenderer returns a glamour TermRenderer with VS Code dark theme
func GetVSCodeDarkRenderer(width int) *glamour.TermRenderer {
	r, _ := glamour.NewTermRenderer(
		glamour.WithStyles(GetVSCodeDarkStyle()),
		glamour.WithWordWrap(width),
	)
	return r
}
