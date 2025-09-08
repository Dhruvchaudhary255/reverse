package cmd

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run [file] [analysis...]",
	Short: "Run a single non-interactive analysis",
	Long: `Run a single analysis in non-interactive mode and exit.
The analysis parameters can be provided as arguments.`,
	Example: `
# Run a simple analysis
reverse run /path/to/binary --find-xxtea

# Run with quiet mode (no spinner)
reverse run -q /path/to/binary --dump-strings
  `,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		quiet, _ := cmd.Flags().GetBool("quiet")

		filepath := args[0]
		analysisArgs := args[1:]

		if quiet {
			slog.Info("Running analysis", "file", filepath, "args", analysisArgs)
		}

		// For now, just print what we would analyze
		fmt.Printf("Analyzing: %s\n", filepath)
		if len(analysisArgs) > 0 {
			fmt.Printf("Analysis options: %s\n", strings.Join(analysisArgs, " "))
		}

		return nil
	},
}

func init() {
	runCmd.Flags().BoolP("quiet", "q", false, "Hide spinner")
}
