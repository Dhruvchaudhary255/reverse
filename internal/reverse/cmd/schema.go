package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra"
)

// ReverseConfig represents configuration for the reverse tool
type ReverseConfig struct {
	Debug       bool   `json:"debug" jsonschema:"title=Debug,description=Enable debug logging"`
	DataDir     string `json:"dataDir" jsonschema:"title=Data Directory,description=Directory for storing reverse data"`
	ProfilePath string `json:"profilePath" jsonschema:"title=Profile Path,description=Path for CPU profile output"`
}

var schemaCmd = &cobra.Command{
	Use:    "schema",
	Short:  "Generate JSON schema for configuration",
	Long:   "Generate JSON schema for the reverse configuration",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		reflector := new(jsonschema.Reflector)
		bts, err := json.MarshalIndent(reflector.Reflect(&ReverseConfig{}), "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal schema: %w", err)
		}
		fmt.Println(string(bts))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(schemaCmd)
}
