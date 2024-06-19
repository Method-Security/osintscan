// Package cmd implements the CobraCLI commands for the methodaws CLI. Subcommands for the CLI should all live within
// this package. Logic should be delegated to internal packages and functions to keep the CLI commands clean and
// focused on CLI I/O.
package cmd

import (
	"errors"
	"strings"
	"time"

	"github.com/Method-Security/osintscan/internal/config"
	"github.com/Method-Security/pkg/signal"
	"github.com/Method-Security/pkg/writer"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// OsintScan is the main struct for the CLI. It contains the version, output configuration, output signal, and root flags
// for the CLI. It also contains all commands and subcommands for the CLI. The output signal is used to write the output
// of the command to the desired output format after the execution of the invoked command's Run function.
type OsintScan struct {
	Version      string
	OutputConfig writer.OutputConfig
	OutputSignal signal.Signal
	RootFlags    config.RootFlags
	RootCmd      *cobra.Command
	VersionCmd   *cobra.Command
	DNSCmd       *cobra.Command
	ShodanCmd    *cobra.Command
}

// NewOsintScan creates a new OsintScan struct with the given version. It initializes the root command and all subcommands
// for the CLI. We pass the version command in here from the main.go file, where we set the version string during the
// build process.
func NewOsintScan(version string) *OsintScan {
	osintScan := OsintScan{
		Version: version,
		RootFlags: config.RootFlags{
			Quiet:   false,
			Verbose: false,
		},
		OutputConfig: writer.NewOutputConfig(nil, writer.NewFormat(writer.SIGNAL)),
		OutputSignal: signal.NewSignal(nil, datetime.DateTime(time.Now()), nil, 0, nil),
	}
	return &osintScan
}

// InitRootCommand initializes the root command for the osintscan CLI. This function initializes the root command with a
// PersistentPreRunE function that is responsible for setting the output configuration properly, as well as a
// PersistentPostRunE function that is responsible for writing the output signal to the desired output format.
func (a *OsintScan) InitRootCommand() {
	var outputFormat string
	var outputFile string
	a.RootCmd = &cobra.Command{
		Use:   "osintscan",
		Short: "Perform an OSINT scan on target(s)",
		Long:  `Perform an OSINT scan on target(s)`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			format, err := validateOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			var outputFilePointer *string
			if outputFile != "" {
				outputFilePointer = &outputFile
			} else {
				outputFilePointer = nil
			}
			a.OutputConfig = writer.NewOutputConfig(outputFilePointer, format)
			cmd.SetContext(svc1log.WithLogger(cmd.Context(), config.InitializeLogging(cmd, &a.RootFlags)))
			return nil
		},
	}

	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Quiet, "quiet", "q", false, "Suppress output")
	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Verbose, "verbose", "v", false, "Verbose output")
	a.RootCmd.PersistentFlags().StringVarP(&outputFile, "output-file", "f", "", "Path to output file. If blank, will output to STDOUT")
	a.RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "signal", "Output format (signal, json, yaml). Default value is signal")

	a.VersionCmd = &cobra.Command{
		Use:   "version",
		Short: "Prints the version number of osintscan",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(a.Version)
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
	}
	a.RootCmd.AddCommand(a.VersionCmd)
}

func validateOutputFormat(output string) (writer.Format, error) {
	var format writer.FormatValue
	switch strings.ToLower(output) {
	case "json":
		format = writer.JSON
	case "yaml":
		format = writer.YAML
	case "signal":
		format = writer.SIGNAL
	default:
		return writer.Format{}, errors.New("invalid output format. Valid formats are: json, yaml, signal")
	}
	return writer.NewFormat(format), nil
}
