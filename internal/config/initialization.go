package config

import (
	"io"

	"github.com/palantir/witchcraft-go-logging/wlog"
	wlogtmpl "github.com/palantir/witchcraft-go-logging/wlog-tmpl"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// InitializeLogging initializes the logging configuration for the CLI. It sets the log level based on the verbose and
// quiet flags provided by the user. If the quiet flag is set, the logger is set to discard all logs. If the verbose flag
// is set, the log level is set to debug. Otherwise, the log level is set to info. The logger is then returned for use
// by caller.
// We are using Palantir's Witchcraft logging library to structure our logging output.
func InitializeLogging(cmd *cobra.Command, rootFlags *RootFlags) svc1log.Logger {
	logLevel := wlog.InfoLevel
	if rootFlags.Verbose {
		logLevel = wlog.DebugLevel
	}

	if rootFlags.Quiet {
		wlog.SetDefaultLoggerProvider(wlog.NewNoopLoggerProvider())
		return svc1log.New(io.Discard, logLevel)
	}
	wlog.SetDefaultLoggerProvider(wlogtmpl.LoggerProvider(nil))
	return svc1log.New(cmd.OutOrStderr(), logLevel)
}
