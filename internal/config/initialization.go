package config

import (
	"io"

	"github.com/palantir/witchcraft-go-logging/wlog"
	wlogtmpl "github.com/palantir/witchcraft-go-logging/wlog-tmpl"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

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
