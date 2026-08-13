package main

import (
	"flag"
	"os"

	"github.com/Method-Security/osintscan/cmd"
)

var version = "none"

func main() {
	flag.Parse()

	osintscan := cmd.NewOsintScan(version)
	osintscan.InitRootCommand()
	osintscan.InitDiscoverCommand()
	osintscan.InitPentestCommand()

	if err := osintscan.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
