package main

import (
	"os"

	"github.com/Method-Security/osintscan/cmd"
)

var version = "none"

func main() {
	osintscan := cmd.NewOsintScan(version)
	osintscan.InitRootCommand()
	osintscan.InitDiscoverCommand()
	osintscan.InitEnumerateCommand()

	if err := osintscan.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
