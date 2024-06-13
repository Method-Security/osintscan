package cmd

import (
	"fmt"
	"os"

	"github.com/Method-Security/osintscan/internal/shodan"
	"github.com/spf13/cobra"
)

func (a *OsintScan) InitShodanCommand() {
	a.ShodanCmd = &cobra.Command{
		Use:   "shodan",
		Short: "Query Shodan for information",
		Long:  `Query Shodan for information`,
	}

	hostnameCmd := &cobra.Command{
		Use:   "hostname",
		Short: "Query Shodan for a hostname string search",
		Long:  `Query Shodan for a hostname string search`,
		Run: func(cmd *cobra.Command, args []string) {
			var apiKey string
			var err error
			if os.Getenv("SHODAN_API_KEY") != "" {
				apiKey = os.Getenv("SHODAN_API_KEY")
			} else {
				apiKeyFlag, err := cmd.Flags().GetString("apikey")
				if err != nil {
					errorMessage := err.Error()
					a.OutputSignal.ErrorMessage = &errorMessage
					a.OutputSignal.Status = 1
					return
				}
				apiKey = apiKeyFlag
			}
			if apiKey == "" {
				err = fmt.Errorf("either SHODAN_API_KEY environment variable or --apikey must be set")
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			query, err := cmd.Flags().GetString("query")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			hostname, err := cmd.Flags().GetString("hostname")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := shodan.QueryShodanHostStrictHostnameMatch(cmd.Context(), apiKey, query, hostname)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	hostnameCmd.Flags().String("apikey", "", "Shodan API Key (reads from SHODAN_API_KEY env by default)")
	hostnameCmd.Flags().String("query", "", "Query string to search Shodan hostname:{} for")
	hostnameCmd.Flags().String("hostname", "", "The hostname suffix you want to ensure the Shodan record contains")

	a.ShodanCmd.AddCommand(hostnameCmd)
	a.RootCmd.AddCommand(a.ShodanCmd)
}
