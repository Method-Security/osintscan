package cmd

import (
	"errors"

	saasFern "github.com/Method-Security/osintscan/generated/go/saas"
	saasdiscovery "github.com/Method-Security/osintscan/internal/saas/discovery"
	"github.com/spf13/cobra"
)

// InitSaasCommand initializes the Saas command for the osintscan CLI that deals with querying Saas for information.
func (a *OsintScan) InitSaasCommand() {
	a.SaasCmd = &cobra.Command{
		Use:   "saas",
		Short: "Gather SaaS information given an organization name",
		Long:  `Gather SaaS information given an organization name`,
	}

	discoveryCmd := &cobra.Command{
		Use:   "discovery",
		Short: "Find SaaS domain slugs associated with an organization name",
		Long:  `Find SaaS domain slugs associated with an organization name`,
		Run: func(cmd *cobra.Command, args []string) {
			// Get the Orgs
			orgs, err := cmd.Flags().GetStringSlice("orgs")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get the SaaS and SSO fingerprints from the files
			saasFilePaths, err := cmd.Flags().GetStringSlice("saasfilepaths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ssoFilePaths, err := cmd.Flags().GetStringSlice("ssofilepaths")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			saasFingerprints := saasdiscovery.UnmarshalFingerprints(saasFilePaths)
			ssoFingerprints := saasdiscovery.UnmarshalFingerprints(ssoFilePaths)

			if len(saasFingerprints.Fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no SaaS fingerprints found"))
				return
			}
			if len(ssoFingerprints.Fingerprints) == 0 {
				a.OutputSignal.AddError(errors.New("no SSO fingerprints found"))
				return
			}

			// Config
			saasCompanies, err := cmd.Flags().GetStringSlice("saascompanies")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			ssoCompanies, err := cmd.Flags().GetStringSlice("ssocompanies")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			httpsOnly, err := cmd.Flags().GetBool("httpsonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			skipTLS, err := cmd.Flags().GetBool("skiptls")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			browserPath, err := cmd.Flags().GetString("browserpath")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			config := saasDiscoveryConfig(orgs, saasFilePaths, ssoFilePaths, saasCompanies, ssoCompanies, timeout, httpsOnly, successfulOnly, skipTLS, browserPath)

			// Generate the report
			report, err := saasdiscovery.Discovery(cmd.Context(), saasFingerprints, ssoFingerprints, config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	discoveryCmd.Flags().StringSlice("orgs", []string{}, "The organization names to use for discovery")
	discoveryCmd.Flags().StringSlice("saasfilepaths", []string{"configs/saas/saas_fingerprints.json"}, "Files containing SaaS application fingerprints")
	discoveryCmd.Flags().StringSlice("ssofilepaths", []string{"configs/saas/sso_fingerprints.json"}, "Files containing SSO application fingerprints")
	discoveryCmd.Flags().StringSlice("saascompanies", []string{}, "The specific SaaS companies to use for discovery (Must be present in the SaaS fingerprints file)")
	discoveryCmd.Flags().StringSlice("ssocompanies", []string{}, "The specific SSO companies to use for discovery (Must be present in the SSO fingerprints file)")
	discoveryCmd.Flags().Int("timeout", 30, "The timeout for the request in seconds")
	discoveryCmd.Flags().Bool("httpsonly", true, "Only use HTTPS for the requests")
	discoveryCmd.Flags().Bool("successfulonly", false, "Only return results where the finding is a success")
	discoveryCmd.Flags().Bool("skiptls", false, "Skip TLS verification")
	discoveryCmd.Flags().String("browserpath", "", "The path to the browser to use for the requests")

	_ = discoveryCmd.MarkFlagRequired("orgs")

	a.SaasCmd.AddCommand(discoveryCmd)
	a.RootCmd.AddCommand(a.SaasCmd)
}

func saasDiscoveryConfig(orgs []string, saasFilePaths []string, ssoFilePaths []string, saasCompanies []string, ssoCompanies []string, timeout int, httpsOnly bool, successfulOnly bool, skipTLS bool, browserPath string) saasFern.SaasDiscoveryConfig {
	config := saasFern.SaasDiscoveryConfig{
		Orgs:           orgs,
		SaasFilePaths:  saasFilePaths,
		SsoFilePaths:   ssoFilePaths,
		Timeout:        timeout,
		HttpsOnly:      httpsOnly,
		SuccessfulOnly: successfulOnly,
		SkipTls:        skipTLS,
	}
	if len(browserPath) > 0 {
		config.BrowserPath = &browserPath
	}
	if len(saasCompanies) > 0 {
		config.SaasCompanies = saasCompanies
	}
	if len(ssoCompanies) > 0 {
		config.SsoCompanies = ssoCompanies
	}
	return config
}
