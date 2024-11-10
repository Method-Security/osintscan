package cmd

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"

	"github.com/Method-Security/osintscan/internal/dns"
	"github.com/spf13/cobra"
)

// InitDNSCommand initializes the DNS command for the osintscan CLI that deals with gathering DNS records, certs, and subdomains.
func (a *OsintScan) InitDNSCommand() {
	a.DNSCmd = &cobra.Command{
		Use:   "dns",
		Short: "Scan and gather intel on DNS services",
		Long:  `Scan and gather intel on DNS services`,
	}

	recordCmd := &cobra.Command{
		Use:   "records",
		Short: "Gather DNS records for a given domain",
		Long:  `Gather DNS records for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := dns.GetDomainDNSRecords(cmd.Context(), domain, true)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	recordCmd.Flags().String("domain", "", "Domain to get DNS records for")

	certsCmd := &cobra.Command{
		Use:   "certs",
		Short: "Gather DNS certs for a given domain",
		Long:  `Gather DNS certs for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := dns.GetDomainCerts(cmd.Context(), domain)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	certsCmd.Flags().String("domain", "", "Domain to get DNS certs for")

	passiveSubEnumCmd := &cobra.Command{
		Use:   "subenum",
		Short: "Passively enumerate subdomains for a given domain",
		Long:  `Passively enumerate subdomains for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := dns.GetDomainSubdomains(cmd.Context(), domain)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	passiveSubEnumCmd.Flags().String("domain", "", "Domain to get subdomains for")

	activeSubEnumCmd := &cobra.Command{
		Use:   "brutesubenum",
		Short: "Actively enumerate subdomains for a given domain using dictionary-based brute force",
		Long:  `Actively enumerate subdomains for a given domain using dictionary-based brute force`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			words, err := cmd.Flags().GetStringSlice("words")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			filePath, err := cmd.Flags().GetString("wordlist")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			fileWords, err := getTargetsFromFiles([]string{filePath})
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			threads, err := cmd.Flags().GetInt("threads")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxRecursiveDepth, err := cmd.Flags().GetInt("max-recursive-depth")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			allWords := append(words, fileWords...)

			if len(allWords) == 0 {
				a.OutputSignal.AddError(errors.New("please provide a comma-separated list of words or a path to a wordlist file"))
				return
			}

			report, err := dns.BruteEnumDomainSubdomains(cmd.Context(), domain, allWords, threads, maxRecursiveDepth)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	activeSubEnumCmd.Flags().String("domain", "", "Domain to get subdomains for")
	activeSubEnumCmd.Flags().StringSlice("words", []string{}, "Comma-separated wordlist")
	activeSubEnumCmd.Flags().String("wordlist", "", "Path to local file containing wordlist")
	activeSubEnumCmd.Flags().Int("threads", 10, "Number of threads used for concurrent DNS lookup of words in wordlist")
	activeSubEnumCmd.Flags().Int("max-recursive-depth", 1, "Maximum number of times to recursively check wordlist against domains found in previous iteration")

	takeoverCmd := &cobra.Command{
		Use:   "takeover",
		Short: "Detect domain takeovers given targets",
		Long:  `Detect domain takeovers given targets`,
		Run: func(cmd *cobra.Command, args []string) {
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			filePaths, err := cmd.Flags().GetStringSlice("files")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			fileTargets, err := getTargetsFromFiles(filePaths)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			allTargets := append(targets, fileTargets...)

			if len(allTargets) == 0 {
				a.OutputSignal.AddError(errors.New("no targets specified"))
				return
			}

			fingerprintsPath, err := cmd.Flags().GetString("fingerprints")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			setHTTP, err := cmd.Flags().GetBool("https")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := dns.DetectDomainTakeover(allTargets, fingerprintsPath, setHTTP, timeout)
			if err != nil {
				a.OutputSignal.AddError(err)
			}
			a.OutputSignal.Content = report
		},
	}

	takeoverCmd.Flags().StringSlice("targets", []string{}, "URL targets to analyze")
	takeoverCmd.Flags().String("fingerprints", "configs/fingerprints.json", "Path to fingerprints file")
	takeoverCmd.Flags().StringSlice("files", []string{}, "Paths to files containing the list of targets")
	takeoverCmd.Flags().Bool("https", false, "Only check sites with secure SSL")
	takeoverCmd.Flags().Int("timeout", 10, "Request timeout in seconds")

	a.DNSCmd.AddCommand(recordCmd)
	a.DNSCmd.AddCommand(certsCmd)
	a.DNSCmd.AddCommand(passiveSubEnumCmd)
	a.DNSCmd.AddCommand(activeSubEnumCmd)
	a.DNSCmd.AddCommand(takeoverCmd)
	a.RootCmd.AddCommand(a.DNSCmd)
}

func getTargetsFromFiles(paths []string) ([]string, error) {
	targets := []string{}
	for _, path := range paths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		file, err := os.Open(absPath)
		if err != nil {
			return nil, err
		}
		var lines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		targets = append(targets, lines...)
		err = file.Close()
		if err != nil {
			return nil, err
		}
	}
	return targets, nil
}
