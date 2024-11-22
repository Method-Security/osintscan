package cmd

import (
	"bufio"
	"context"
	"errors"
	"github.com/Method-Security/osintscan/internal/util"
	"os"
	"path/filepath"
	"time"

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
			report, err := dns.GetDomainDNSRecords(cmd.Context(), domain)
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

	passiveSubenumCmd := &cobra.Command{
		Use:   "enum",
		Short: "Enumerate subdomains for a given domain",
		Long:  `Enumerate subdomains for a given domain`,
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

	passiveSubenumCmd.Flags().String("domain", "", "Domain to get subdomains for")

	bruteForceSubenumCmd := &cobra.Command{
		Use:   "brutesubenum",
		Short: "Brute-force enumerate subdomains for a given domain",
		Long:  `Brute-force enumerate subdomains for a given domain`,
		Run: func(cmd *cobra.Command, args []string) {
			domain, err := cmd.Flags().GetString("domain")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			wordlistArg, err := cmd.Flags().GetString("wordlist")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			wordlistFile, err := cmd.Flags().GetString("wordlist-file")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			numWorkers, err := cmd.Flags().GetInt("workers")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeoutSeconds, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxEnumerationMinutes, err := cmd.Flags().GetInt("max-enum-minutes")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxRecursionDepth, err := cmd.Flags().GetInt("max-recursion-depth")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			ctx, _ := context.WithDeadline(cmd.Context(), time.Now().Add(time.Duration(maxEnumerationMinutes)*time.Minute))

			// Validate mutual exclusivity of wordlist and wordlist-file
			if wordlistArg != "" && wordlistFile != "" || wordlistArg == "" && wordlistFile == "" {
				err := errors.New("exactly one of --wordlist or --wordlist-file must be specified")
				a.OutputSignal.AddError(err)
				return
			}
			var wordlist []string
			if wordlistArg != "" {
				wordlist = util.ParseCommaSeparated(wordlistArg)
			} else {
				wordlist, err = util.LoadWordlist(wordlistFile)
				if err != nil {
					errorMessage := err.Error()
					a.OutputSignal.ErrorMessage = &errorMessage
					a.OutputSignal.Status = 1
				}
			}

			report, err := dns.GetBruteForceSubdomains(ctx, domain, &wordlist, numWorkers, time.Duration(timeoutSeconds)*time.Second, maxRecursionDepth)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	bruteForceSubenumCmd.Flags().String("domain", "", "Number of threads to dedicate to enumeration")
	bruteForceSubenumCmd.Flags().String("wordlist", "", "Comma-separated string containing a wordlist for enumeration")
	bruteForceSubenumCmd.Flags().String("wordlist-file", "", "File containing a wordlist for enumeration")
	bruteForceSubenumCmd.Flags().Int("workers", 10, "Number of workers to dedicate to enumeration")
	bruteForceSubenumCmd.Flags().Int("timeout", 30, "Request timeout in seconds")
	bruteForceSubenumCmd.Flags().Int("max-recursion-depth", 3, "Number of threads to dedicate to enumeration")
	bruteForceSubenumCmd.Flags().Int("max-enum-minutes", 10, "Maximum amount of time in mins to wait for enumeration")

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
	a.DNSCmd.AddCommand(bruteForceSubenumCmd)
	a.DNSCmd.AddCommand(passiveSubenumCmd)
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
		err = file.Close()
		if err != nil {
			return nil, err
		}
		var lines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		targets = append(targets, lines...)
	}
	return targets, nil
}
