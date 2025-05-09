package cmd

import (
	"context"
	"net"
	"fmt"
	"errors"

	subnetfern "github.com/Method-Security/osintscan/generated/go/subnet"
	"github.com/spf13/cobra"
	"github.com/Method-Security/osintscan/internal/subnet"
)

// InitSubnetCommand initializes the 'subnet' command and its subcommands.
func (a *OsintScan) InitSubnetCommand() {
	a.SubnetCmd = &cobra.Command{
		Use:   "subnet",
		Short: "OSINT scanning for IP subnets",
		Long:  "Perform open-source intelligence gathering on a given IPv4 subnet (CIDR format).",
	}

	researchCmd := &cobra.Command{
		Use:   "research",
		Short: "Research all IPs in a subnet",
		Long:  `Enumerate all IP addresses in the given IPv4 subnet and gather OSINT data (PTR records, ASN info, WHOIS ownership).`,
		Run: func(cmd *cobra.Command, args []string) {
			cidr, _ := cmd.Flags().GetString("subnet")
			resolverIP, _ := cmd.Flags().GetString("dns-resolver")
			tableMode, _ := cmd.Flags().GetBool("table")

			if cidr == "" {
				a.OutputSignal.AddError(errors.New("Missing Subnet"))
				return
			}

			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			if resolverIP != "" && net.ParseIP(resolverIP) == nil {
	                 	a.OutputSignal.AddError(errors.New("Invalid DNS resolver IP"))
				return
	                }

			ctx := context.Background()
			result, err := subnet.ResearchSubnet(ctx, network, resolverIP)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			if tableMode {
				printTable(result)
				return
			}
			
			a.OutputSignal.Content = result
			
			return
		},
	}

	researchCmd.Flags().StringP("subnet", "s", "", "IPv4 subnet in CIDR notation (e.g. 192.0.2.0/24)")
	researchCmd.Flags().String("dns-resolver", "", "Optional custom DNS resolver IP (e.g. 8.8.8.8)")
	researchCmd.Flags().BoolP("table", "t", false, "Display results as a table (instead of other formats)")
	researchCmd.MarkFlagRequired("subnet")

	a.SubnetCmd.AddCommand(researchCmd)
	a.RootCmd.AddCommand(a.SubnetCmd)
}

func printTable(report *subnetfern.SubnetResearchOutput) {
	if report == nil {
		fmt.Println("No data to display.")
		return
	}

	fmt.Printf("Subnet: %s\n", report.Subnet)
	fmt.Println("-------------------------------------------------------------------------------------------------------")
	fmt.Printf("%-10s  %-35s  %-10s  %-18s  %-25s\n", "IP", "PTR", "ASN", "Org", "Email")
	fmt.Println("-------------------------------------------------------------------------------------------------------")

	for _, host := range report.Hosts {
		ip := host.Ip
		ptr := truncate(clean(host.Ptr), 35)
		asn := ""
		if host.Asn != nil {
			asn = fmt.Sprintf("%d", host.Asn.Number)
		}
		org := truncate(clean(host.Whois.Organization), 18)
		email := truncate(clean(host.Whois.ContactEmail), 25)

		fmt.Printf("%-10s  %-35s  %-10s  %-18s  %-25s\n", ip, ptr, asn, org, email)
	}
}

func clean(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max-1] + "…"
	}
	return s
}

