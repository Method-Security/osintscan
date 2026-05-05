# Enumerate

The `osintscan enumerate` command performs active enumeration techniques to gather detailed information from discovered targets.

## Usage
```bash
osintscan enumerate [command]
```

## Available Commands

- **dns**: Active DNS enumeration techniques including zone transfers

## Commands

### DNS

Subcommands for active DNS enumeration.

#### Zone Transfer

Attempt DNS zone transfers (AXFR) to enumerate all DNS records if the server allows it.

##### Usage
```bash
osintscan enumerate dns zone-transfer --zones example.com
osintscan enumerate dns zone-transfer --zones example.com --target-nameservers 10.0.0.1
```

##### Help Text
```bash
Attempt DNS zone transfers (AXFR) for the specified zones to enumerate all DNS records, if the server allows it. This can reveal all subdomains and records

Usage:
  osintscan enumerate dns zone-transfer [flags]

Flags:
      --dns-resolvers strings       DNS resolvers for NS lookups (e.g. 10.0.0.1). Uses system resolver if not set.
  -h, --help                        help for zone-transfer
      --target-nameservers strings  Nameserver IPs to attempt AXFR against directly, bypassing NS record lookup (e.g. 10.0.0.1)
      --timeout int                 Timeout in seconds for each zone transfer request (default 30)
      --zones strings               Zone FQDNs to test for unauthorized zone transfers (e.g. example.com)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
