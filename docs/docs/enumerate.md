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
osintscan enumerate dns zonetransfer --domains example.com
osintscan enumerate dns zonetransfer --nameserver ns1.example.com
```

##### Help Text
```bash
Attempt DNS zone transfers (AXFR) for the specified domains to enumerate all DNS records, if the server allows it. This can reveal all subdomains and records

Usage:
  osintscan enumerate dns zonetransfer [domain...] [flags]

Flags:
      --dns-resolvers strings   Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53) (default [1.1.1.1:53])
      --domains strings         A list of domain names to attempt zone transfers on
  -h, --help                    help for zonetransfer
      --nameserver string       Specific nameserver to test zone transfers against (e.g., ns1.example.com or 192.168.1.10)
      --timeout int             Timeout in seconds for each zone transfer request (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
