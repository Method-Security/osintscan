# Enumerate

The `osintscan enumerate` command actively gathers deeper detail about assets found during discovery.

## Usage
```bash
osintscan enumerate [command]
```

## Available Commands

- **dns**: Active DNS enumeration, including subdomain takeover detection

## Commands

### DNS

Subcommands for active DNS enumeration.

#### Takeover

Detect DNS records that may be vulnerable to subdomain takeover.

This detects a claimable record; it does not claim it. The CNAME lookup and the HTTP request both go to the third-party provider the record dangles at, never to infrastructure the target still controls.

##### Usage
```bash
osintscan enumerate dns takeover --targets https://example.com,subdomain.example.com
```

##### Help Text
```bash
Analyze the provided targets to identify DNS records that may be vulnerable to subdomain takeover attacks, using known fingerprints and heuristics.

Usage:
  osintscan enumerate dns takeover [flags]

Flags:
      --fingerprints-file string   Path to the JSON file containing service fingerprints for takeover detection
  -h, --help                       help for takeover
      --successful-only            Show only confirmed successful takeovers in the results
      --target-files strings       File paths containing lists of targets to analyze for takeover vulnerabilities
      --targets strings            A list of URLs or domains to analyze for takeover vulnerabilities
      --timeout int                Timeout in seconds for each takeover check request (default 180)
      --verify-tls                 Verify TLS certificates when making HTTPS requests during takeover analysis

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
