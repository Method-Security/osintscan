# DNS and Network Intelligence

The osintscan toolkit provides comprehensive DNS and network intelligence capabilities across discovery, enumeration, and penetration testing phases. This includes DNS records analysis, ASN information gathering, CDN detection, IP address investigation, subdomain discovery, zone transfers, and takeover detection.

## ASN Discovery

The `osintscan discover asn` command retrieves detailed ASN information using BGPView's API.

### Usage

```bash
osintscan discover asn --asn AS23028
```

### Help Text

```bash
Discover information about ASN, including ASN description, CIDRs, country, and other metadata

Usage:
  osintscan discover asn [flags]

Flags:
      --asn string      The ASN number to lookup (e.g., AS23028 or 23028)
  -h, --help           help for asn
      --timeout int    The timeout in seconds for the ASN lookup (default 120)
```

## CDN Discovery

The `osintscan discover cdn` command checks if IP addresses or domains belong to known CDN providers.

### Usage

```bash
osintscan discover cdn --domain example.com
```

### Help Text

```bash
Check if an IP address belongs to a known CDN provider

Usage:
  osintscan discover cdn [flags]

Flags:
      --domain string                The domain name to check against CDN provider ranges
      --dns-resolvers stringSlice    Custom DNS resolver/servers to use (default [1.1.1.1:53])
      --fingerprints-file string     Path to CDN fingerprints file (default "/opt/method/osintscan/var/conf/discover/cdn/providers.json")
  -h, --help                        help for cdn
      --ip-addresses stringSlice    IP addresses to check against CDN provider ranges
```

## DNS Discovery

The `osintscan discover dns` family of commands provides comprehensive DNS intelligence gathering capabilities.

### Usage

```bash
osintscan discover dns [command]
```

## Commands

### Certs

The `osintscan discover dns certs` command returns information about the certificate chains that are being leveraged by the specified domain.

#### Usage

```bash
osintscan discover dns certs --domain example.com
```

#### Help Text

```bash
$ osintscan discover dns certs --help
Fetch and display SSL/TLS certificates associated with the specified domain, including certificate chains and metadata.

Usage:
  osintscan discover dns certs [flags]

Flags:
      --domain string   The domain name to retrieve SSL/TLS certificates for
  -h, --help            help for certs

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Records

#### Usage

```bash
osintscan discover dns records --domain example.com
```

#### Help Text

```bash
$ osintscan discover dns records --help
Query and display all DNS records (A, AAAA, MX, TXT, etc.) for the specified domain.

Usage:
  osintscan discover dns records [flags]

Flags:
      --domain string          The domain name to query for DNS records
  -h, --help                   help for records
      --record-types strings   Comma-separated list of DNS record types to query (A, AAAA, CNAME, MX, NS, SOA, TXT, PTR, SRV, ALL) (default [ALL])

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Forward DNS Lookups

The `osintscan discover dns forward` command performs forward DNS lookups to identify IPs associated with a domain.

#### Usage

```bash
osintscan discover dns forward --domain example.com
```

#### Help Text

```bash
Perform forward DNS lookups for the specified domain to identify associated IPs

Usage:
  osintscan discover dns forward [flags]

Flags:
      --dns-resolvers stringSlice   Custom DNS resolver/servers (default [1.1.1.1:53])
      --domain string              Domain name to perform forward lookups on
  -h, --help                      help for forward
```

### Reverse DNS Lookups

The `osintscan discover dns reverse` command performs reverse DNS lookups on IP addresses or CIDR ranges.

#### Usage

```bash
osintscan discover dns reverse --ip-addresses 8.8.8.8,1.1.1.1
osintscan discover dns reverse --cidr 192.168.1.0/24
```

#### Help Text

```bash
Perform a reverse DNS lookup on a single IP, list of IPs, or a CIDR range.

Usage:
  osintscan discover dns reverse [flags]

Flags:
      --cidr string             The CIDR range to perform reverse DNS lookup on
      --dns-resolvers strings   Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53) (default [1.1.1.1:53])
  -h, --help                    help for reverse
      --ip-addresses strings    The IP addresses to perform reverse DNS lookup on
      --threads int             Number of concurrent threads for scanning (Default is number of CPUS on machine)
```

### Subdomain Discovery

#### Usage

```bash
osintscan discover dns subdomain [command]
```

#### Commands

##### Active Subdomain Discovery

Actively discovers subdomains using brute-force techniques with wordlists.

###### Usage

```bash
osintscan discover dns subdomain active --domain example.com --wordlist-size small
```

###### Help Text

```bash
Actively discover subdomains for the specified domain by bruteforcing common subdomain names and patterns.

Usage:
  osintscan discover dns subdomain active [flags]

Flags:
      --dns-resolvers strings   Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53)
      --domain string           The domain name to discover subdomains for
  -h, --help                    help for active
      --max-depth int           Maximum recursion depth for subdomain discovery (default 2)
      --sleep int               Sleep time in milliseconds between requests to avoid rate limiting
      --subdomains strings      A list of subdomain names to test during discovery
      --threads int             Number of parallel threads to use for discovery (default 10)
      --timeout int             Maximum time (in minutes) to spend on subdomain discovery
      --wordlist-file string    The file containing the wordlist to use for discovery
      --wordlist-size string    The size of the in-built wordlist to use for discovery
```

##### Correlation Subdomain Discovery

Correlates subdomains across multiple domains using active data sources.

###### Usage

```bash
osintscan discover dns subdomain correlation --domains example.com,test.com
```

###### Help Text

```bash
Correlate subdomains across multiple domains using active data sources (no direct interaction with the target).

Usage:
  osintscan discover dns subdomain correlation [flags]

Flags:
      --dns-resolvers strings   Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53)
      --domains strings         The domains to test
  -h, --help                    help for correlation
      --threads int             Number of parallel threads to use for testing (default 10)
      --timeout int             Maximum time (in seconds) to spend on each lookup
```

##### Passive Subdomain Discovery

Passively discovers subdomains using external data sources without direct target interaction.

###### Usage

```bash
osintscan discover dns subdomain passive --domain example.com
```

###### Help Text

```bash
Identify subdomains for the specified domain using only passive data sources (no direct interaction with the target).

Usage:
  osintscan discover dns subdomain passive [flags]

Flags:
      --all-sources               Use all passive sources (subfinder equivalent of --all)
      --dns-resolvers strings     Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53) (default [1.1.1.1:53])
      --domain string             The domain name to passively enumerate subdomains for
  -h, --help                      help for passive
      --max-dns-queries int       Maximum number of DNS queries to perform per request (default 2000)
      --max-resolvers-qps int     Maximum number of queries per second per resolver (default 100)
      --modules strings           Which passive modules to run: SUBFINDER, AMASS, or ALL (default [SUBFINDER])
      --requests-per-second int   Maximum number of requests per second to send to the DNS resolvers
      --threads int               Number of concurrent threads for scanning (default 10)
```

## IP Address Discovery

The `osintscan discover ip` command provides IP address and CIDR range intelligence.

### Domain ASN Lookup

Performs reverse DNS and ASN lookups on IP addresses or CIDR ranges.

#### Usage

```bash
osintscan discover ip domain-asn --ip-addresses 8.8.8.8,1.1.1.1
osintscan discover ip domain-asn --cidr 192.168.1.0/24
```

#### Help Text

```bash
Perform a reverse DNS lookup and ASN lookup on a single IP, list of IPs, or a CIDR range. Warning: /16 and larger can take upwards of 30 minutes.

Usage:
  osintscan discover ip domain-asn [flags]

Flags:
      --cidr string             The CIDR range to perform reverse DNS and ASN lookup on
      --dns-resolvers strings   Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53) (default [1.1.1.1:53])
  -h, --help                    help for domain-asn
      --ip-addresses strings    The IP addresses to perform reverse DNS and ASN lookup on
```

## Penetration Testing

### DNS Takeover Detection

The `osintscan pentest dns takeover` command detects potential subdomain takeover vulnerabilities.

#### Usage

```bash
osintscan pentest dns takeover --targets https://example.com,subdomain.example.com
```

#### Help Text

```bash
Analyze the provided targets to identify DNS records that may be vulnerable to subdomain takeover attacks, using known fingerprints and heuristics.

Usage:
  osintscan pentest dns takeover [flags]

Flags:
      --fingerprints-file string   Path to the JSON file containing service fingerprints for takeover detection (default "/opt/method/osintscan/var/conf/pentest/dns/takeover/fingerprints.json")
  -h, --help                       help for takeover
      --successful-only            Show only confirmed successful takeovers in the results
      --target-files strings       File paths containing lists of targets to analyze for takeover vulnerabilities
      --targets strings            A list of URLs or domains to analyze for takeover vulnerabilities
      --timeout int                Timeout in seconds for each takeover check request (default 30)
      --verify-tls                 Verify TLS certificates when making HTTPS requests during takeover analysis
```

## Enumeration

### DNS Zone Transfer

The `osintscan enumerate dns zonetransfer` command attempts DNS zone transfers (AXFR) to enumerate all DNS records if the server allows it.

#### Usage

```bash
osintscan enumerate dns zonetransfer --domains example.com
osintscan enumerate dns zonetransfer --nameserver ns1.example.com
```

#### Help Text

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
```
