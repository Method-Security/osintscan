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
osintscan discover dns certs -h
Gather DNS certs for a given domain

Usage:
  osintscan discover dns certs [flags]

Flags:
      --domain string   Domain to get DNS certs for
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
$ osintscan discover dns records -h
Gather DNS records for a given domain

Usage:
  osintscan discover dns records [flags]

Flags:
      --domain string   Domain to get DNS records for
  -h, --help            help for records

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
Perform reverse DNS lookup on single IP, list of IPs, or CIDR range

Usage:
  osintscan discover dns reverse [flags]

Flags:
      --cidr string                CIDR range to perform reverse DNS lookup on
      --dns-resolvers stringSlice  Custom DNS resolver/servers (default [1.1.1.1:53])
  -h, --help                      help for reverse
      --ip-addresses stringSlice  IP addresses to perform reverse DNS lookup on
      --threads int               Number of concurrent threads (default: number of CPUs)
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
Actively discover subdomains for the specified domain by bruteforcing common subdomain names

Usage:
  osintscan discover dns subdomain active [flags]

Flags:
      --dns-resolvers stringSlice  Custom DNS resolver/servers for queries
      --domain string             Domain name to discover subdomains for
  -h, --help                     help for active
      --max-depth int            Maximum recursion depth for subdomain discovery (default 2)
      --subdomains stringSlice   List of subdomain names to test during discovery
      --threads int              Number of parallel threads (default 10)
      --timeout int              Maximum time (in minutes) for subdomain discovery
      --wordlist-file string     File containing wordlist for discovery
      --wordlist-size string     Size of in-built wordlist (small, medium, large)
```

##### Correlation Subdomain Discovery

Correlates subdomains across multiple domains using active data sources.

###### Usage

```bash
osintscan discover dns subdomain correlation --domains example.com,test.com
```

###### Help Text

```bash
Correlate subdomains across multiple domains using active data sources

Usage:
  osintscan discover dns subdomain correlation [flags]

Flags:
      --dns-resolvers stringSlice  Custom DNS resolver/servers for queries
      --domains stringSlice       Domains to test
  -h, --help                     help for correlation
      --threads int              Number of parallel threads (default 10)
      --timeout int              Maximum time (in seconds) for each lookup
```

##### Passive Subdomain Discovery

Passively discovers subdomains using external data sources without direct target interaction.

###### Usage

```bash
osintscan discover dns subdomain passive --domain example.com
```

###### Help Text

```bash
Identify subdomains using only passive data sources (no direct target interaction)

Usage:
  osintscan discover dns subdomain passive [flags]

Flags:
      --domain string             Domain name to passively enumerate subdomains for
  -h, --help                     help for passive
      --requests-per-second int  Maximum requests per second to DNS resolvers
      --threads int              Number of concurrent threads (default 10)
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
Perform reverse DNS lookup and ASN lookup on single IP, list of IPs, or CIDR range

Usage:
  osintscan discover ip domain-asn [flags]

Flags:
      --cidr string                CIDR range to perform reverse DNS and ASN lookup on
      --dns-resolvers stringSlice  Custom DNS resolver/servers (default [1.1.1.1:53])
  -h, --help                      help for domain-asn
      --ip-addresses stringSlice  IP addresses to perform reverse DNS and ASN lookup on
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
Analyze targets to identify DNS records vulnerable to subdomain takeover attacks

Usage:
  osintscan pentest dns takeover [flags]

Flags:
      --fingerprints-file string  Path to JSON file with service fingerprints (default "/opt/method/osintscan/var/conf/pentest/dns/takeover/fingerprints.json")
  -h, --help                     help for takeover
      --successful-only          Show only confirmed successful takeovers
      --target-files stringSlice  File paths containing lists of targets
      --targets stringSlice      URLs or domains to analyze for takeover vulnerabilities
      --timeout int              Timeout in seconds for each takeover check (default 30)
      --verify-tls               Verify TLS certificates when making HTTPS requests
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
Attempt DNS zone transfers (AXFR) for domains to enumerate all DNS records

Usage:
  osintscan enumerate dns zonetransfer [flags]

Flags:
      --dns-resolvers stringSlice  Custom DNS resolver/servers (default [1.1.1.1:53])
      --domains stringSlice       Domain names to attempt zone transfers on
  -h, --help                     help for zonetransfer
      --nameserver string         Specific nameserver to test zone transfers against
      --timeout int              Timeout in seconds for each zone transfer request (default 30)
```
