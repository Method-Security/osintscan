# Discover

The `osintscan discover` command performs passive reconnaissance and information gathering to collect open source intelligence about targets.

## Usage

```bash
osintscan discover [command]
```

## Available Commands

- **asn**: ASN information discovery using BGPView API
- **cdn**: CDN provider detection for IP addresses and domains
- **dns**: Comprehensive DNS intelligence gathering
- **idp**: Identity provider discovery for a domain
- **ip**: IP address and network intelligence
- **shodan**: Query the Shodan search engine

## Commands

### ASN

Retrieve detailed ASN information using BGPView's API.

#### Usage
```bash
osintscan discover asn --asn AS23028
```

#### Help Text
```bash
Discover information about ASN, including ASN description, CIDRs, country, and other metadata

Usage:
  osintscan discover asn [flags]

Flags:
      --asn string      The ASN number to lookup (e.g., AS23028 or 23028)
  -h, --help           help for asn
      --timeout int    The timeout in seconds for the ASN lookup (default 120)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### CDN

Check if IP addresses or domains belong to known CDN providers.

#### Usage
```bash
osintscan discover cdn --domain example.com
```

#### Help Text
```bash
Check if an IP address belongs to a known CDN provider

Usage:
  osintscan discover cdn [flags]

Flags:
      --domain string                The domain name to check against CDN provider ranges
      --dns-resolvers stringSlice    Custom DNS resolver/servers to use
      --fingerprints-file string     The path to the CDN fingerprints file
  -h, --help                        help for cdn
      --ip-addresses stringSlice    IP addresses to check against CDN provider ranges

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### IDP

Detect identity providers associated with a domain by querying public endpoints, DNS records, and federation metadata. Supports detection of Azure AD/Entra ID and Okta.

#### Usage
```bash
osintscan discover idp --domain example.com
```

#### Azure AD / Entra ID Detection

For domains using Azure AD/Entra ID, the command queries Microsoft's public federation and OpenID endpoints to extract:

- **Tenant details**: Tenant ID, brand name, cloud instance, namespace type
- **Federation status**: `MANAGED` (password auth via Azure AD), `FEDERATED` (auth delegated to on-prem IdP), or `UNKNOWN`
- **Federation metadata**: Auth URL, authorization endpoint, token endpoint, OpenID configuration URL
- **Credential type info**: Desktop SSO (Seamless SSO) status, preferred credential type (`PASSWORD`, `FEDERATION`, `FIDO2`, `WINDOWS_HELLO`, `PHONE_SIGN_IN`), custom branding configured
- **M365 service presence**: Detects Exchange Online, SharePoint Online, Teams, and Skype for Business (SSFB)

#### Okta Detection

For domains using Okta, the command tries four detection methods in order:

| Method | Description |
|--------|-------------|
| `DNS_CNAME` | Checks for a DNS CNAME on the domain pointing to an Okta endpoint |
| `OPENID_CONFIG` | Fetches the OpenID Connect discovery document from the domain |
| `AZURE_USERREALM_FEDERATION` | Queries Microsoft's UserRealm API to detect Okta federation |
| `ORG_SLUG_LOOKUP` | Generates candidate org slugs from the domain (e.g., `method.security` → `method-security`, `methodsecurity`, `method`) and probes `{slug}.okta.com` OIDC endpoints |

When detected, returns: org URL, issuer, custom domain, authorization endpoint, token endpoint, and the detection method used.

#### Help Text
```bash
Detect identity providers (Azure AD/Entra ID, Okta, etc.) associated with a domain by querying public endpoints, DNS records, and federation metadata.

Usage:
  osintscan discover idp [flags]

Flags:
      --domain string   The domain name to discover identity providers for
  -h, --help            help for idp
      --timeout int     The timeout in seconds for each HTTP request (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### DNS

Comprehensive DNS intelligence gathering capabilities.

#### Usage
```bash
osintscan discover dns [command]
```

#### Available Subcommands

- **certs**: Retrieve SSL/TLS certificates for domains
- **records**: Fetch DNS records (A, AAAA, MX, TXT, etc.)
- **forward**: Perform forward DNS lookups
- **reverse**: Perform reverse DNS lookups on IPs/CIDRs
- **subdomain**: Subdomain discovery (active, correlation, passive)

#### Certs

Fetch and display SSL/TLS certificates associated with the specified domain.

##### Usage
```bash
osintscan discover dns certs --domain example.com
```

##### Help Text
```bash
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

#### Records

Query and display all DNS records for the specified domain.

##### Usage
```bash
osintscan discover dns records --domain example.com
```

##### Help Text
```bash
Query and display all DNS records (A, AAAA, MX, TXT, etc.) for the specified domain.

Usage:
  osintscan discover dns records [flags]

Flags:
      --dns-resolvers strings   DNS resolvers to use for record lookups (e.g. 10.0.0.1:53).
      --domain string           The domain name to query for DNS records
  -h, --help                    help for records
      --record-types strings    Comma-separated list of DNS record types to query (A, AAAA, CNAME, MX, NS, SOA, TXT, PTR, SRV, ALL) (default [ALL])

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

#### Forward

Perform forward DNS lookups to identify IPs associated with a domain.

##### Usage
```bash
osintscan discover dns forward --domain example.com
```

##### Help Text
```bash
Perform forward DNS lookups for the specified domain to identify associated IPs

Usage:
  osintscan discover dns forward [flags]

Flags:
      --dns-resolvers stringSlice   Custom DNS resolver/servers
      --domain string              Domain name to perform forward lookups on
  -h, --help                      help for forward

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

#### Reverse

Perform reverse DNS lookups on IP addresses or CIDR ranges.

##### Usage
```bash
osintscan discover dns reverse --ip-addresses 8.8.8.8,1.1.1.1
osintscan discover dns reverse --cidr 192.168.1.0/24
```

##### Help Text
```bash
Perform a reverse DNS lookup on a single IP, list of IPs, or a CIDR range.

Usage:
  osintscan discover dns reverse [flags]

Flags:
      --cidr string             The CIDR range to perform reverse DNS lookup on
      --dns-resolvers strings   Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53)
  -h, --help                    help for reverse
      --ip-addresses strings    The IP addresses to perform reverse DNS lookup on
      --threads int             Number of concurrent threads for scanning

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

#### Subdomain

Discover subdomains using various techniques.

##### Usage
```bash
osintscan discover dns subdomain [command]
```

##### Active

Actively discover subdomains using brute-force techniques with wordlists.

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
      --max-depth int           Maximum recursion depth for subdomain discovery (default 1)
      --sleep int               Sleep time in milliseconds between requests to avoid rate limiting
      --subdomains strings      A list of subdomain names to test during discovery
      --threads int             Number of parallel threads to use for discovery (default 100)
      --timeout int             Maximum time (in minutes) to spend on subdomain discovery (default 65)
      --wildcard-checks int     Number of random subdomain probes used to detect wildcard DNS records (default 5)
      --wordlist-file string    The file containing the wordlist to use for discovery
      --wordlist-size string    The size of the in-built wordlist to use for discovery (default "SMALL")

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

##### Correlation

Correlate subdomains across multiple domains using active data sources.

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

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

##### Passive

Passively discover subdomains using external data sources without direct target interaction.

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
      --all-sources               Use all passive sources (subfinder equivalent of --all) (default true)
      --dns-resolvers strings     Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53)
      --domain string             The domain name to passively enumerate subdomains for
  -h, --help                      help for passive
      --max-dns-queries int       Maximum number of DNS queries to perform per request (default 2000)
      --max-resolvers-qps int     Maximum number of queries per second per resolver (default 20)
      --modules strings           Which passive modules to run: SUBFINDER, AMASS, or ALL (default [SUBFINDER])
      --recursive-depth int       Recursive discovery depth (0=none, 1=re-scan discovered domains, 2=two levels deep, etc.) (default 1)
      --requests-per-second int   Maximum number of requests per second to send to the DNS resolvers
      --threads int               Number of concurrent threads for scanning (default 50)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### IP

IP address and CIDR range intelligence.

#### Domain ASN Lookup

Perform reverse DNS and ASN lookups on IP addresses or CIDR ranges.

##### Usage
```bash
osintscan discover ip domain-asn --ip-addresses 8.8.8.8,1.1.1.1
osintscan discover ip domain-asn --cidr 192.168.1.0/24
```

##### Help Text
```bash
Perform a reverse DNS lookup and ASN lookup on a single IP, list of IPs, or a CIDR range. Warning: /16 and larger can take upwards of 30 minutes.

Usage:
  osintscan discover ip domain-asn [flags]

Flags:
      --cidr string             The CIDR range to perform reverse DNS and ASN lookup on
      --dns-resolvers strings   Custom DNS resolver/servers to use for queries (e.g. 1.1.1.1:53)
  -h, --help                    help for domain-asn
      --ip-addresses strings    The IP addresses to perform reverse DNS and ASN lookup on

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Shodan

Leverage the [Shodan](https://www.shodan.io/) search engine to provide open source intelligence on exposed internet assets.

#### Authentication

All `osintscan discover shodan` commands leverage the Shodan API, which needs an API key in order to authenticate. All commands read from a `SHODAN_API_KEY` environment variable or from a `--api-key` flag where you can include your Shodan API key.

#### Usage
```bash
osintscan discover shodan [command]
```

#### Hostname

##### Usage
```bash
osintscan discover shodan hostname --query nginx --hostname example.com
```

##### Help Text
```bash
Query Shodan for information about a specific hostname, filtering results to match the provided hostname suffix.

Usage:
  osintscan discover shodan hostname [flags]

Flags:
      --api-key string    Shodan API Key
  -h, --help              help for hostname
      --hostname string   The hostname suffix to match in Shodan search results
      --query string      The search query string to use with Shodan (e.g., 'apache', 'nginx')

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
