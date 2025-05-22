# DNS

The `osintscan discover dns` family of commands provides security teams with an easy to use mechanism to dig into information available within the DNS infrastructure.

## Usage

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

### Subenum

#### Usage

```bash
osintscan discover dns subdomain [command]

```

#### Commands

##### Passive

###### Help Text

```bash
$ osintscan discover dns subdomain passive -h
Passively enumerate subdomains for a given domain

Usage:
  osintscan discover dns subdomain passive [flags]

Flags:
      --domain string   Domain to get subdomains for
  -h, --help            help for subenum

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

##### Brute

###### Help Text

```bash
osintscan discover dns subdomain brute -h

Bruteforce subdomains for a given domain. This tool recursively discovers subdomains by building on previously found valid subdomains. For example, if scanning example.com:

1. First checks base subdomains like sub.example.com
2. If sub.example.com exists, will then check deeper subdomains like deep.sub.example.com
3. If sub.example.com does not exist, will not check deep.sub.example.com

This ensures efficient scanning but means some valid deep subdomains may be missed if their parent subdomain does not exist.

Usage:
  osintscan discover dns subdomain brute [flags]

Flags:
      --dns-resolver string       Custom DNS resolver/server to use for queries
      --domain string             Domain to get subdomains for
      --file strings              List of files containing subdomains to enumerate
  -h, --help                      help for brute
      --max-depth int             Maximum recursion depth (default 3)
      --subdomain strings         List of subdomains to enumerate
      --threads int               Number of parallel threads (default 20)
      --timeout int               Maximum time of enumeration (Minutes)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output

```

### Takeover

#### Usage

```bash
osintscan pentest dns takeover --targets https://example.com
```

#### Help Text

```bash
osintscan pentest dns takeover -h
Detect domain takeovers given a list of targets

Usage:
  osintscan pentest dns takeover [flags]

Flags:
      --target-files strings   Paths to files containing the list of targets
      --fingerprint-files string   Path to fingerprints file (default "configs/pentest/dns/takeover/fingerprints.json")
  -h, --help                  help for takeover
      --https                 Only check sites with secure SSL
      --targets strings       URL targets to analyze
      --timeout int           Request timeout in seconds (default 10)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Zone Transfer

#### Usage

```bash
osintscan enumerate dns zonetransfer --domains example.com --timeout 10
```

#### Help Text

```bash
Perform zone transfers for a given domain

Usage:
  osintscan enumerate dns zonetransfer [flags]

Flags:
      --domains strings   Domains to perform zone transfers for
  -h, --help              help for zonetransfer
      --timeout int       Request timeout in seconds (default 30)


Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
  
  ```
