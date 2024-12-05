# DNS

The `osintscan dns` family of commands provides security teams with an easy to use mechanism to dig into information available within the DNS infrastructure.

## Usage

```bash
osintscan dns [command]
```

## Commands

### Certs

The `osintscan dns certs` command returns information about the certificate chains that are being leveraged by the specified domain.

#### Usage

```bash
osintscan dns certs --domain example.com
```

#### Help Text

```bash
osintscan dns certs -h
Gather DNS certs for a given domain

Usage:
  osintscan dns certs [flags]

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
osintscan dns records --domain example.com
```

#### Help Text

```bash
$ osintscan dns records -h
Gather DNS records for a given domain

Usage:
  osintscan dns records [flags]

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
osintscan dns subenum [command]

```

#### Commands

##### Passive

###### Help Text

```bash
$ osintscan dns subenum passive -h
Passively enumerate subdomains for a given domain

Usage:
  osintscan dns subenum passive[flags]

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
osintscan dns subenum brute -h

Bruteforce subdomains for a given domain. This tool recursively discovers subdomains by building on previously found valid subdomains. For example, if scanning example.com:

1. First checks base subdomains like sub.example.com
2. If sub.example.com exists, will then check deeper subdomains like deep.sub.example.com
3. If sub.example.com does not exist, will not check deep.sub.example.com

This ensures efficient scanning but means some valid deep subdomains may be missed if their parent subdomain does not exist.

Usage:
  osintscan dns subenum brute [flags]

Flags:
      --domain string       Domain to get subdomains for
      --file strings        List of files containing subdomains to enumerate
  -h, --help                help for brute
      --maxdepth int        Maximum recursion depth (default 3)
      --subdomain strings   List of subdomains to enumerate
      --threads int         Number of parallel threads (default 20)
      --timeout int         Maximum time of enumeration (Minutes)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output

```

### Takeover

#### Usage

```bash
webscan domain takeover --targets https://example.com
```

#### Help Text

```bash
webscan domain takeover -h
Detect domain takeovers given a list of targets

Usage:
  osintscan dns takeover [flags]

Flags:
      --files strings         Paths to files containing the list of targets
      --fingerprints string   Path to fingerprints file (default "configs/fingerprints.json")
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