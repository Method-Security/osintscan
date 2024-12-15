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