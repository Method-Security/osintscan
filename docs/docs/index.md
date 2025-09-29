# Capabilities

osintscan offers a variety of techniques that allow security teams to leverage open source intelligence (OSINT) capabilities to better understand their internet facing exposure. Each of the below pages offers you an in depth look at a osintscan capability related to a unique technique.

## Top Level Commands

osintscan organizes functionality under three primary command groups and their modules:

### discover

- [ASN](./dns.md) – ASN information discovery using BGPView API
- [CDN](./dns.md) – CDN provider detection for IP addresses and domains
- [DNS](./dns.md) – records, certificates, subdomain enumeration, forward/reverse lookups
- [IP](./dns.md) – IP address and CIDR information, domain-ASN lookups
- [Shodan](./shodan.md) – query the Shodan search engine

### enumerate

- [DNS zone transfer](./dns.md) – attempt AXFR zone transfers

### pentest

- [DNS takeover](./dns.md) – detect domain takeover vulnerabilities

## Top Level Flags

osintscan has several top level flags that can be used on any subcommand. These include:

```bash
Flags:
  -h, --help                 help for osintscan
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

## Version Command

Run `osintscan version` to get the exact version information for your binary

## Output Formats

For more information on the various output formats that are supported by osintscan, see the [Output Formats](https://method-security.github.io/docs/output.html) page in our organization wide documentation.
