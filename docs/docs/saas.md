# Shodan

The `osintscan saas` family of commands enable you to gather SaaS information given an organization name


## Usage

```bash
osintscan saas [command]
```

## Commands

### Discover

#### Usage

```bash
osintscan saas discovery -o json --skiptls true --successfulonly --orgs method 
```

#### Help Text

```bash
$ osintscan saas discovery -h               
Find SaaS domain slugs associated with an organization name

Usage:
  osintscan saas discovery [flags]

Flags:
  -h, --help                    help for discovery
      --httpsonly               Only use HTTPS for the requests (default true)
      --orgs strings            The organization names to use for discovery
      --saascompanies strings   The specific SaaS companies to use for discovery (Must be present in the SaaS fingerprints file)
      --saasfilepaths strings   Files containing SaaS application fingerprints (default [configs/saas/saas_fingerprints.json])
      --skiptls                 Skip TLS verification
      --ssocompanies strings    The specific SSO companies to use for discovery (Must be present in the SSO fingerprints file)
      --ssofilepaths strings    Files containing SSO application fingerprints (default [configs/saas/sso_fingerprints.json])
      --successfulonly          Only return results where the finding is a success
      --timeout int             The timeout for the request in seconds (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
