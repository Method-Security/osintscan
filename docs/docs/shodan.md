# Shodan

The `osintscan shodan` family of commands leverage the [Shodan](https://www.shodan.io/) search engine to provide open source intelligence on exposed internet assets.

## Authentication

All the `osintscan shodan` commands leverage the Shodan API, which needs an API key in order to authenticate. All commands read from a `SHODAN_API_KEY` environment variable or from a `--apikey` flag where you can include your Shodan API key.

## Hostname

### Usage

```bash
osintscan shodan hostname --hostname example.com
```

### Help Test

```bash
$ osintscan shodan hostname -h
Query Shodan for a hostname string search

Usage:
  osintscan shodan hostname [flags]

Flags:
      --apikey string     Shodan API Key (reads from SHODAN_API_KEY env by default)
  -h, --help              help for hostname
      --hostname string   The hostname suffix you want to ensure the Shodan record contains
      --query string      Query string to search Shodan hostname:{} for

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
