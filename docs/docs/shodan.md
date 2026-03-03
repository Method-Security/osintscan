# Shodan

The `osintscan discover shodan` family of commands leverage the [Shodan](https://www.shodan.io/) search engine to provide open source intelligence on exposed internet assets.

## Authentication

All the `osintscan discover shodan` commands leverage the Shodan API, which needs an API key in order to authenticate. All commands read from a `SHODAN_API_KEY` environment variable or from a `--api-key` flag where you can include your Shodan API key.

## Usage

```bash
osintscan discover shodan [command]
```

## Commands

### Hostname

#### Usage

```bash
osintscan discover shodan hostname --query nginx --hostname example.com
```

#### Help Text

```bash
$ osintscan discover shodan hostname --help
Query Shodan for information about a specific hostname, filtering results to match the provided hostname suffix.

Usage:
  osintscan discover shodan hostname [flags]

Flags:
      --api-key string    Shodan API Key (defaults to SHODAN_API_KEY environment variable if not provided)
  -h, --help              help for hostname
      --hostname string   The hostname suffix to match in Shodan search results
      --query string      The search query string to use with Shodan (e.g., 'apache', 'nginx')

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
