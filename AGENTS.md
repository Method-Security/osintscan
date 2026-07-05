# osintscan Project Context

## Overview

osintscan is an Open Source Intelligence (OSINT) scanning and enumeration tool that provides security teams with data-rich insights into publicly available information about targets. It follows the CLI Development Conventions for attack stage organization and implements discover, enumerate, and pentest capabilities.

## Architecture

The tool follows the standard CLI Development Conventions with clear separation by attack stages:

### Attack Stages

1. **Discover Stage** (`internal/discover/`)
   - Passive reconnaissance and information gathering
   - Public data source enumeration
   - Target fingerprinting without direct interaction

2. **Enumerate Stage** (`internal/enumerate/`)
   - Active information gathering from public sources
   - Deep inspection of discovered targets
   - Social media and public record analysis

3. **Pentest Stage** (`internal/pentest/`)
   - Verification of discovered information
   - Social engineering preparation
   - Attack surface mapping

### Core Components

1. **Discovery Module** (`internal/discover/`)
   - Domain and subdomain discovery
   - Email address harvesting
   - Social media profile enumeration
   - Public record searches

2. **Enumeration Module** (`internal/enumerate/`)
   - Detailed target profiling
   - Technology stack identification
   - Employee and contact enumeration
   - Data breach and leak detection

3. **Penetration Testing Module** (`internal/pentest/`)
   - Information validation and verification
   - Social engineering target identification
   - Attack vector mapping

### CLI Structure (`cmd/`)
- `root.go` - Main CLI setup with Cobra
- `discover.go` - Discovery command implementations
- `enumerate.go` - Enumeration command implementations  
- `pentest.go` - Penetration testing command implementations

### Generated Code (`generated/go/`)
- Fern-generated Go types and clients
- OSINT data definitions and structures
- API interfaces for type safety

## Project Structure

- **Language**: Go
- **Module**: github.com/Method-Security/osintscan
- **CLI Framework**: Cobra
- **Type Generation**: Fern
- **Testing**: Standard Go testing + external API integration tests

## Key OSINT Capabilities

- **Domain Intelligence**: Subdomain discovery, DNS enumeration, certificate transparency
- **Email Intelligence**: Email harvesting, breach detection, validation
- **Social Media**: Profile discovery, relationship mapping
- **Public Records**: Corporate filings, registration data, contact information
- **Technology Stack**: Framework detection, service identification

## Development Patterns

### CLI Development Conventions
- Follow the CLI Development Conventions for attack stage organization
- Use `<stage>Cmd` in camelCase for top-level commands (e.g., `discoverCmd`)
- Use `<stage><Component>Cmd` for subcommands (e.g., `discoverDomainCmd`)
- Implement Run functions with action verbs (e.g., `RunDomainDiscovery`, `RunEmailHarvest`)

### Flag Naming and Handling
- Use kebab-case for CLI flags: `--target-domain`
- Use camelCase when extracting flags: `targetDomain, err := cmd.Flags().GetString("target-domain")`
- Always check errors when extracting flags:
  ```go
  if err != nil {
      a.OutputSignal.AddError(err)
      return
  }
  ```
- Use `.GetStringSlice` for slice inputs with plural flag names
- Mark required flags explicitly: `_ = cmd.MarkFlagRequired("target")`

### Code Organization
- Repository organized by attack stage (`discover`, `enumerate`, `pentest`)
- Mirror naming between `fern/definition/<stage>/<component>.yml`, `internal/<stage>/<component>.go`, and `cmd/<stage>.go`
- Use subdirectories for complex components, flat files for simple ones

### OSINT-Specific Patterns
- Respect rate limits of public APIs and services
- Implement proper caching to avoid redundant requests
- Handle API key management securely
- Provide passive-only options to avoid detection
- Implement data correlation and relationship mapping

### Error Handling
```go
if err != nil {
    a.OutputSignal.AddError(err)
    return
}
```

### Fern Type Requirements
- **MANDATORY**: Every CLI command with output must have a corresponding Fern report structure
- **Three-Part Structure Pattern**: All commands must define:
  ```yaml
  # 1. Config type for input parameters
  <Stage><Component>Config:
    properties:
      # OSINT-specific configuration parameters
      target: string
      dataSources: optional<list<DataSource>>
      apiKeys: optional<map<string, string>>
  
  # 2. Result type for output data
  <Stage><Component>Result:
    properties:
      # OSINT-specific result data
      domains: optional<list<DomainInfo>>
      emailAddresses: optional<list<EmailAddress>>
  
  # 3. Report type wrapping config, result, and errors
  <Stage><Component>Report:
    properties:
      config: <Stage><Component>Config
      result: <Stage><Component>Result
      errors: optional<list<string>>
  ```
- **OSINT Example Implementation**:
  ```yaml
  DiscoverDomainConfig:
    properties:
      domain: string
      includeSubdomains: boolean
      dataSources: optional<list<DataSource>>
  
  DiscoverDomainResult:
    properties:
      domains: optional<list<DomainInfo>>
      certificates: optional<list<Certificate>>
  
  DiscoverDomainReport:
    properties:
      config: DiscoverDomainConfig
      result: DiscoverDomainResult
      errors: optional<list<string>>
  ```
- **OSINT-Specific Types**: Include OSINT-specific enums and objects:
  ```yaml
  DataSource:
    enum: [SHODAN, CENSYS, VIRUSTOTAL, SOCIAL_MEDIA, PUBLIC_RECORDS]
  ConfidenceLevel:
    enum: [HIGH, MEDIUM, LOW, UNKNOWN]
  ```
- **Type Organization**: Follow the CLI Development Conventions type ordering:
  1. ENUMs (e.g., `DataSource`, `ConfidenceLevel`)
  2. Common Objects (e.g., `EmailAddress`, `DomainInfo`)
  3. Config Types (e.g., `DiscoverDomainConfig`)
  4. Result Types (e.g., `DiscoverDomainResult`)
  5. Report Types (e.g., `DiscoverDomainReport`)

### Output Structure
```go
a.OutputSignal.Content = report
```

## Important Notes

- **API Keys**: Many OSINT sources require API keys (store securely in environment variables)
- **Rate Limits**: Respect rate limits of public services to avoid blocking
- **Legal Compliance**: Ensure all OSINT activities comply with terms of service and legal requirements
- **Data Privacy**: Handle collected data responsibly and in compliance with privacy laws
- **Passive vs Active**: Clearly distinguish between passive and active reconnaissance options

## Development Commands

```bash
# MANDATORY: Run after completing TODOs to ensure code can be merged
./godelw verify

# Build the binary
./godelw build
```

## Development Workflow

1. Follow CLI Development Conventions for new commands
2. Use Fern definitions for type safety
3. Implement proper rate limiting and error handling
4. Test with various target types and scenarios
5. Follow existing patterns for consistency
6. **CRITICAL**: Always run `./godelw verify` after TODO completion before merging

## File Structure Conventions

- `/cmd/` - CLI command implementations
- `/internal/<stage>/` - OSINT capability implementations
- `/fern/definition/` - Fern API definitions
- `/generated/go/` - Generated Go code
- `/configs/` - Configuration files and wordlists
- `/docs/` - Documentation

## Development Practices

- Follow CLI Development Conventions exactly
- Implement comprehensive error handling and rate limiting
- Respect public service terms of use
- Handle sensitive data appropriately
- Always end files with a single newline