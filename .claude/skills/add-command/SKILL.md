---
name: add-command
description: "Add a new CLI command — Fern types, Go implementation, signal generation, and pypi-local generation. Usage: /add-command <describe what the command does>"
user-invocable: true
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, Agent, Task
---

# Add Command

This skill adds a new CLI command end-to-end: Fern type definitions, Go implementation, cobra wiring, signal generation against a real target, verification, and Python type generation.

**First**: Determine the repo name and Go module path from `go.mod` in the repo root. All paths below use `<REPO>` and `<MODULE>` as placeholders — replace with actual values (e.g., `networkscan` / `github.com/Method-Security/networkscan`).

## Overview

1. Define Fern types (Three-Part Pattern)
2. Generate Go types from Fern
3. Implement the Go internal logic
4. Wire the cobra command in `cmd/`
5. Build the binary and verify
6. Find a real target and generate a signal JSON
7. Generate pypi-local Python types

---

## Step 1: Define Fern Types

Create a new Fern definition file. Determine the stage (`discover`, `enumerate`, or `pentest`) from the user's description.

### File location

- Simple: `fern/definition/<stage>/<component>.yml`
- Complex: `fern/definition/<stage>/<component>/<component>.yml`

First, read existing Fern definitions in `fern/definition/<stage>/` to understand the patterns used in this repo.

### Three-Part Pattern (MANDATORY)

```yaml
types:
  # 1. ENUMs (if needed)
  <EnumName>:
    enum:
      - VALUE_ONE
      - VALUE_TWO

  # 2. Detail objects
  <Stage><Component>Details:
    properties:
      target: string
      # ... service-specific fields
      error: optional<string>

  # 3. Config — input parameters
  <Stage><Component>Config:
    properties:
      targets: list<string>
      timeout: integer

  # 4. Result — wraps output data
  <Stage><Component>Result:
    properties:
      details: optional<list<<Stage><Component>Details>>

  # 5. Report — wraps config + result + errors
  <Stage><Component>Report:
    properties:
      config: <Stage><Component>Config
      result: <Stage><Component>Result
      errors: optional<list<string>>
```

### Fern naming conventions

- Types: PascalCase (`EnumerateFtpDetails`)
- Properties: camelCase (`allowsAnonymousLogin`)
- Enums: UPPER_SNAKE_CASE (`TLS_1_2`)

### If adding to an existing stage's service enum

Check if this stage has a parent yml that aggregates services (e.g., `enumerate/enumerate.yml` with `SupportedServiceType` and `EnumerateServiceDetails` union). If so, add the new component there too.

---

## Step 2: Generate Go Types

```bash
fern generate --group local
```

Verify: `ls generated/go/<stage>/<component>/`

---

## Step 3: Implement Go Logic

Create `internal/<stage>/<component>/<component>.go` (or flat file for simple cases).

Read 2-3 existing implementations in `internal/<stage>/` to match the patterns used in this specific repo.

### Import organization

```go
import (
    // Standard
    "context"

    // Generated — from this repo's generated Go types
    <stage>fern "<MODULE>/generated/go/<stage>"

    // Internal
    "<MODULE>/internal/..."

    // External
    svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)
```

### If adding to an engine pattern

Check if `internal/<stage>/engine.go` exists. If so, add the new component as a case in the engine's dispatch logic.

---

## Step 4: Wire the Cobra Command

Edit `cmd/<stage>.go`. Read the existing commands in that file to match the exact pattern.

### Flag conventions

- CLI flags: kebab-case (`--scan-type`)
- Go variables: camelCase (`scanType`)
- Always check errors: `value, err := cmd.Flags().GetString("flag-name"); if err != nil { a.OutputSignal.AddError(err); return }`
- Mark required: `_ = cmd.MarkFlagRequired("targets")`
- Plural names for slices: `--targets` with `GetStringSlice`

### Output assignment

```go
a.OutputSignal.Content = report
```

---

## Step 5: Build and Verify

```bash
./godelw build
```

Test the command exists:
```bash
./build/<REPO> <stage> <component> --help
```

Run full verification (MANDATORY):
```bash
./godelw verify
```

Fix all errors before proceeding.

---

## Step 6: Generate a Signal JSON

Run the command against a real target to produce a valid signal JSON. This signal is used by ontology processor tests.

### Option A: Shodan (internet-facing services)

```bash
# Requires SHODAN_API_KEY env var
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=port:<port>+<service>" \
  | jq -r '.matches[0].ip_str'

./build/<REPO> <stage> <component> --target <ip>:<port> --timeout 30 -o signal -f /tmp/signal-<component>.json
```

### Option B: Docker (local testing)

```bash
docker run -d --name test-<component> -p <port>:<port> <image>
sleep 3
./build/<REPO> <stage> <component> --target 127.0.0.1:<port> --timeout 30 -o signal -f /tmp/signal-<component>.json
docker stop test-<component> && docker rm test-<component>
```

### Common Docker test targets

| Service | Image | Port |
|---------|-------|------|
| FTP | `fauria/vsftpd` | 21 |
| SSH | `linuxserver/openssh-server` | 2222 |
| SMTP | `mailhog/mailhog` | 1025 |
| LDAP | `osixia/openldap` | 389 |
| SMB | `dperson/samba` | 445 |
| HTTP/TLS | `nginx:alpine` | 443 |
| DNS | `coredns/coredns` | 53 |
| SNMP | `polinux/snmpd` | 161 |
| Redis | `redis:alpine` | 6379 |
| MySQL | `mysql:8` | 3306 |
| PostgreSQL | `postgres:alpine` | 5432 |

### Validate

```bash
cat /tmp/signal-<component>.json | jq .
```

Must have populated `config`, `result` (with real data), and `errors` fields.

Save location and tell the user — this file is needed for ontology processor tests.

---

## Step 7: Generate pypi-local Python Types

```bash
fern generate --group pypi-local
```

This outputs Pydantic models to `generated/python/`. These can be hot-installed into ontology:

```bash
cd generated/python
cat > setup.py << 'EOF'
from setuptools import setup, find_packages
setup(name="method<REPO>", version="0.0.999", packages=find_packages(), install_requires=["pydantic>=1.9.2"])
EOF
python3 setup.py sdist bdist_wheel
```

Then in the ontology repo: `uv pip install generated/python/dist/*.whl --force-reinstall --no-deps`

---

## Checklist

- [ ] Fern definition follows Three-Part Pattern
- [ ] `fern generate --group local` succeeded
- [ ] Go implementation matches repo patterns (imports, logging, error handling)
- [ ] Cobra command uses kebab-case flags with error checking
- [ ] `./godelw build` succeeds, `--help` shows new command
- [ ] Signal JSON generated against a real target with populated data
- [ ] `./godelw verify` passes clean
- [ ] `fern generate --group pypi-local` succeeded
- [ ] Signal JSON location reported to user
