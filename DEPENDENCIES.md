# Dependency security posture

Last reviewed: **2026-08-31**. Tooling: `govulncheck -mode=source ./...` and
`osv-scanner --lockfile=go.mod`.

Reachable-vulnerability count at last review: **1**, which has **no published
fix**. Everything with a fix available has been taken.

Reproduce with:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck -mode=source ./...
```

`govulncheck` is the number that matters — it does call-graph reachability, so
it distinguishes "this module is in our graph" from "our code can actually
reach the vulnerable function". `osv-scanner` reports the former and is much
noisier. Where they disagree, prefer `govulncheck` and record the reasoning.

## Accepted risk

### GO-2026-5932 — `golang.org/x/crypto`

**Not an exploitable defect.** Read the advisory text: *"the golang.org/x/crypto/openpgp
package is unmaintained, unsafe by design, and has known security issues."* It is a
blanket **deprecation notice** for the package, which is why `Fixed in: N/A` — there is no
patch, the remedy is "stop using it". Do not triage this as if it were a CVE.

It reaches us through `google/go-github/v30` (a 2020-era release), which
`projectdiscovery/utils` uses for verifying self-update release signatures. It cannot be
removed from here: go-github v30 is pinned by `projectdiscovery/utils` and we are already
on that module's current release. Excising it means a `replace` directive that breaks
`utils`.

Re-check on each sweep in case a fix path appears upstream.

## A structural note

Every vulnerable module this repo has ever been flagged for is **transitive**.
No first-party file imports any of them; they arrive through amass, subfinder,
dnsx and miekg/dns. That changes what a bump is risking: not "does our code
still compile" but "do those parent libraries still behave against the bumped
version". Compilation is a weak signal here.

## Before you bump anything

This repo has **zero** hand-written unit tests — the 419 test functions under
`generated/` are Fern-generated JSON round-trips. A green `go build` is **not**
evidence that a bump is safe.

Run the smoke test, which stands up a local authoritative DNS server and drives
the real CLI against it, so the `miekg/dns` wire path is exercised for real:

```sh
scripts/smoke/smoke.sh
SMOKE_DOCKER=1 scripts/smoke/smoke.sh   # reproduce what CI (ubuntu) sees
```

Run it once **before** your change and once after, and compare. A suite that
only passes after the change tells you nothing; the before-run is the control.

**This script is not wired into CI**, by deliberate choice — running it is a
manual step during dependency work, not something that gates merges.
