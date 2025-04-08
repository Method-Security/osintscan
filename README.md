<div align="center">
<h1>osintscan</h1>

[![GitHub Release][release-img]][release]
[![Verify][verify-img]][verify]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]

[![GitHub Downloads][github-downloads-img]][release]
[![Docker Pulls][docker-pulls-img]][docker-pull]

</div>

osintscan has been designed to provide security teams with an easy-to-use yet data-rich suite of open source intelligence (OSINT) capabilities to help them better understand the internet exposure of the networks they defend. Designed with data-modeling and data-integration needs in mind, osintscan can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

The types of scans that osintscan can conduct are constantly growing. For the most up to date listing, please see the documentation [here](https://method-security.github.io/osintscan/docs/index.html)

To learn more about osintscan, please see the [Documentation site](https://method-security.github.io/osintscan/) for the most detailed information.

## Quick Start

### Get osintscan

For the full list of available installation options, please see the [Installation](./getting-started/installation.md) page. For convenience, here are some of the most commonly used options:

- `docker run methodsecurity/osintscan`
- `docker run ghcr.io/method-security/osintscan`
- Download the latest binary from the [Github Releases](https://github.com/Method-Security/osintscan/releases/latest) page
- [Installation documentation](./getting-started/installation.md)

#### Examples

```bash
osintscan dns records --domain example.com
```

```bash
osintscan dns certs --domain example.com

### Building a Statically Compiled Container for Local Testing
(Reference reusable-build.yaml)

1. Build ARM64 builder image: `docker buildx build . --platform linux/arm64 --load --tag armbuilder -f Dockerfile.builder`

2. Build ARM64 image: `docker run -v .:/app/osintscan -e GOARCH=arm64 -e GOOS=linux --rm armbuilder goreleaser build --single-target -f .goreleaser/goreleaser-build.yml --snapshot --clean`

3. `cp dist/linux_arm64/build-linux_linux_arm64/osintscan .`

4. `docker buildx build . --platform linux/arm64 --load --tag osintscan:local -f Dockerfile`

5. Open shell: `docker run -it --rm --entrypoint /bin/bash osintscan:local`

6. OR run command without shell example: `docker run osintscan:local discovery saas --org example -o json`


### Note:
This tool runs on a headless-shell base image to support chrome/chromium browser automation. The dockerfile uses debian-based install tools. 
```

## Contributing

Interested in contributing to osintscan? Please see our organization wide [Contribution](https://method-security.github.io/community/contribute/discussions.html) page.

## Want More?

If you're looking for an easy way to tie osintscan into your broader cybersecurity workflows, or want to leverage some autonomy to improve your overall security posture, you'll love the broader Method Platform.

For more information, visit us [here](https://method.security)

## Community

osintscan is a Method Security open source project.

Learn more about Method's open source source work by checking out our other projects [here](https://github.com/Method-Security) or our organization wide documentation [here](https://method-security.github.io).

Have an idea for a Tool to contribute? Open a Discussion [here](https://github.com/Method-Security/Method-Security.github.io/discussions).

[verify]: https://github.com/Method-Security/osintscan/actions/workflows/verify.yml
[verify-img]: https://github.com/Method-Security/osintscan/actions/workflows/verify.yml/badge.svg
[go-report]: https://goreportcard.com/report/github.com/Method-Security/osintscan
[go-report-img]: https://goreportcard.com/badge/github.com/Method-Security/osintscan
[release]: https://github.com/Method-Security/osintscan/releases
[releases]: https://github.com/Method-Security/osintscan/releases/latest
[release-img]: https://img.shields.io/github/release/Method-Security/osintscan.svg?logo=github
[github-downloads-img]: https://img.shields.io/github/downloads/Method-Security/osintscan/total?logo=github
[docker-pulls-img]: https://img.shields.io/docker/pulls/methodsecurity/osintscan?logo=docker&label=docker%20pulls%20%2F%20osintscan
[docker-pull]: https://hub.docker.com/r/methodsecurity/osintscan
[license]: https://github.com/Method-Security/osintscan/blob/main/LICENSE
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
