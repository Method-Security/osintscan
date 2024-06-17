# Getting Started

If you are just getting started with networkscan, welcome! This guide will walk you through the process of going zero to one with the tool.

## Installation

networkscan is provided in several convenient form factors, including statically compiled binary images on a variety of architectures as well as a Docker image for both x86 and ARM machines.

If you do not see an architecture that you require, please open a [Discussion](https://method-security.github.io/community/contribute/discussions.html) to propose adding it.

### Binaries

networkscan currently supports statically compiled binaries across the following operating systems and architectures:

| OS      | Architecture |
| ------- | ------------ |
| Linux   | amd64        |
| Linux   | arm64        |
| MacOS   | arm64        |
| Windows | amd64        |

The latest binaries can be downloaded directly from [Github](https://github.com/Method-Security/networkscan/releases/latest).

### Docker

Docker images for networkscan are hosted in both Github Container Registry as well as on Docker Hub and can be pulled via:

```bash
docker pull ghcr.io/method-security/networkscan
```

```bash
docker pull methodsecurity/networkscan
```
