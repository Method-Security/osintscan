# Development Setup

## Adding a new capability

To add a new scan to osintscan, providing new enumeration capabilities to security operators everywhere, please see the [adding a new capability](./adding.md) page.

## Setting up your development environment

If you've just cloned osintscan for the first time, welcome to the community! We use Palantir's [godel](https://github.com/palantir/godel) to streamline local development and [goreleaser](https://goreleaser.com/) to handle the heavy lifting on the release process.

To get started with godel, you can run

```bash
./godelw verify
```

This will run a number of checks for us, including linters, tests, and license checks. We run this command as part of our CI pipeline to ensure the codebase is consistently passing tests.

## Building the CLI

We can use godel to build our CLI locally by running

```bash
./godelw build
```

You should see output in `out/build/osintscan/<version>/<os>-<arch>/osintscan`.

If you'd like to clean this output up, you can run

```bash
./godelw clean
```

## Testing releases locally

We can use goreleaser locally as well to test our builds. As osintscan uses [cosign](https://github.com/sigstore/cosign) to sign our artifacts and Docker containers during our CI pipeline, we'll want to skip this step when running locally.

```bash
goreleaser release --snapshot --clean --skip sign
```

This should output binaries, distributable tarballs/zips, as well as docker images to your local machine's Docker registry.
