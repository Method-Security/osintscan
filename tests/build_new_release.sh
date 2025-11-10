#!/usr/bin/env bash
set -euo pipefail

echo "[+] Building ARM64 builder image"
docker buildx build . --platform linux/arm64 --load --tag armbuilder -f Dockerfile.builder > /dev/null 2>&1

echo "[+] Building ARM64 image"
docker run -v .:/app/osintscan -e GOARCH=arm64 -e GOOS=linux --rm armbuilder goreleaser build --single-target -f .goreleaser/goreleaser-build.yml --snapshot --clean > /dev/null 2>&1

echo "[+] Copying osintscan binary"
cp dist/linux_arm64/build-linux_linux_arm64/osintscan .  > /dev/null 2>&1

echo "[+] Building local image"
docker buildx build . --platform linux/arm64 --load --tag osintscan:local -f Dockerfile  > /dev/null 2>&1
