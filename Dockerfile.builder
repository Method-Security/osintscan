# Dockerfile used for the compilation of the statically compiled osintscan binary
FROM golang:1.24.4-alpine AS base
ARG GORELEASER_VERSION="v2.0.1"
ARG CLI_NAME="osintscan"
ARG TARGETARCH

RUN \
  apk add --no-cache git gcc musl-dev bash && \
  mkdir -p /app/${CLI_NAME} && \
  git config --global --add safe.directory /app/${CLI_NAME}

WORKDIR /app/${CLI_NAME}

FROM base AS amd64
ARG CLI_NAME
ARG GORELEASER_VERSION
RUN \
  wget https://github.com/goreleaser/goreleaser-pro/releases/download/${GORELEASER_VERSION}-pro/goreleaser-pro_Linux_x86_64.tar.gz && \
  tar -xvzf goreleaser-pro_Linux_x86_64.tar.gz && \
  mv goreleaser /usr/local/bin/goreleaser && \
  rm -rf goreleaser-pro_Linux_x86_64.tar.gz LICENSE.md README.md completions manpages

FROM base AS arm64
ARG CLI_NAME
RUN \
  wget https://github.com/goreleaser/goreleaser-pro/releases/download/${GORELEASER_VERSION}-pro/goreleaser-pro_Linux_arm64.tar.gz && \
  tar -xvzf goreleaser-pro_Linux_arm64.tar.gz && \
  mv goreleaser /usr/local/bin/goreleaser && \
  rm -rf goreleaser-pro_Linux_arm64.tar.gz LICENSE.md README.md completions manpages

