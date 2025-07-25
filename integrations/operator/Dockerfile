ARG BASE_IMAGE=gcr.io/distroless/cc-debian12

# BUILDPLATFORM is provided by Docker/buildx
FROM --platform=$BUILDPLATFORM docker.io/debian:12 AS builder
ARG BUILDARCH

## Install dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    unzip \
    # x86_64 dependencies and build tools
    build-essential \
    # ARM dependencies
    libc6-dev-armhf-cross \
    gcc-arm-linux-gnueabihf \
    # ARM64 dependencies
    libc6-dev-arm64-cross \
    gcc-aarch64-linux-gnu \
    # i386 dependencies
    libc6-dev-i386-cross \
    gcc-i686-linux-gnu

# Install Go.
ARG GOLANG_VERSION
RUN mkdir -p /opt && cd /opt && curl -fsSL https://storage.googleapis.com/golang/$GOLANG_VERSION.linux-${BUILDARCH}.tar.gz | tar xz && \
    chmod a+w /var/lib && \
    chmod a-w /
ENV GOPATH="/go" \
    GOROOT="/opt/go" \
    PATH="$PATH:/opt/go/bin:/go/bin"

# Install protoc.
ARG PROTOC_VERSION # eg, "3.20.2"
RUN VERSION="$PROTOC_VERSION" && \
  PB_REL='https://github.com/protocolbuffers/protobuf/releases' && \
  PB_FILE="$(mktemp protoc-XXXXXX.zip)" && \
  curl -fsSL -o "$PB_FILE" "$PB_REL/download/v$VERSION/protoc-$VERSION-linux-$(if [ "$BUILDARCH" = "amd64" ]; then echo "x86_64"; else echo "aarch_64"; fi).zip"  && \
  unzip "$PB_FILE" -d /usr/local && \
  rm -f "$PB_FILE"

## Build the operator

WORKDIR /go/src/github.com/gravitational/teleport

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# We have to copy the API before `go mod download` because go.mod has a replace directive for it
COPY api/ api/

# Download and Cache dependencies before building and copying source
# This will prevent re-downloading the operator's dependencies if they have not changed as this
# `run` layer will be cached
RUN go mod download

COPY *.go ./
COPY lib/ lib/
COPY gen/ gen/
COPY entitlements/ entitlements/
COPY integrations/lib/embeddedtbot/ integrations/lib/embeddedtbot/
COPY integrations/operator/apis/ integrations/operator/apis/
COPY integrations/operator/controllers/ integrations/operator/controllers/
COPY integrations/operator/main.go integrations/operator/main.go
COPY integrations/operator/namespace.go integrations/operator/namespace.go
COPY integrations/operator/config.go integrations/operator/config.go

# Compiler package should use host-triplet-agnostic name (i.e. "x86-64-linux-gnu-gcc" instead of "gcc")
#  in most cases, to avoid issues on systems with multiple versions of gcc (i.e. buildboxes)
# TARGETOS and TARGETARCH are provided by Docker/buildx, but must be explicitly listed here
ARG COMPILER_NAME
ARG TARGETOS
ARG TARGETARCH

# Build the program
# CGO is required for github.com/gravitational/teleport/lib/system
RUN echo "Targeting $TARGETOS/$TARGETARCH with CC=$COMPILER_NAME" && \
    CGO_ENABLED=1 CC=$COMPILER_NAME GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -tags "kustomize_disable_go_plugin_support" -a -o /go/bin/teleport-operator github.com/gravitational/teleport/integrations/operator

# Create the image with the build operator on the $TARGETPLATFORM
# TARGETPLATFORM is provided by Docker/buildx
FROM --platform=$TARGETPLATFORM $BASE_IMAGE
WORKDIR /
COPY --from=builder /go/bin/teleport-operator .

ENTRYPOINT ["/teleport-operator"]
