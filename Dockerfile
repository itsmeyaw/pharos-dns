# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM rust:1.99.1-bookworm AS builder
ARG BUILDARCH
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang xz-utils \
    && rm -rf /var/lib/apt/lists/*
RUN case "$BUILDARCH" in \
      amd64) arch=x86_64; sha=24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c ;; \
      arm64) arch=aarch64; sha=f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b ;; \
      *) exit 1 ;; \
    esac \
    && curl -fsSL "https://ziglang.org/download/0.14.1/zig-${arch}-linux-0.14.1.tar.xz" -o /tmp/zig.tar.xz \
    && echo "$sha  /tmp/zig.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/zig.tar.xz -C /opt \
    && rm /tmp/zig.tar.xz \
    && ln -s "/opt/zig-${arch}-linux-0.14.1/zig" /usr/local/bin/zig
RUN cargo install cargo-zigbuild --version 0.20.1 --locked
WORKDIR /src
COPY . .
ARG TARGETARCH
ARG VERSION=0.1.0
# Zig's linker rejects Rust's A53 erratum flag; rust-lld applies the fix.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    actual="$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version = "\([^"]*\)"/\1/p;}' Cargo.toml)" \
    && test "$VERSION" = "$actual" \
    || { echo "VERSION must match Cargo workspace version" >&2; exit 1; }; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl; \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS='-C linker=rust-lld -C linker-flavor=ld.lld -C link-arg=--fix-cortex-a53-843419'; \
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && rustup target add "$target" \
    && cargo zigbuild --locked --release -p pharos --target "$target" \
    && cp "target/$target/release/pharos" /pharos

FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS capabilities
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /pharos /pharos
RUN setcap cap_net_bind_service=+ep /pharos

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=0.1.0
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/itsmeyaw/pharos-dns" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=capabilities /pharos /usr/bin/pharos
USER 65532:65532
WORKDIR /
EXPOSE 53 53/udp
ENTRYPOINT ["/usr/bin/pharos"]
