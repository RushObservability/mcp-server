# Build a static-ish release binary, then copy it into a minimal non-root image.
FROM rust:1.88-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY contracts ./contracts
RUN cargo build --locked --release && strip target/release/rush-mcp

FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:eaa0c377a38e4c67f4192fd5fe9d24d39d51c4531613d97731537f9d33460ae4
COPY --from=build --chown=65532:65532 /src/target/release/rush-mcp /usr/local/bin/rush-mcp
USER 65532:65532
# stdio by default; use `--transport http --listen 0.0.0.0:8090` for HTTP.
ENTRYPOINT ["/usr/local/bin/rush-mcp"]
