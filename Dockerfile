# Build a static-ish release binary, then copy it into a minimal non-root image.
FROM rust:1.88-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo build --locked --release && strip target/release/rush-mcp

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/rush-mcp /usr/local/bin/rush-mcp
USER nonroot
# stdio by default; use `--transport http --listen 0.0.0.0:8090` for HTTP.
ENTRYPOINT ["/usr/local/bin/rush-mcp"]
