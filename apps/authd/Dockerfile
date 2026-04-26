FROM rust:1.82-bookworm AS builder
WORKDIR /workspace

COPY Cargo.toml rust-toolchain.toml ./
COPY apps/authd/Cargo.toml apps/authd/Cargo.toml
COPY crates/localzet-auth-core/Cargo.toml crates/localzet-auth-core/Cargo.toml
COPY crates/localzet-config/Cargo.toml crates/localzet-config/Cargo.toml
COPY crates/localzet-storage/Cargo.toml crates/localzet-storage/Cargo.toml
COPY crates/localzet-domain/Cargo.toml crates/localzet-domain/Cargo.toml
COPY crates/localzet-audit/Cargo.toml crates/localzet-audit/Cargo.toml
COPY crates/localzet-crypto/Cargo.toml crates/localzet-crypto/Cargo.toml
COPY crates/localzet-policy/Cargo.toml crates/localzet-policy/Cargo.toml
COPY deploy deploy
COPY db db
COPY apps apps
COPY crates crates

RUN cargo build --release -p authd

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home localzet
WORKDIR /app
COPY --from=builder /workspace/target/release/authd /usr/local/bin/authd
COPY --from=builder /workspace/deploy/keys /app/keys
USER localzet
EXPOSE 8080
CMD ["/usr/local/bin/authd"]
