.PHONY: fmt lint test run check

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

check:
	cargo check --workspace

run:
	cargo run -p authd
