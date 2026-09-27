#!/usr/bin/env bash
# Shared tool pins for local development and CI (Linux x86_64).
set -euo pipefail
install_dir="${1:-$HOME/.local}"
mkdir -p "$install_dir/bin"

curl -fsSL https://github.com/rust-lang/mdBook/releases/download/v0.5.4/mdbook-v0.5.4-x86_64-unknown-linux-gnu.tar.gz |
  tar -xz -C "$install_dir/bin" mdbook
curl -fsSL https://github.com/badboy/mdbook-mermaid/releases/download/v0.17.0/mdbook-mermaid-v0.17.0-x86_64-unknown-linux-gnu.tar.gz |
  tar -xz -C "$install_dir/bin" mdbook-mermaid
# Released i18n-helpers versions use mdBook 0.4. Pin the mdBook 0.5 migration.
cargo install --git https://github.com/google/mdbook-i18n-helpers.git \
  --rev d54121c6732fa33926d929d942955d0e6e5223b1 --locked \
  --root "$install_dir" mdbook-i18n-helpers
printf 'Installed manual tools. Add %s/bin to PATH.\n' "$install_dir"
