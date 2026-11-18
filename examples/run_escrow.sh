#!/usr/bin/env bash

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

artifact_dir=escrow-bytecode/artifacts
if [[ ! -f "$artifact_dir/erc20_deployment.hex" || ! -f "$artifact_dir/erc20_runtime.hex" ]]; then
    git submodule update --init --recursive -- escrow-bytecode
fi

for artifact in erc20_deployment.hex erc20_runtime.hex; do
    if [[ ! -f "$artifact_dir/$artifact" ]]; then
        printf 'Escrow artifact not found: %s\n' "$artifact_dir/$artifact" >&2
        exit 1
    fi
done

cargo run --locked --release --bin azoth-examples
printf '\nReport saved to %s/mirage_report.json\n' "$PWD"
