---
name: azoth-bytecode-review
description: Investigate Azoth changes by generating deployment bytecode, inspecting instructions, and testing EVM behavior on base and head revisions.
---

# Azoth review recipe

This is an opt-in recipe. Copy it into Azoth as `.github/ai-review/azoth.md` and add that path to `instruction_files` in the target branch's `.github/ai-review/config.json`. Keep other configured instructions. Do not automatically apply this recipe to unrelated repositories.

Commands and limitations below were checked against Azoth source on 2026-10-06. They have not been validated by a complete local build. Recheck command definitions when the PR changes the CLI. Azoth transforms existing EVM creation/runtime bytecode; it does not compile Solidity itself.

## Environment and trustworthy evidence

- Work in disposable `/workspace/base` and `/workspace/head` copies. Read their commits and gitlinks from `/control/snapshots.json`. Write investigation artifacts under `/output/azoth`. Files there are temporary: this workflow exports the structured report and command transcripts, not arbitrary generated files. Include a minimal textual reproduction and relevant observed output in the finding or transcript so another engineer can reproduce it.
- Both revisions need the same Rust toolchain for a controlled comparison. The inspected `rust-toolchain.toml` selects Rust 1.90.0 with rustfmt and clippy. Record any deliberate toolchain difference required by the PR.
- Building the CLI requires the pinned Escrow submodule artifacts even when using only the Counter fixture: `fuzz.rs` embeds them at compile time. Cargo also fetches locked crates and the Heimdall git dependency. Missing dependencies are an incomplete check, not a pass.
- Full `azoth-tests` builds additionally require Z3 development headers/library and libclang for its binding build. The core, transform, and CLI test selection below avoids the verification crate. Committed hex fixtures do not require solc, Foundry, an RPC endpoint, a wallet, or real funds.
- Do not use `examples/run_escrow.sh`: it updates a submodule to a moving branch. The example's functional-equivalence function returns `Ok(true)` without doing the comparison. Neither its success banner nor the SMT crate proves equivalence. Treat the formal-verification implementation as unfinished.
- `--emit` reports size-derived gas estimates, not measured EVM execution gas. Distinguish those estimates from REVM measurements. A successful deployment check is not a transaction-behavior equivalence check.

## Materialize the pinned public dependency

The snapshot export omits `.git` and submodule contents. The metadata schema is `{base:{commit,gitlinks},head:{commit,gitlinks}}`. Resolve each revision's recorded gitlink using the fixed public Escrow URL. Do not execute a PR-controlled `.gitmodules` URL or fetch a moving branch instead of the recorded commit.

```bash
node --input-type=module <<'NODE'
import { readFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
const snapshots = JSON.parse(readFileSync('/control/snapshots.json', 'utf8'));
for (const revision of ['base', 'head']) {
  const sha = snapshots[revision].gitlinks['examples/escrow-bytecode'];
  if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error(`Missing Escrow pin for ${revision}`);
  const destination = `/workspace/${revision}/examples/escrow-bytecode`;
  mkdirSync(destination, { recursive: true });
  const git = args => execFileSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', ...args], { stdio: 'inherit' });
  git(['init', destination]);
  git(['-C', destination, 'remote', 'add', 'origin', 'https://github.com/MiragePrivacy/escrow']);
  git(['-C', destination, 'fetch', '--depth=1', 'origin', sha]);
  git(['-C', destination, 'checkout', '--detach', sha]);
}
NODE
```

Run this once per fresh sandbox. If the PR intentionally moves/removes the dependency or changes its layout, inspect that change and adapt explicitly. Keep the base Escrow fixtures as common input to both binaries below, then separately test any new head fixtures. Record both dependency pins.

## Build and establish existing coverage

Run the following in each revision's directory, replacing `base` with `head` for the second run. Keep their target directories and logs separate. A compilation failure does not prevent independent source investigation; report which revision failed and why.

```bash
mkdir -p /output/azoth/base /output/azoth/head
cd /workspace/base
export RUSTUP_TOOLCHAIN=1.90.0
export CARGO_TARGET_DIR=/workspace/target-base
rustc --version > /output/azoth/base/toolchain.txt
cargo --version >> /output/azoth/base/toolchain.txt
cargo build --locked --release --bin azoth > /output/azoth/base/build.log 2>&1
cargo test --locked --release -p azoth-core -p azoth-transform -p azoth-cli > /output/azoth/base/unit-tests.log 2>&1
cargo test --locked --release -p azoth-tests e2e:: -- --nocapture > /output/azoth/base/evm-tests.log 2>&1
```

Inspect the test summary, including executed and filtered counts. Existing EVM tests include `test_obfuscated_counter_deploys_and_counts`, `test_obfuscated_function_calls`, per-transform deployment cases, and `test_same_seed_produces_same_deployed_runtime`. Some use random seeds; preserve a failing seed or add a fixed-seed reproducer before attributing a difference to the PR.

For constructor changes, `cargo test --locked --release -p azoth-transform constructor_args::tests:: -- --nocapture` exercises masking, deterministic output, 64 fixed-RNG argument/length cases, immutable initialization, and oversize rejection. The full-pipeline test checks selected immutable values; it does not establish equivalence for arbitrary transactions.

## Generate bytecode from identical inputs

The CLI requires a full 32-byte hex seed: 64 hex digits, optionally prefixed by `0x`. The following uses one explicit seed and pass list on both revisions and repeats each run. No TUI or human interaction is needed.

```bash
set -euo pipefail
review_seed=0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
review_passes=arithmetic_chain,push_split,slot_shuffle,string_obfuscate
for revision in base head; do
  review_binary="/workspace/target-$revision/release/azoth"
  for attempt in 1 2; do
    review_prefix="/output/azoth/$revision/counter-$attempt"
    "$review_binary" obfuscate \
      -D /workspace/base/tests/bytecode/counter/counter_deployment.hex \
      -R /workspace/base/tests/bytecode/counter/counter_runtime.hex \
      --seed "$review_seed" --passes "$review_passes" \
      --emit "$review_prefix.metrics.json" --emit-debug "$review_prefix.trace.json" \
      > "$review_prefix.stdout" 2> "$review_prefix.stderr"
    node --input-type=module - "$review_prefix" <<'NODE'
import { readFileSync, writeFileSync } from 'node:fs';
const prefix = process.argv[2];
const bytecode = readFileSync(`${prefix}.stdout`, 'utf8').trim().split(/\r?\n/).at(-1);
if (!/^(?:0x)?(?:[a-fA-F0-9]{2})+$/.test(bytecode)) throw new Error('Missing final bytecode output');
writeFileSync(`${prefix}.hex`, `${bytecode}\n`);
NODE
  done
  cmp "/output/azoth/$revision/counter-1.hex" "/output/azoth/$revision/counter-2.hex"
  "$review_binary" decode -D "/output/azoth/$revision/counter-1.hex" \
    > "/output/azoth/$revision/counter.asm"
done
sha256sum /output/azoth/base/counter-1.hex /output/azoth/head/counter-1.hex
```

The final stdout line is deployment bytecode in the inspected CLI; `--emit` and `--emit-debug` do not contain a ready-to-deploy bytecode file. The pipeline also inserts the function-dispatcher transform when it detects a dispatcher. The explicit pass list above matches the inspected CLI's actual `DEFAULT_PASSES`; its README's claimed default of `shuffle` is stale. Test any changed pass in isolation and in the production combination, recording its exact spelling and order.

Same-revision, same-input repeats must be deterministic. A base/head bytecode difference can be intentional: explain it using the diff, trace, and execution tests. Do not require byte-for-byte identity across versions of an obfuscator, or treat a hash match on one fixture as security evidence.

For the original Counter CFG, use `azoth cfg -D /workspace/base/tests/bytecode/counter/counter_deployment.hex -R /workspace/base/tests/bytecode/counter/counter_runtime.hex --output /output/azoth/counter-original.dot`. `decode` already gives instruction text without Graphviz. Do not pass the original runtime as the authoritative runtime boundary for transformed creation code. To inspect transformed runtime/CFG, obtain `ObfuscationResult.obfuscated_runtime` from the Rust API, or capture the runtime returned by REVM deployment; constructor-patched deployed runtime can differ from the template.

## Inspect constructor handling and EVM behavior

For an Escrow experiment, use the base pin's `examples/escrow-bytecode/artifacts/erc20_deployment.hex` and `erc20_runtime.hex`. Supply either a creation payload that already contains constructor arguments or `--constructor-args <ABI_HEX>`, never both. Derive the ABI layout from that exact pinned contract and the test helpers; do not reuse an assumed layout after a dependency update.

For each relevant reproducer, compare original and transformed execution from equivalent REVM initial state: deployment success/revert, returned runtime, storage and balances, return/revert data, logs, calls, and measured gas as appropriate. When dispatcher rewriting changes selectors, map each original selector to its token using `ObfuscationResult.selector_mapping`; sending unchanged ABI selectors to transformed code is not a valid equivalence test. Consult `tests/src/e2e/test_counter.rs` and `tests/src/e2e/escrow.rs` for the current calldata helpers.

For a suspected bug, add a temporary fixed-input test in the disposable checkout that calls the actual Rust APIs. Capture its input bytecode, seed, pass list, constructor payload, expected behavior, and observed outcome. Run that reproducer on base and head with the same fixture and toolchain. Preserve the test patch under `/output/azoth`; do not alter the PR branch. Test rejection paths as well as successful execution. Pay attention to arithmetic overflow, stack effects, jump destinations, offset relocation, constructor copies, immutable references, and contract-size limits when the diff touches them.

## Bounded fuzz investigation

After a working build, run a bounded campaign in each revision. Set both a time and iteration bound, choose worker count for the runner, and use a fresh crash directory.

```bash
/workspace/target-head/release/azoth fuzz --iterations 1000 --duration 120 --jobs 2 \
  --check-deploy --crash-dir /output/azoth/head/crashes \
  > /output/azoth/head/fuzz.log 2>&1
rg 'Iterations:|Successes:|Errors:|Deployment mismatches:|Unique crashes saved:' /output/azoth/head/fuzz.log
rg --files /output/azoth/head/crashes
```

The final `rg` can exit 1 when there are no files; that is separate from the fuzzer's outcome. The inspected fuzzer can exit zero after finding failures. Require actual iterations, inspect error/mismatch/crash counts and saved JSON, and replay findings on both binaries using `azoth fuzz --check-deploy replay <crash.json>`. Replay also reports its outcome in stdout, so inspect the result text. Random campaigns across two revisions do not share the same corpus; replaying the same saved case provides the controlled comparison.

`--check-deploy` checks that a transformed payload deploys when the original deployed. It does not compare every resulting runtime, storage value, transaction outcome, or gas cost. Supplement it with the focused differential test your hypothesis needs.

## Report

Attach only actionable PR-introduced findings to inline review locations. Include the smallest reproduction, the exact observed consequence, and the commands needed to reproduce it. Keep a short account of the affected design/invariants. State missing checks, build/network/time limits, and nondeterministic cases explicitly. Do not call the review complete when required generation or execution checks could not run. Never present placeholder verification, sample coverage, successful deployment, or obfuscation metrics as a proof of soundness or privacy.

Source checks: [CLI generation](https://github.com/MiragePrivacy/azoth/blob/master/crates/cli/src/commands/obfuscate.rs), [CLI defaults](https://github.com/MiragePrivacy/azoth/blob/master/crates/cli/src/commands/mod.rs), [seed validation](https://github.com/MiragePrivacy/azoth/blob/master/crates/core/src/seed.rs), [fuzz oracle](https://github.com/MiragePrivacy/azoth/blob/master/crates/cli/src/commands/fuzz.rs), [constructor tests](https://github.com/MiragePrivacy/azoth/blob/master/crates/transforms/src/constructor_args.rs), [EVM test helpers](https://github.com/MiragePrivacy/azoth/blob/master/tests/src/e2e/mod.rs), [report implementation](https://github.com/MiragePrivacy/azoth/blob/master/crates/transforms/src/obfuscator.rs).
