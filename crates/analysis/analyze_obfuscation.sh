#!/bin/bash

set -euo pipefail

# Script to analyze byte sequence preservation in obfuscated bytecode.
# Uses only the default dispatcher transform plus the shuffle pass when generating samples.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEFAULT_BYTECODE="$REPO_ROOT/examples/escrow-bytecode/artifacts/runtime_bytecode.hex"

usage() {
    echo "Usage: $0 <num_iterations> [bytecode_file]"
    echo ""
    echo "Arguments:"
    echo "  num_iterations  Number of obfuscated versions to generate and analyze"
    echo "  bytecode_file   Path to bytecode file (default: $DEFAULT_BYTECODE)"
    echo ""
    echo "Example:"
    echo "  $0 50"
    echo "  $0 100 path/to/bytecode.hex"
    exit 1
}

# Check arguments
if [ $# -lt 1 ]; then
    usage
fi

NUM_ITERATIONS="$1"
INPUT_PATH="${2:-$DEFAULT_BYTECODE}"

# Resolve bytecode path to absolute form
if [[ "$INPUT_PATH" == /* ]]; then
    BYTECODE_FILE="$INPUT_PATH"
else
    if command -v realpath >/dev/null 2>&1; then
        BYTECODE_FILE="$(realpath -m "$PWD/$INPUT_PATH")"
    else
        BYTECODE_FILE="$(python3 - <<'PYTHON_SCRIPT' "$PWD" "$INPUT_PATH"
import os
import sys

cwd, path = sys.argv[1], sys.argv[2]
joined = os.path.join(cwd, path)
print(os.path.abspath(joined))
PYTHON_SCRIPT
)"
    fi
fi

# Validate number of iterations
if ! [[ "$NUM_ITERATIONS" =~ ^[0-9]+$ ]] || [ "$NUM_ITERATIONS" -lt 1 ]; then
    echo "Error: num_iterations must be a positive integer"
    exit 1
fi

# Validate bytecode file exists
if [ ! -f "$BYTECODE_FILE" ]; then
    echo "Error: Bytecode file not found: $BYTECODE_FILE"
    exit 1
fi

echo "=========================================="
echo "Obfuscation Analysis Script"
echo "=========================================="
echo "Iterations: $NUM_ITERATIONS"
echo "Bytecode:   $BYTECODE_FILE"
echo "Transforms: function_dispatcher (default) + shuffle"
echo ""

# Create temporary directory for analysis
WORK_DIR=$(mktemp -d -t azoth-analysis-XXXXXX)
trap "rm -rf $WORK_DIR" EXIT

echo "Working directory: $WORK_DIR"
echo ""

# Restrict transforms to shuffle plus default dispatcher
TRANSFORM_PASSES="shuffle"
TRANSFORM_LABEL="function_dispatcher (default) + shuffle"

# Prepare original bytecode
ORIGINAL_COPY="$WORK_DIR/original.hex"
cp "$BYTECODE_FILE" "$ORIGINAL_COPY"
ORIGINAL_LENGTH_BYTES=$(python3 - <<'PYTHON_SCRIPT' "$ORIGINAL_COPY"
import sys
from pathlib import Path

hex_content = Path(sys.argv[1]).read_text().strip()
if hex_content.startswith("0x"):
    hex_content = hex_content[2:]
hex_content = "".join(hex_content.split())
print(len(bytes.fromhex(hex_content)) if hex_content else 0)
PYTHON_SCRIPT
)
echo "Original bytecode length: ${ORIGINAL_LENGTH_BYTES} bytes"
echo ""

# Build the CLI if needed
echo "Building azoth CLI..."
cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --bin azoth --release --quiet
AZOTH_BIN="$REPO_ROOT/target/release/azoth"

# Generate obfuscated versions
echo "Generating $NUM_ITERATIONS obfuscated versions..."
echo ""

OBFUSCATED_DIR="$WORK_DIR/obfuscated"
mkdir -p "$OBFUSCATED_DIR"

# Track seeds used
SEEDS_FILE="$WORK_DIR/seeds.txt"
: > "$SEEDS_FILE"

MAX_ATTEMPTS=5

for i in $(seq 1 "$NUM_ITERATIONS"); do
    attempt=1
    while true; do
        RAW_SEED=$(python3 - <<'PYTHON_SCRIPT'
import secrets

print(secrets.token_hex(32))
PYTHON_SCRIPT
)
        SEED_DISPLAY="0x${RAW_SEED}"
        echo -n "[$i/$NUM_ITERATIONS] Attempt ${attempt}: obfuscating with seed ${SEED_DISPLAY} (passes: ${TRANSFORM_PASSES})... "

        set +e
        OUTPUT=$(RUST_LOG=error "$AZOTH_BIN" obfuscate --passes "$TRANSFORM_PASSES" --seed "$RAW_SEED" "$BYTECODE_FILE" 2>&1)
        STATUS=$?
        set -e

        if [ "$STATUS" -ne 0 ]; then
            echo "failed"
            if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
                echo "Error: Obfuscation failed after ${MAX_ATTEMPTS} attempts for iteration ${i}" >&2
                echo "$OUTPUT" >&2
                exit 1
            fi
            attempt=$((attempt + 1))
            continue
        fi

        HEX_LINE=$(printf "%s\n" "$OUTPUT" | awk '/^0x[0-9a-fA-F]+$/ { hex=$0 } END { if (hex) print hex }' | tr -d '\r')

        if [[ "$HEX_LINE" =~ ^0x[0-9a-fA-F]+$ ]]; then
            printf "%s\n" "$HEX_LINE" > "$OBFUSCATED_DIR/${i}.hex"
            printf "%s\n" "$SEED_DISPLAY" >> "$SEEDS_FILE"
            echo "done (${#HEX_LINE} chars)"
            break
        fi

        echo "unexpected output format"
        if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
            echo "Error: Unexpected CLI output after ${MAX_ATTEMPTS} attempts for iteration ${i}" >&2
            echo "$OUTPUT" >&2
            exit 1
        fi
        attempt=$((attempt + 1))
    done
done

echo ""
echo "Analysis phase..."
echo ""

# Export paths for Python script
export WORK_DIR
export SEEDS_FILE
export TRANSFORM_LABEL
REPORT_PATH="$SCRIPT_DIR/obfuscation_analysis_report.md"
export REPORT_PATH

# Python analysis script
python3 - <<'PYTHON_SCRIPT'
import os
import math
from pathlib import Path
from collections import Counter
from difflib import SequenceMatcher
from statistics import mean, median, stdev
from typing import List, Tuple

WORK_DIR = os.environ['WORK_DIR']
SEEDS_FILE = Path(os.environ['SEEDS_FILE'])
TRANSFORM_LABEL = os.environ.get('TRANSFORM_LABEL', 'function_dispatcher (default) + shuffle')
REPORT_PATH = os.environ.get('REPORT_PATH', 'obfuscation_analysis_report.md')

def load_bytecode(filepath: str) -> bytes:
    """Load bytecode from hex file and convert to bytes."""
    with open(filepath, 'r') as f:
        hex_str = f.read().strip()
    # Remove 0x prefix if present
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)

def find_longest_common_subsequence(original: bytes, obfuscated: bytes) -> Tuple[int, bytes]:
    """
    Find the longest contiguous byte sequence that appears in both original and obfuscated.
    Uses SequenceMatcher for reasonable performance on long byte strings.
    Returns (length, sequence).
    """
    if not original or not obfuscated:
        return 0, b""

    matcher = SequenceMatcher(None, original, obfuscated, autojunk=False)
    match = matcher.find_longest_match(0, len(original), 0, len(obfuscated))

    if match.size == 0:
        return 0, b""

    start = match.a
    end = start + match.size
    return match.size, original[start:end]

def extract_all_ngrams(data: bytes, n: int) -> List[bytes]:
    """Extract all n-byte sequences from data."""
    return [data[i:i+n] for i in range(len(data) - n + 1)]

def calculate_ngram_diversity(bytecodes: List[bytes], n: int) -> float:
    """Calculate percentage of unique n-grams across all bytecodes."""
    all_ngrams = []
    for bytecode in bytecodes:
        all_ngrams.extend(extract_all_ngrams(bytecode, n))

    if not all_ngrams:
        return 0.0

    unique_count = len(set(all_ngrams))
    total_count = len(all_ngrams)
    return (unique_count / total_count) * 100

def percentile(values: List[int], percentile_value: float) -> float:
    """Compute percentile with linear interpolation."""
    if not values:
        return 0.0

    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])

    k = (len(ordered) - 1) * (percentile_value / 100)
    lower_index = math.floor(k)
    upper_index = math.ceil(k)

    lower_value = ordered[lower_index]
    upper_value = ordered[upper_index]

    if lower_index == upper_index:
        return float(lower_value)

    fraction = k - lower_index
    return float(lower_value + (upper_value - lower_value) * fraction)

def bytes_to_hex(b: bytes) -> str:
    """Convert bytes to hex string for display."""
    return b.hex()

def main():
    # Load original bytecode
    original = load_bytecode(f"{WORK_DIR}/original.hex")

    # Load all obfuscated versions
    obfuscated_dir = Path(f"{WORK_DIR}/obfuscated")
    obfuscated_files = sorted(obfuscated_dir.glob("*.hex"), key=lambda x: int(x.stem))

    print(f"Analyzing {len(obfuscated_files)} obfuscated versions...")
    print()

    # Collect data
    sequence_lengths: List[int] = []
    sequence_counter: Counter[bytes] = Counter()
    all_obfuscated: List[bytes] = []

    for i, obf_file in enumerate(obfuscated_files, 1):
        obfuscated = load_bytecode(str(obf_file))
        all_obfuscated.append(obfuscated)

        # Find longest common sequence
        length, sequence = find_longest_common_subsequence(original, obfuscated)
        sequence_lengths.append(length)
        if length > 0 and sequence:
            sequence_counter[sequence] += 1

        if i % 10 == 0:
            print(f"Processed {i}/{len(obfuscated_files)}...")

    print()
    print("Calculating statistics...")
    print()

    # Calculate statistics
    if sequence_lengths:
        avg_length = mean(sequence_lengths)
        median_length = median(sequence_lengths)
        stdev_length = stdev(sequence_lengths) if len(sequence_lengths) > 1 else 0.0
        p25 = percentile(sequence_lengths, 25)
        p75 = percentile(sequence_lengths, 75)
        p95 = percentile(sequence_lengths, 95)
        min_length = min(sequence_lengths)
        max_length = max(sequence_lengths)
    else:
        avg_length = median_length = stdev_length = 0.0
        p25 = p75 = p95 = 0.0
        min_length = max_length = 0

    # Top 10 most repeated sequences
    top_sequences = sequence_counter.most_common(10)

    # Seed information
    seeds_used = [line.strip() for line in SEEDS_FILE.read_text().splitlines() if line.strip()]
    unique_seed_count = len(set(seeds_used))

    # N-gram diversity
    print("Calculating n-gram diversity...")
    ngram2_diversity = calculate_ngram_diversity(all_obfuscated, 2)
    ngram4_diversity = calculate_ngram_diversity(all_obfuscated, 4)
    ngram8_diversity = calculate_ngram_diversity(all_obfuscated, 8)

    # Generate markdown report
    report_path = REPORT_PATH

    with open(report_path, 'w') as f:
        f.write("# Obfuscation Analysis Report\n\n")
        f.write(f"**Generated:** {os.popen('date').read().strip()}  \n")
        f.write(f"**Iterations:** {len(obfuscated_files)}  \n")
        f.write(f"**Original Bytecode Length:** {len(original)} bytes  \n")
        f.write(f"**Transforms Used:** {TRANSFORM_LABEL}  \n")
        f.write("\n")

        f.write("## Summary Statistics\n\n")
        f.write("This analysis measures the longest contiguous byte sequence from the original bytecode ")
        f.write("that remains present in each obfuscated version, providing insights into how effectively ")
        f.write("the obfuscation transforms modify the bytecode structure.\n\n")

        f.write("### Sequence Length Metrics\n\n")
        f.write(f"- **Average Length:** {avg_length:.2f} bytes\n")
        f.write(f"- **Median Length:** {median_length:.2f} bytes\n")
        f.write(f"- **Standard Deviation:** {stdev_length:.2f} bytes\n")
        f.write(f"- **Minimum Length:** {min_length} bytes\n")
        f.write(f"- **Maximum Length:** {max_length} bytes\n")
        f.write("\n")

        f.write("### Distribution Percentiles\n\n")
        f.write(f"- **25th Percentile:** {p25:.2f} bytes\n")
        f.write(f"- **75th Percentile:** {p75:.2f} bytes\n")
        f.write(f"- **95th Percentile:** {p95:.2f} bytes\n")
        f.write("\n")

        f.write("## Top 10 Most Repeated Sequences\n\n")
        f.write("These sequences appear most frequently across all obfuscated versions, ")
        f.write("indicating bytecode patterns that persist through obfuscation.\n\n")
        if top_sequences:
            f.write("| Rank | Length (bytes) | Frequency | Sequence (hex) |\n")
            f.write("|------|----------------|-----------|----------------|\n")

            for rank, (seq, count) in enumerate(top_sequences, 1):
                hex_seq = bytes_to_hex(seq)
                # Truncate long sequences for display
                display_seq = hex_seq if len(hex_seq) <= 40 else f"{hex_seq[:37]}..."
                f.write(f"| {rank} | {len(seq)} | {count} | `{display_seq}` |\n")

            f.write("\n")
        else:
            f.write("_No repeated sequences found across obfuscations._\n\n")

        f.write("## Seed Summary\n\n")
        f.write(f"- **Total seeds generated:** {len(seeds_used)}\n")
        f.write(f"- **Unique seeds:** {unique_seed_count}\n")
        if seeds_used:
            preview = [f"`{seed}`" for seed in seeds_used[:5]]
            f.write(f"- **Sample seeds:** {', '.join(preview)}\n")
            if len(seeds_used) > 5:
                f.write(f"- _...and {len(seeds_used) - 5} more_\n")
        f.write("\n")

        f.write("## N-gram Diversity Analysis\n\n")
        f.write("Measures the percentage of unique byte sequences of various lengths across all ")
        f.write("obfuscated versions. Higher diversity indicates more varied bytecode patterns.\n\n")
        f.write(f"- **2-byte sequences:** {ngram2_diversity:.2f}% unique\n")
        f.write(f"- **4-byte sequences:** {ngram4_diversity:.2f}% unique\n")
        f.write(f"- **8-byte sequences:** {ngram8_diversity:.2f}% unique\n")
        f.write("\n")

        f.write("## Distribution Histogram\n\n")
        f.write("Distribution of longest common sequence lengths across all iterations:\n\n")

        # Create histogram
        hist_buckets = {}
        if sequence_lengths:
            span = max_length - min_length
            bucket_size = max(1, math.ceil((span + 1) / 10))

            for length in sequence_lengths:
                bucket = ((length - min_length) // bucket_size) * bucket_size + min_length
                hist_buckets[bucket] = hist_buckets.get(bucket, 0) + 1

            max_count = max(hist_buckets.values())
            f.write("```\n")
            for bucket_start in sorted(hist_buckets.keys()):
                count = hist_buckets[bucket_start]
                bucket_end = bucket_start + bucket_size - 1
                bar = '█' * max(1, int((count / max_count) * 50))
                f.write(f"{bucket_start:4d}-{bucket_end:4d} bytes | {bar} ({count})\n")
            f.write("```\n")
        else:
            f.write("_No data available to build histogram._\n")
        f.write("\n")

        f.write("## Interpretation\n\n")

        # Add interpretation based on results
        preservation_ratio = (avg_length / len(original)) * 100 if original else 0.0
        f.write(f"The average longest common sequence represents **{preservation_ratio:.2f}%** ")
        f.write("of the original bytecode length. ")

        if preservation_ratio < 10:
            f.write("This indicates strong obfuscation with minimal sequence preservation.\n")
        elif preservation_ratio < 25:
            f.write("This indicates moderate obfuscation with some sequence preservation.\n")
        else:
            f.write("This indicates weaker obfuscation with significant sequence preservation.\n")

        f.write("\n")

        if ngram8_diversity > 90:
            f.write("The high n-gram diversity suggests that obfuscation produces highly varied bytecode patterns ")
            f.write("across different seeds, which is desirable for defeating pattern-based analysis.\n")
        elif ngram8_diversity > 70:
            f.write("The moderate n-gram diversity suggests reasonable variation in obfuscated bytecode patterns.\n")
        else:
            f.write("The lower n-gram diversity suggests that obfuscation may produce similar patterns across ")
            f.write("different seeds, which could be exploited by analysts.\n")

        f.write("\n")
        f.write("---\n")
        f.write(f"*Analysis generated by Azoth obfuscator analysis script with {len(obfuscated_files)} iterations*\n")

    print(f"Report generated: {report_path}")
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Average longest sequence:  {avg_length:.2f} bytes ({preservation_ratio:.2f}% of original)")
    print(f"Median longest sequence:   {median_length:.2f} bytes")
    print(f"Standard deviation:        {stdev_length:.2f} bytes")
    if sequence_lengths:
        print(f"Range:                     {min_length}-{max_length} bytes")
    else:
        print("Range:                     N/A")
    print(f"Seeds generated:           {len(seeds_used)} (unique: {unique_seed_count})")
    print(f"Transforms used:           {TRANSFORM_LABEL}")
    print()
    print(f"2-byte n-gram diversity:   {ngram2_diversity:.2f}%")
    print(f"4-byte n-gram diversity:   {ngram4_diversity:.2f}%")
    print(f"8-byte n-gram diversity:   {ngram8_diversity:.2f}%")
    print("=" * 60)

if __name__ == '__main__':
    main()
PYTHON_SCRIPT

echo ""
echo "Analysis complete!"
echo "Report saved to: $REPORT_PATH"
