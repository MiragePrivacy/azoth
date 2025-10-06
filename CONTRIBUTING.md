# Contributing to Azoth

Thank you for your interest in improving Azoth! We're excited to have you join us in building the future of EVM bytecode obfuscation.

As Azoth is in early development, there are many opportunities to contribute at any level. Whether you're new to Rust, EVM internals, or are an experienced expert, we can use your help.

**No contribution is too small and all contributions are valued.**

This guide will help you get started. Don't let this guide intimidate you - it's here to help you navigate the process.

## Conduct

The Azoth project adheres to the [Rust Code of Conduct](https://github.com/rust-lang/rust/blob/master/CODE_OF_CONDUCT.md). This describes the minimum behavior expected from all contributors. Instances of violations of the Code of Conduct can be reported by contacting the project team at [g4titan1@gmail.com](mailto:g4titan1@gmail.com).


## Getting Started with Azoth

Since Azoth is in active development, the best way to get started is to:

1. **Read the README** to understand Azoth's philosophy and architecture
2. **Check open issues** for areas where help is needed
3. **Join the discussion** on existing issues or open new ones
4. **Experiment with the CLI** to understand how Azoth transforms bytecode

## Contributing in Issues

For any issue, there are fundamentally three ways to contribute:

1. **Opening issues for discussion**: If you've discovered a bug, have a feature request, or want to discuss obfuscation techniques, you can create a new issue in the [Azoth issue tracker](https://github.com/MiragePrivacy/Azoth/issues/).

2. **Helping to triage issues**: Provide test cases, suggest solutions, or help categorize issues with appropriate labels.

3. **Helping to resolve issues**: Submit Pull Requests that address open issues or improve the codebase.


### Asking for General Help

If you have questions after reviewing the documentation, feel free to open an issue with the discussion label or comment on relevant issues. We encourage questions - they often lead to documentation improvements that help future contributors.


### Submitting a Bug Report

When reporting bugs, please include:
- A clear description of the expected vs actual behavior
- The bytecode that triggers the issue (if applicable)
- Steps to reproduce the problem
- Your environment (OS, Rust version, etc.)

For bytecode-related issues, minimal test cases are invaluable. If possible, provide the smallest bytecode snippet that demonstrates the problem.

## Pull Requests

Pull Requests are how we make concrete changes to Azoth's code, documentation, and tests.

### Before You Start

For significant changes:
1. **Open an issue first** to discuss your proposal
2. **Check if someone else is working on it** to avoid duplicate effort
3. **Consider the architectural implications** - Azoth's three-stage pipeline should be respected

### Development Setup

```bash
# Clone the repository
git clone https://github.com/MiragePrivacy/azoth
cd azoth

# Build the project
cargo bb  # or cargo build --workspace

# Run tests
cargo tt  # or cargo nextest run --workspace

# Run clippy
cargo cc  # or cargo clippy --workspace
```

### Code Style and Standards

- Follow Rust's standard formatting: `cargo fmt --all`
- Ensure clippy passes: `cargo clippy --workspace -- -D warnings`
- Add tests for new functionality
- Document public APIs with rustdoc comments
- Use meaningful commit messages following [Conventional Commits](https://www.conventionalcommits.org/)

### Areas of Focus for Contributors

Given Azoth's current development status, here are key areas where contributions are especially welcome:

#### 1. **Obfuscation Transforms**
- New transform passes (e.g., arithmetic obfuscation, control flow flattening)
- Improvements to existing transforms
- Transform composition strategies

#### 2. **Analysis and Metrics**
- Enhanced potency measurements
- Resilience testing against decompilers
- Gas cost optimization strategies

#### 3. **Formal Verification**
- Semantic equivalence proofs
- Invariant checking
- Safety guarantees

#### 4. **Documentation**
- Architecture deep-dives
- Transform technique explanations
- Usage examples and tutorials

#### 5. **Testing and Benchmarks**
- Edge case identification
- Performance benchmarking
- Real-world contract testing

Thank you for contributing to Azoth! Your efforts help make Ethereum contracts more private while maintaining the network's integrity.
