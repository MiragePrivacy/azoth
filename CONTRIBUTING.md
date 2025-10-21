# Contributing to Azoth

Thank you for your interest in improving Azoth! We're excited to have you join us in building the future of EVM bytecode obfuscation.

As Azoth is in early development, there are many opportunities to contribute at any level. Whether you're new to Rust, EVM internals, or are an experienced expert, we can use your help.

## Conduct

The Azoth project adheres to the [Rust Code of Conduct](https://github.com/rust-lang/rust/blob/master/CODE_OF_CONDUCT.md). This describes the minimum behavior expected from all contributors. Instances of violations of the Code of Conduct can be reported by contacting the project team at [g4titan1@gmail.com](mailto:g4titan1@gmail.com).


## Getting Started with Azoth

Since Azoth is in active development, the best way to get started is to:

1. **Read the README** to understand Azoth's philosophy and architecture
2. **Check open issues** for areas where help is needed
3. **Join the discussion** on existing issues or open new ones
4. **Experiment with the CLI** to understand how Azoth transforms bytecode

## Contributing in Issues

If you've discovered a bug, have a feature request, or want to discuss obfuscation techniques, you can create a new issue in the [Azoth issue tracker](https://github.com/MiragePrivacy/Azoth/issues/).

### Development Setup

```bash
# Clone the repository
git clone https://github.com/MiragePrivacy/azoth
cd azoth

# Build the project
cargo bb  # or cargo build --all --all-features --release

# Run tests
cargo tt  # or cargo nextest run --release --all --no-fail-fast

# Run clippy
cargo cc  # or cargo clippy --all -- -D warnings
```

### Code Style and Standards

- Follow Rust's standard formatting: `cargo fmt --all`
- Ensure clippy passes: `cargo clippy --workspace -- -D warnings`
- Add tests for new functionality
- Document public APIs with rustdoc comments
- Use meaningful commit messages following [Conventional Commits](https://www.conventionalcommits.org/)

Thank you for contributing to Azoth! Your efforts help make Ethereum contracts more private while maintaining the network's integrity.
