# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Azoth is a research-grade toolchain for Ethereum smart-contract obfuscation. The project follows a three-stage pipeline:

**Repository**: https://github.com/MiragePrivacy/obfuscator

1. **Pre-processing/Analysis**: Isolate runtime bytecode and measure structure
2. **Obfuscation Passes**: Apply reversible transforms to raise analyst effort
3. **Re-assembly & Validation**: Splice segments back and validate equivalence

## Architecture

This is a Rust workspace with six main crates:

- **`crates/core/`**: Core functionality including bytecode decoder, encoder, section detector, bytecode stripper, and CFG-IR generation. The detection module includes section isolation (`detection/sections.rs`) and dispatcher pattern detection (`detection/dispatcher.rs`)
- **`crates/analysis/`**: Analysis utilities for measuring bytecode complexity and obfuscation quality through comprehensive metrics
- **`crates/transforms/`**: Obfuscation passes including opaque predicates, control flow shuffling, function dispatcher obfuscation, and jump address transformation. The `obfuscator.rs` module orchestrates all transforms
- **`crates/verification/`**: Formal verification engine providing mathematical proofs of semantic equivalence using Z3 SMT solver, plus practical testing with REVM. Supports multiple verification levels and generates cryptographic certificates
- **`crates/utils/`**: Shared utilities including deterministic seed generation and error types
- **`crates/cli/`**: Command-line interface (`azoth` binary) with subcommands for decode, strip, cfg, and obfuscate

### Additional Workspace Members
- **`tests/`**: Workspace-level integration and end-to-end tests organized by component (core, transforms, analysis, verification, e2e)
- **`examples/`**: Example contracts including escrow bytecode for testing and benchmarking

## Development Requirements

**Important**: This project uses Rust edition 2021 and standard stable toolchain:
```bash
cargo build
```

## Common Commands

### Build and Test

The project uses custom cargo aliases defined in `.cargo/config.toml`:

```bash
# Build all packages with release optimizations
cargo bb

# Run clippy on all packages (warnings treated as errors)
cargo cc

# Run all tests using cargo-nextest
cargo tt

# Standard cargo commands also work
cargo build
cargo test
cargo fmt
cargo clippy
```

**Note**: This project uses `cargo-nextest` as the test runner. Install it with:
```bash
cargo install cargo-nextest
```

### CLI Usage
```bash
# Build CLI binary
cargo build --bin azoth

# Decode bytecode to annotated assembly
cargo run --bin azoth -- decode <bytecode>

# Strip init/auxdata, output runtime hex
cargo run --bin azoth -- strip <bytecode>

# Generate and visualize CFG-IR
cargo run --bin azoth -- cfg <bytecode>

# Apply obfuscation transforms
cargo run --bin azoth -- obfuscate <bytecode>
```

### Input Formats
- Hex string: `0x608060405234801561001057600080fd5b50...`
- File path: `path/to/bytecode.hex`

## Code Style and Documentation Standards

### Rust Code Standards
The project follows strict Rust coding standards to ensure maintainability and consistency across the codebase.

**Formatting and Structure:**
- Standard rustfmt configuration
- Maximum line width of 100 characters
- Rust edition 2021
- Consistent indentation and spacing enforced by automated tools

**Documentation Requirements:**
All public APIs must include comprehensive rustdoc documentation. This is enforced by the `missing-docs` lint at the workspace level.

**Required Documentation Elements:**
- Module-level documentation explaining the purpose and scope of functionality
- Comprehensive documentation for all public functions, structs, enums, and traits
- Parameter descriptions with type constraints and expected ranges
- Return value documentation with error conditions
- Usage examples demonstrating typical API interactions
- Cross-references to related functionality where appropriate

**Documentation Style Guidelines:**
Write documentation in clear, professional prose rather than fragmented bullet points. The documentation should provide sufficient context for developers to understand not just how to use the API, but why certain design decisions were made and how the component fits into the larger system architecture.

**Example Documentation Pattern:**
```rust
/// Constructs a Control Flow Graph with Intermediate Representation from EVM bytecode.
///
/// This function performs the core transformation from linear bytecode instructions
/// into a structured graph representation that enables sophisticated analysis and
/// obfuscation transforms. The resulting CFG maintains semantic equivalence while
/// providing the structural information necessary for advanced code analysis.
///
/// The construction process involves several phases: basic block identification
/// through control flow analysis, edge creation based on jump target resolution,
/// and SSA form generation for stack operation tracking. Each phase validates
/// the bytecode structure to ensure the resulting CFG accurately represents
/// the original program semantics.
///
/// # Parameters
///
/// * `instructions` - A slice of decoded EVM instructions representing the complete
///   bytecode sequence. These instructions must be validated and properly formatted.
/// * `sections` - Detected bytecode sections that define the boundaries between
///   initialization code, runtime code, and auxiliary data.
/// * `clean_report` - Stripping report containing PC mappings and section information
///   required for proper reassembly after obfuscation transforms.
///
/// # Returns
///
/// Returns a `CfgIrBundle` containing the constructed control flow graph, PC-to-block
/// mappings for efficient lookup operations, and the associated clean report for
/// bytecode reassembly. The bundle provides all necessary information for subsequent
/// analysis and transformation phases.
///
/// # Errors
///
/// Returns `CfgIrError` in several scenarios:
/// - `NoEntryBlock` when the instruction sequence contains no valid entry point
/// - `NoExitBlock` when terminal instructions cannot be identified
/// - `InvalidSequence` when the bytecode structure is malformed or contains
///   inconsistent control flow patterns
///
/// # Examples
///
/// ```rust
/// use azoth_core::cfg_ir::build_cfg_ir;
///
/// let (instructions, _, _, bytes) = decode_bytecode("0x6001600155", false).await?;
/// let sections = locate_sections(&bytes, &instructions)?;
/// let (_, report) = strip_bytecode(&bytes, &sections)?;
///
/// let cfg_bundle = build_cfg_ir(&instructions, &sections, report)?;
/// println!("CFG contains {} blocks", cfg_bundle.cfg.node_count());
/// ```
pub fn build_cfg_ir(
    instructions: &[Instruction],
    sections: &[Section],
    clean_report: CleanReport,
) -> Result<CfgIrBundle, CfgIrError>
```

This documentation style provides comprehensive information while maintaining readability and professional presentation. Avoid excessive use of bullet points or fragmented lists in favor of coherent explanatory prose.

## Key Modules and Data Structures

- **CFG IR**: Control Flow Graph intermediate representation in `crates/core/src/cfg_ir.rs`
- **Opcodes**: EVM opcode definitions and utilities in `crates/core/src/opcode.rs`
- **Transform Passes**: Obfuscation transforms implementing a common pass interface

## Git Workflow and GitHub Integration

### Branch Management
**CRITICAL**: Never make changes directly on the `master` branch. Always create feature branches for any modifications, including documentation updates.

```bash
# Always start from master
git checkout master
git pull origin master
git checkout -b feature/your-feature-name

# Push new branch to remote and set upstream
git push -u origin feature/your-feature-name
```

### Branch Naming Conventions
Use descriptive branch names that indicate the type and scope of changes:
- `feat/add-new-transform` for new features
- `fix/memory-leak-in-cfg` for bug fixes
- `docs/update-api-documentation` for documentation updates
- `refactor/simplify-opcode-parsing` for code improvements
- `test/add-integration-tests` for testing enhancements

### Commit Guidelines
Follow conventional commit format with detailed descriptions. The commit message should clearly explain both what changed and why the change was necessary.

```
type(scope): brief description

Detailed explanation of the changes made and the reasoning behind them.
Include any breaking changes, migration notes, or special considerations.

Examples:
- feat(core): implement advanced CFG dominance analysis
- fix(cli): resolve panic when processing malformed bytecode input
- docs: enhance API documentation with comprehensive examples
- refactor(transforms): extract reusable opcode classification logic
```

### GitHub Issue and Pull Request Management

#### Creating Issues
When creating GitHub issues, always assign appropriate labels to ensure proper categorization and workflow management:

**Priority Labels:**
- `priority:high` - Critical bugs, security issues, or blocking features
- `priority:medium` - Important improvements and standard features
- `priority:low` - Nice-to-have enhancements and code quality improvements

**Type Labels:**
- `type:bug` - Software defects and unexpected behavior
- `type:feature` - New functionality or capabilities
- `type:enhancement` - Improvements to existing features
- `type:documentation` - Documentation updates and improvements
- `type:refactor` - Code structure improvements without functional changes
- `type:performance` - Performance optimizations and efficiency improvements

**Component Labels:**
- `component:core` - Issues related to core bytecode processing
- `component:transforms` - Obfuscation transform implementations
- `component:analysis` - Metrics and analytical functionality
- `component:verification` - Formal verification and testing
- `component:utils` - Shared utilities and helpers
- `component:cli` - Command-line interface and user experience
- `component:tests` - Testing infrastructure and test cases

#### Pull Request Guidelines
Every pull request should include comprehensive information about the changes, testing performed, and any potential impacts on the system.

**Required PR Content:**
- Clear description of what changes were made
- Explanation of why the changes were necessary
- Details of testing performed (unit tests, integration tests, manual verification)
- Any breaking changes or migration requirements
- Links to related issues or discussions

**Example PR Description Template:**
```markdown
## Summary
Brief overview of the changes made in this pull request.

## Motivation
Explanation of the problem being solved or feature being added.

## Changes Made
Detailed description of the implementation approach and key modifications.

## Testing
Description of testing performed, including any new test cases added.

## Breaking Changes
Any API changes or compatibility issues that might affect users.

## Related Issues
Links to GitHub issues that this PR addresses or relates to.
```

### Code Review Process
All changes must go through code review before merging to master. The review process should focus on code quality, documentation completeness, test coverage, and adherence to project standards.

## Testing

Located in `tests/` workspace directory, organized by component:
  - `tests/src/core/`
  - `tests/src/transforms/`
  - `tests/src/analysis/`
  - `tests/src/verification/`
  - `tests/src/e2e/`

### Test Data
- **`examples/escrow-bytecode/`**: Real-world escrow contract bytecode for integration testing
- **`examples/src/main.rs`**: Example usage and demonstration code

### Running Tests
```bash
# Run all tests with nextest (recommended)
cargo tt

# Run specific test suite
cargo nextest run --test e2e
```
