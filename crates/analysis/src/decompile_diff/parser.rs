//! Parser for Heimdall-decompiled Solidity source.
//!
//! Extracts semantic structures from decompiled output:
//! - Header (license, pragma, contract declaration)
//! - Storage variables block
//! - Functions with their selectors

use std::collections::HashMap;

/// A parsed function from decompiled source.
#[derive(Debug, Clone)]
pub struct ParsedFunction {
    /// The 4-byte selector.
    pub selector: u32,
    /// Function name (e.g., "fund", "Unresolved_a65e2cfd").
    pub name: String,
    /// Full function content including doc comments and body.
    pub content: String,
}

/// Parsed structure from decompiled Solidity source.
#[derive(Debug, Clone)]
pub struct ParsedSource {
    /// Header content (before contract body).
    pub header: String,
    /// Storage variables block.
    pub storage: String,
    /// Functions indexed by their selector.
    pub functions: HashMap<u32, ParsedFunction>,
    /// Contract closing brace and any trailing content.
    pub footer: String,
}

/// Parses decompiled Solidity source into structured components.
///
/// This extracts:
/// - Header: Everything up to and including `contract DecompiledContract {`
/// - Storage: Variable declarations at the start of the contract body
/// - Functions: Each function with its selector from `@custom:selector` annotation
/// - Footer: Closing brace and trailing content
pub fn parse(source: &str) -> ParsedSource {
    let lines: Vec<&str> = source.lines().collect();
    let mut header = String::new();
    let mut storage = String::new();
    let mut functions: HashMap<u32, ParsedFunction> = HashMap::new();
    let mut footer = String::new();

    #[derive(PartialEq)]
    enum State {
        Header,
        Storage,
        Function,
        Footer,
    }

    let mut state = State::Header;
    let mut current_function_lines: Vec<&str> = Vec::new();
    let mut current_selector: Option<u32> = None;
    let mut current_name: Option<String> = None;
    let mut brace_depth = 0;

    for line in &lines {
        match state {
            State::Header => {
                header.push_str(line);
                header.push('\n');
                if line.contains("contract DecompiledContract") {
                    brace_depth = 1;
                    state = State::Storage;
                }
            }
            State::Storage => {
                // First function annotation or declaration marks end of storage
                if line.contains("/// @custom:selector") || line.trim().starts_with("function ") {
                    state = State::Function;
                    current_function_lines.push(line);
                    if let Some(sel) = extract_selector(line) {
                        current_selector = Some(sel);
                    }
                } else if line.trim() == "}" && brace_depth == 1 {
                    state = State::Footer;
                    footer.push_str(line);
                    footer.push('\n');
                } else {
                    storage.push_str(line);
                    storage.push('\n');
                }
            }
            State::Function => {
                current_function_lines.push(line);

                if let Some(sel) = extract_selector(line) {
                    current_selector = Some(sel);
                }

                if line.trim().starts_with("function ") {
                    current_name = extract_function_name(line);
                }

                // Track brace depth
                for ch in line.chars() {
                    match ch {
                        '{' => brace_depth += 1,
                        '}' => brace_depth -= 1,
                        _ => {}
                    }
                }

                // Function ends at contract-level brace depth
                if brace_depth == 1 && line.trim().ends_with('}') {
                    save_function(
                        &mut functions,
                        &mut current_selector,
                        &mut current_name,
                        &mut current_function_lines,
                    );
                } else if brace_depth == 0 {
                    // Contract closing brace reached
                    if current_function_lines.last() == Some(&"}") {
                        current_function_lines.pop();
                    }
                    save_function(
                        &mut functions,
                        &mut current_selector,
                        &mut current_name,
                        &mut current_function_lines,
                    );
                    state = State::Footer;
                    footer.push_str(line);
                    footer.push('\n');
                }
            }
            State::Footer => {
                footer.push_str(line);
                footer.push('\n');
            }
        }
    }

    // Handle remaining function content
    if !current_function_lines.is_empty() {
        save_function(
            &mut functions,
            &mut current_selector,
            &mut current_name,
            &mut current_function_lines,
        );
    }

    ParsedSource {
        header,
        storage,
        functions,
        footer,
    }
}

fn save_function(
    functions: &mut HashMap<u32, ParsedFunction>,
    selector: &mut Option<u32>,
    name: &mut Option<String>,
    lines: &mut Vec<&str>,
) {
    if let Some(sel) = selector.take() {
        let fn_name = name
            .take()
            .unwrap_or_else(|| format!("Unresolved_{:08x}", sel));
        let content = lines.join("\n") + "\n";
        functions.insert(
            sel,
            ParsedFunction {
                selector: sel,
                name: fn_name,
                content,
            },
        );
    }
    lines.clear();
}

/// Extracts selector from a `/// @custom:selector 0x...` line.
fn extract_selector(line: &str) -> Option<u32> {
    if !line.contains("@custom:selector") {
        return None;
    }
    let pos = line.find("0x")?;
    let hex_str = &line[pos + 2..];
    let hex_part: String = hex_str.chars().take(8).collect();
    u32::from_str_radix(&hex_part, 16).ok()
}

/// Extracts function name from a function declaration line.
fn extract_function_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with("function ") {
        return None;
    }
    let after_fn = &trimmed[9..];
    let name_end = after_fn.find('(')?;
    Some(after_fn[..name_end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_selector() {
        assert_eq!(
            extract_selector("    /// @custom:selector    0xede7f6a3"),
            Some(0xede7f6a3)
        );
        assert_eq!(
            extract_selector("/// @custom:selector 0x046f7da2"),
            Some(0x046f7da2)
        );
        assert_eq!(extract_selector("function foo() public"), None);
    }

    #[test]
    fn test_extract_function_name() {
        assert_eq!(
            extract_function_name("    function fund(uint256 arg0) public payable {"),
            Some("fund".to_string())
        );
        assert_eq!(
            extract_function_name(
                "function Unresolved_ede7f6a3(uint256 arg0, uint256 arg1) public view {"
            ),
            Some("Unresolved_ede7f6a3".to_string())
        );
    }

    #[test]
    fn test_parse_simple_contract() {
        let source = r#"// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

contract DecompiledContract {
    uint256 public bondAmount;
    address public owner;

    /// @custom:selector    0xa65e2cfd
    /// @custom:signature   fund(uint256 arg0) public payable
    function fund(uint256 arg0) public payable {
        require(msg.value);
    }

    /// @custom:selector    0x3ccfd60b
    /// @custom:signature   withdraw() public payable
    function withdraw() public payable {
        require(msg.sender == owner);
    }
}
"#;

        let parsed = parse(source);

        assert!(parsed.header.contains("contract DecompiledContract"));
        assert!(parsed.storage.contains("bondAmount"));
        assert!(parsed.storage.contains("owner"));
        assert_eq!(parsed.functions.len(), 2);
        assert!(parsed.functions.contains_key(&0xa65e2cfd));
        assert!(parsed.functions.contains_key(&0x3ccfd60b));

        let fund_fn = &parsed.functions[&0xa65e2cfd];
        assert_eq!(fund_fn.name, "fund");
        assert!(fund_fn.content.contains("require(msg.value)"));
    }
}
