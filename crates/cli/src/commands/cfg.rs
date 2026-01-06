//! This module processes input bytecode, constructs a CFG using the `cfg_ir` module, and
//! generates a Graphviz .dot file representing the CFG. The output can be written to a file or
//! printed to stdout.

use async_trait::async_trait;
use azoth_core::cfg_ir::{build_cfg_ir, Block, CfgIrBundle, EdgeType};
use azoth_core::decoder::decode_bytecode;
use azoth_core::detection::locate_sections;
use azoth_core::input_to_bytes;
use azoth_core::strip::strip_bytecode;
use clap::Args;
use std::error::Error;
use std::fs;
use std::path::Path;

/// Arguments for the `cfg` subcommand.
#[derive(Args)]
pub struct CfgArgs {
    /// Input deployment bytecode as a hex string (0x...) or file path containing EVM bytecode.
    #[arg(short = 'D', long = "deployment")]
    pub deployment_bytecode: String,
    /// Input runtime bytecode as a hex string (0x...) or file path containing EVM bytecode.
    #[arg(short = 'R', long = "runtime")]
    pub runtime_bytecode: String,
    /// Output file for Graphviz .dot (default: stdout)
    #[arg(short, long)]
    output: Option<String>,
}

/// Executes the `cfg` subcommand to generate a CFG visualization.
#[async_trait]
impl super::Command for CfgArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let is_file = !self.deployment_bytecode.starts_with("0x")
            && Path::new(&self.deployment_bytecode).is_file();
        let runtime_is_file =
            !self.runtime_bytecode.starts_with("0x") && Path::new(&self.runtime_bytecode).is_file();
        let (instructions, _, _, bytes) =
            decode_bytecode(&self.deployment_bytecode, is_file).await?;
        let runtime_bytes = input_to_bytes(&self.runtime_bytecode, runtime_is_file)?;
        let sections = locate_sections(&bytes, &instructions, &runtime_bytes)?;
        let (_clean_runtime, clean_report) = strip_bytecode(&bytes, &sections)?;
        let cfg_ir = build_cfg_ir(&instructions, &sections, clean_report, &bytes)?;

        let dot = generate_dot(&cfg_ir);
        if let Some(out_path) = self.output {
            fs::write(out_path, &dot)?;
        } else {
            println!("{dot}");
        }
        Ok(())
    }
}

/// Generates a Graphviz .dot representation of the CFG.
///
/// # Arguments
/// * `cfg_ir` - The `CfgIrBundle` containing the CFG to visualize.
///
/// # Returns
/// A `String` containing the .dot file content.
fn generate_dot(cfg_ir: &CfgIrBundle) -> String {
    let mut dot = String::from("digraph CFG {\n");

    // Add nodes
    for node in cfg_ir.cfg.node_indices() {
        let block = cfg_ir.cfg.node_weight(node).unwrap();
        let label = match block {
            Block::Entry => "Entry".to_string(),
            Block::Exit => "Exit".to_string(),
            Block::Body(body) => {
                let instrs: Vec<String> = body.instructions.iter().map(|i| i.to_string()).collect();
                format!("Block_{}\\n{}", body.start_pc, instrs.join("\\n"))
            }
        };
        dot.push_str(&format!("    {} [label=\"{}\"];\n", node.index(), label));
    }

    // Add edges
    for edge in cfg_ir.cfg.edge_indices() {
        let (src, dst) = cfg_ir.cfg.edge_endpoints(edge).unwrap();
        let edge_type = cfg_ir.cfg.edge_weight(edge).unwrap();
        let label = match edge_type {
            EdgeType::Fallthrough => "Fallthrough",
            EdgeType::Jump => "Jump",
            EdgeType::BranchTrue => "BranchTrue",
            EdgeType::BranchFalse => "BranchFalse",
        };
        dot.push_str(&format!(
            "    {} -> {} [label=\"{}\"];\n",
            src.index(),
            dst.index(),
            label
        ));
    }

    dot.push_str("}\n");
    dot
}
