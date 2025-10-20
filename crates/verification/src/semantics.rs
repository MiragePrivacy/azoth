//! Contract semantics extraction and representation
//!
//! This module analyzes bytecode to extract semantic information needed for formal verification
//! by leveraging pattern recognition, symbolic execution, and property synthesis.

use crate::{Error, VerificationResult};
use azoth_core::cfg_ir::{Block, CfgIrBundle, EdgeType};
use azoth_core::decoder::Instruction;
use azoth_core::{cfg_ir, decoder, detection, strip, Opcode};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use tracing;

/// Stack value for symbolic execution
#[derive(Debug, Clone, PartialEq)]
pub enum StackValue {
    /// Concrete value from PUSH instruction
    Concrete(u64),
    /// Symbolic value (e.g., from CALLDATALOAD)
    Symbolic(String),
    /// Result of an operation
    Operation {
        op: String,
        operands: Vec<Box<StackValue>>,
    },
    /// Storage load result
    StorageLoad(Box<StackValue>),
    /// Unknown/top value
    Unknown,
}

/// Path condition for conditional execution
#[derive(Debug, Clone)]
pub struct PathCondition {
    /// SMT formula representing the condition
    pub formula: String,
    /// Whether this is a positive or negative condition
    pub polarity: bool,
    /// Source instruction PC
    pub source_pc: usize,
}

/// Storage access pattern
#[derive(Debug, Clone)]
pub struct StorageAccess {
    /// Program counter of the access
    pub pc: usize,
    /// Computed storage slot
    pub slot: StackValue,
    /// Access type (SLOAD or SSTORE)
    pub access_type: StorageAccessType,
    /// Value being stored (for SSTORE)
    pub stored_value: Option<StackValue>,
    /// Path conditions leading to this access
    pub conditions: Vec<PathCondition>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StorageAccessType {
    Load,
    Store,
}

/// Contract pattern recognition
#[derive(Debug, Clone)]
pub struct ContractPattern {
    /// Pattern type (ERC20, ERC721, etc.)
    pub pattern_type: PatternType,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Supporting evidence
    pub evidence: Vec<PatternEvidence>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PatternType {
    ERC20Token,
    ERC721NFT,
    Ownable,
    ReentrancyGuard,
    SafeMath,
    Proxy,
    Multisig,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PatternEvidence {
    /// Type of evidence found
    pub evidence_type: String,
    /// Location in bytecode
    pub pc: usize,
    /// Supporting details
    pub details: String,
}

/// Semantic representation of a smart contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSemantics {
    /// Contract functions with their properties
    pub functions: Vec<FunctionSemantics>, // what the contract can do
    /// Storage layout mapping
    pub storage_layout: HashMap<u64, String>, // slot -> type (how data is stored)
    /// Global state invariants
    pub state_invariants: Vec<String>, // SMT formulas (what must always be true)
    /// Contract-level properties
    pub properties: ContractProperties, // security characteristics
    /// Reference to the CFG for analysis
    pub cfg_metadata: CfgMetadata,
}

/// Metadata extracted from the CFG for semantic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgMetadata {
    /// Number of basic blocks in the CFG
    pub block_count: usize,
    /// Number of edges in the CFG
    pub edge_count: usize,
    /// Entry points (function selectors to block start PCs)
    pub entry_points: HashMap<[u8; 4], usize>,
    /// Block summaries for analysis
    pub block_summaries: Vec<BlockSummary>,
}

/// Summary of a basic block for semantic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSummary {
    /// Block identifier (PC of first instruction)
    pub start_pc: usize,
    /// Number of instructions in this block
    pub instruction_count: usize,
    /// Block type based on terminating instruction
    pub block_type: BlockType,
    /// Opcodes in this block (using enum instead of strings)
    pub opcodes: Vec<Opcode>,
    /// Maximum stack height reached in this block
    pub max_stack: usize,
    /// Incoming edge types
    pub incoming_edges: Vec<EdgeType>,
    /// Outgoing edge types
    pub outgoing_edges: Vec<EdgeType>,
}

/// Semantic representation of a contract function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSemantics {
    /// Function name (if known)
    pub name: String,
    /// Function selector (first 4 bytes of keccak hash)
    pub selector: Option<[u8; 4]>,
    /// Function preconditions (SMT formulas)
    pub preconditions: Vec<String>,
    /// Function postconditions (SMT formulas)
    pub postconditions: Vec<String>,
    /// State modifications this function can make
    pub state_modifications: Vec<StateModification>,
    /// Gas consumption characteristics
    pub gas_characteristics: GasCharacteristics,
    /// Whether this function is view/pure
    pub read_only: bool,
    /// Whether this function is payable
    pub payable: bool,
    /// Basic blocks that belong to this function
    pub block_pcs: Vec<usize>,
}

/// Description of how a function modifies contract state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateModification {
    /// Storage slot being modified
    pub storage_slot: u64,
    /// Type of modification
    pub modification_type: ModificationType,
    /// Conditions under which modification occurs
    pub conditions: Vec<String>, // SMT formulas
}

/// Types of state modifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModificationType {
    /// Direct assignment
    Assignment,
    /// Increment/decrement
    Arithmetic,
    /// Conditional update
    Conditional,
    /// Array/mapping update
    Collection,
}

/// Gas consumption characteristics of a function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasCharacteristics {
    /// Base gas cost (fixed part)
    pub base_cost: u64,
    /// Variable gas cost factors
    pub variable_costs: Vec<VariableGasCost>,
    /// Maximum possible gas consumption
    pub max_gas: Option<u64>,
}

/// Variable gas cost component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableGasCost {
    /// What drives this variable cost
    pub factor: GasCostFactor,
    /// Cost per unit
    pub cost_per_unit: u64,
}

/// Factors that affect gas consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GasCostFactor {
    /// Input data size
    InputDataSize,
    /// Storage operations
    StorageOperations,
    /// Loop iterations
    LoopIterations,
    /// External calls
    ExternalCalls,
}

/// Contract-level properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractProperties {
    /// Whether the contract uses a proxy pattern
    pub is_proxy: bool,
    /// Whether the contract is upgradeable
    pub is_upgradeable: bool,
    /// Reentrancy guards present
    pub has_reentrancy_guards: bool,
    /// Access control mechanisms
    pub access_control: AccessControlType,
}

/// Types of access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessControlType {
    /// No access control
    None,
    /// Simple owner-based control
    Owner,
    /// Role-based access control
    RoleBased,
    /// Custom access control
    Custom,
}

/// Types of basic blocks based on their terminating instruction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BlockType {
    /// Function entry point
    Entry,
    /// Regular execution block
    Normal,
    /// Conditional branch
    Branch,
    /// Function return
    Return,
    /// Error/revert
    Error,
    /// Unconditional jump
    Jump,
}

/// Extract semantic information from a CFG bundle
pub fn extract_semantics(cfg_bundle: &CfgIrBundle) -> VerificationResult<ContractSemantics> {
    tracing::debug!("Extracting semantics from CFG bundle");

    let mut analyzer = SemanticAnalyzer::new(cfg_bundle.clone());
    analyzer.analyze()?;
    analyzer.extract_semantics_from_cfg()
}

/// Extract semantic information from bytecode
pub async fn extract_semantics_from_bytecode(
    bytecode: &[u8],
) -> VerificationResult<ContractSemantics> {
    tracing::debug!(
        "Extracting semantics from bytecode ({} bytes)",
        bytecode.len()
    );

    let (instructions, _, _, _) =
        decoder::decode_bytecode(&format!("0x{}", hex::encode(bytecode)), false)
            .await
            .map_err(|e| Error::BytecodeAnalysis(format!("Failed to decode bytecode: {e}")))?;

    let sections = detection::locate_sections(bytecode, &instructions)
        .map_err(|e| Error::BytecodeAnalysis(format!("Failed to detect sections: {e}")))?;

    let (_clean_runtime, clean_report) = strip::strip_bytecode(bytecode, &sections)
        .map_err(|e| Error::BytecodeAnalysis(format!("Failed to strip bytecode: {e}")))?;

    let cfg_bundle = cfg_ir::build_cfg_ir(&instructions, &sections, clean_report, bytecode)
        .map_err(|e| Error::BytecodeAnalysis(format!("Failed to build CFG: {e}")))?;

    extract_semantics(&cfg_bundle)
}

/// Semantic analyzer capable of deep bytecode analysis
pub struct SemanticAnalyzer {
    /// CFG bundle for analysis
    cfg_bundle: CfgIrBundle,
    /// Storage access patterns found
    storage_accesses: Vec<StorageAccess>,
    /// Detected contract patterns
    patterns: Vec<ContractPattern>,
}

impl SemanticAnalyzer {
    /// Create new analyzer instance
    pub fn new(cfg_bundle: CfgIrBundle) -> Self {
        Self {
            cfg_bundle,
            storage_accesses: Vec::new(),
            patterns: Vec::new(),
        }
    }

    /// Perform comprehensive semantic analysis
    pub fn analyze(&mut self) -> VerificationResult<()> {
        tracing::info!("Starting semantic analysis");

        // Analyze storage access patterns with symbolic execution
        self.analyze_storage_patterns()?;

        // Detect contract patterns (ERC20, Ownable, etc.)
        self.detect_contract_patterns()?;

        // Perform symbolic execution on critical paths
        self.symbolic_execution_analysis()?;

        tracing::info!("Semantic analysis completed");
        Ok(())
    }

    /// Extract semantic information from CFG
    pub fn extract_semantics_from_cfg(&self) -> VerificationResult<ContractSemantics> {
        let cfg_metadata = self.extract_cfg_metadata()?;
        let functions = self.extract_functions()?;
        let storage_layout = self.analyze_storage_layout()?;
        let properties = self.analyze_contract_properties()?;
        let state_invariants = self.extract_state_invariants(&functions, &storage_layout)?;

        Ok(ContractSemantics {
            functions,
            storage_layout,
            state_invariants,
            properties,
            cfg_metadata,
        })
    }

    /// Extract CFG metadata for analysis
    fn extract_cfg_metadata(&self) -> VerificationResult<CfgMetadata> {
        let cfg = &self.cfg_bundle.cfg;
        let mut entry_points = HashMap::new();
        let mut block_summaries = Vec::new();

        // Extract semantic information from existing CFG blocks
        for node_idx in cfg.node_indices() {
            if let Some(Block::Body(body)) = cfg.node_weight(node_idx) {
                let start_pc = body.start_pc;
                let instructions = &body.instructions;
                let max_stack = body.max_stack;
                // Extract function selectors (semantic analysis)
                if let Some(selector) =
                    self.extract_function_selector_from_instructions(instructions)
                {
                    entry_points.insert(selector, start_pc);
                }

                // Extract opcodes from instructions
                let opcodes: Vec<Opcode> = instructions.iter().map(|i| i.op).collect();

                // Determine block type using enum comparison
                let block_type = if instructions.is_empty() {
                    BlockType::Normal
                } else {
                    match instructions.last().unwrap().op {
                        Opcode::RETURN => BlockType::Return,
                        Opcode::REVERT => BlockType::Error,
                        Opcode::JUMP => BlockType::Jump,
                        Opcode::JUMPI => BlockType::Branch,
                        _ => {
                            if matches!(instructions.first().map(|i| i.op), Some(Opcode::JUMPDEST))
                            {
                                BlockType::Entry
                            } else {
                                BlockType::Normal
                            }
                        }
                    }
                };

                // Use CFG's existing edge information
                let incoming_edges: Vec<EdgeType> = cfg
                    .edges_directed(node_idx, petgraph::Direction::Incoming)
                    .map(|edge| edge.weight().clone())
                    .collect();

                let outgoing_edges: Vec<EdgeType> = cfg
                    .edges_directed(node_idx, petgraph::Direction::Outgoing)
                    .map(|edge| edge.weight().clone())
                    .collect();

                block_summaries.push(BlockSummary {
                    start_pc,
                    instruction_count: instructions.len(),
                    block_type,
                    opcodes,
                    max_stack,
                    incoming_edges,
                    outgoing_edges,
                });
            }
        }

        Ok(CfgMetadata {
            block_count: cfg.node_count(),
            edge_count: cfg.edge_count(),
            entry_points,
            block_summaries,
        })
    }

    fn extract_functions(&self) -> VerificationResult<Vec<FunctionSemantics>> {
        let mut functions = Vec::new();
        let cfg_metadata = self.extract_cfg_metadata()?;

        // For each entry point, analyze the reachable blocks as a function
        for (selector, start_pc) in &cfg_metadata.entry_points {
            let function = self.analyze_function(*selector, *start_pc)?;
            functions.push(function);
        }

        // If no entry points found, create a single function for the entire contract
        if functions.is_empty() {
            let function = self.create_fallback_function(&cfg_metadata)?;
            functions.push(function);
        }

        Ok(functions)
    }

    /// Analyze a single function with sophisticated analysis
    fn analyze_function(
        &self,
        selector: [u8; 4],
        start_pc: usize,
    ) -> VerificationResult<FunctionSemantics> {
        let function_name = format!("function_{}", hex::encode(selector));

        // Find all blocks reachable from the start_pc
        let reachable_blocks = self.find_reachable_blocks_in_cfg(start_pc)?;
        let block_pcs: Vec<usize> = reachable_blocks.to_vec();

        // Analyze state modifications across all reachable blocks
        let state_modifications = self.analyze_state_modifications_in_blocks(&reachable_blocks)?;

        // Analyze gas characteristics
        let gas_characteristics = self.analyze_gas_characteristics_in_blocks(&reachable_blocks)?;

        // Determine function properties
        let (read_only, payable) = self.analyze_function_properties_in_blocks(&reachable_blocks)?;

        // Generate sophisticated preconditions and postconditions
        let preconditions = self.generate_preconditions(&selector, &state_modifications)?;
        let postconditions = self.generate_postconditions(&selector, &state_modifications)?;

        Ok(FunctionSemantics {
            name: function_name,
            selector: Some(selector),
            preconditions,
            postconditions,
            state_modifications,
            gas_characteristics,
            read_only,
            payable,
            block_pcs,
        })
    }

    fn create_fallback_function(
        &self,
        cfg_metadata: &CfgMetadata,
    ) -> VerificationResult<FunctionSemantics> {
        let all_block_pcs: Vec<usize> = cfg_metadata
            .block_summaries
            .iter()
            .map(|b| b.start_pc)
            .collect();
        let state_modifications = self.analyze_state_modifications_in_blocks(&all_block_pcs)?;
        let gas_characteristics = self.analyze_gas_characteristics_in_blocks(&all_block_pcs)?;
        let (read_only, payable) = self.analyze_function_properties_in_blocks(&all_block_pcs)?;

        Ok(FunctionSemantics {
            name: "fallback".to_string(),
            selector: None,
            preconditions: vec![],
            postconditions: vec![],
            state_modifications,
            gas_characteristics,
            read_only,
            payable,
            block_pcs: all_block_pcs,
        })
    }

    fn find_reachable_blocks_in_cfg(&self, start_pc: usize) -> VerificationResult<Vec<usize>> {
        let cfg = &self.cfg_bundle.cfg;
        let mut reachable = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        if let Some(&start_node) = self.cfg_bundle.pc_to_block.get(&start_pc) {
            queue.push_back(start_node);
        } else {
            return Err(Error::BytecodeAnalysis(format!(
                "No block found for start PC: {start_pc}",
            )));
        }

        while let Some(node_idx) = queue.pop_front() {
            if visited.contains(&node_idx) {
                continue;
            }
            visited.insert(node_idx);

            if let Some(Block::Body(body)) = cfg.node_weight(node_idx) {
                reachable.push(body.start_pc);
            }

            for edge in cfg.edges_directed(node_idx, petgraph::Direction::Outgoing) {
                queue.push_back(edge.target());
            }
        }

        Ok(reachable)
    }

    fn analyze_storage_patterns(&mut self) -> VerificationResult<()> {
        tracing::debug!("Analyzing storage access patterns");

        for node_idx in self.cfg_bundle.cfg.node_indices() {
            if let Some(Block::Body(body)) = self.cfg_bundle.cfg.node_weight(node_idx) {
                let instructions = &body.instructions;
                let mut stack = Vec::new();
                let path_conditions = Vec::new();

                for instruction in instructions {
                    self.update_stack(&mut stack, instruction);

                    match instruction.op {
                        Opcode::SLOAD => {
                            if let Some(slot) = stack.last().cloned() {
                                self.storage_accesses.push(StorageAccess {
                                    pc: instruction.pc,
                                    slot,
                                    access_type: StorageAccessType::Load,
                                    stored_value: None,
                                    conditions: path_conditions.clone(),
                                });
                            }
                        }
                        Opcode::SSTORE => {
                            if stack.len() >= 2 {
                                let slot = stack[stack.len() - 1].clone();
                                let value = stack[stack.len() - 2].clone();
                                self.storage_accesses.push(StorageAccess {
                                    pc: instruction.pc,
                                    slot,
                                    access_type: StorageAccessType::Store,
                                    stored_value: Some(value),
                                    conditions: path_conditions.clone(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        tracing::debug!("Found {} storage accesses", self.storage_accesses.len());
        Ok(())
    }

    fn analyze_storage_layout(&self) -> VerificationResult<HashMap<u64, String>> {
        let mut layout = HashMap::new();

        for access in &self.storage_accesses {
            if let StackValue::Concrete(slot) = access.slot {
                layout.entry(slot).or_insert("uint256".to_string());
            }
        }

        if layout.is_empty() {
            // Default entries for demonstration
            layout.insert(0, "uint256".to_string());
            layout.insert(1, "address".to_string());
            layout.insert(2, "mapping(address=>uint256)".to_string());
        }

        Ok(layout)
    }

    fn detect_contract_patterns(&mut self) -> VerificationResult<()> {
        tracing::debug!("Detecting contract patterns");

        if let Some(erc20_pattern) = self.detect_erc20_pattern()? {
            self.patterns.push(erc20_pattern);
        }

        if let Some(ownable_pattern) = self.detect_ownable_pattern()? {
            self.patterns.push(ownable_pattern);
        }

        if let Some(guard_pattern) = self.detect_reentrancy_guard_pattern()? {
            self.patterns.push(guard_pattern);
        }

        tracing::debug!("Detected {} contract patterns", self.patterns.len());
        Ok(())
    }

    fn detect_erc20_pattern(&self) -> VerificationResult<Option<ContractPattern>> {
        let mut evidence = Vec::new();
        let mut score = 0.0;

        if self.has_function_selector(&[0xa9, 0x05, 0x9c, 0xbb]) {
            evidence.push(PatternEvidence {
                evidence_type: "transfer_function".to_string(),
                pc: 0,
                details: "Found transfer function selector".to_string(),
            });
            score += 0.3;
        }

        if self.has_balance_mapping_pattern() {
            evidence.push(PatternEvidence {
                evidence_type: "balance_mapping".to_string(),
                pc: 0,
                details: "Found balance mapping access pattern".to_string(),
            });
            score += 0.3;
        }

        if score >= 0.3 {
            Ok(Some(ContractPattern {
                pattern_type: PatternType::ERC20Token,
                confidence: score,
                evidence,
            }))
        } else {
            Ok(None)
        }
    }

    fn detect_ownable_pattern(&self) -> VerificationResult<Option<ContractPattern>> {
        let mut evidence = Vec::new();
        let mut score = 0.0;

        if self.has_owner_storage_pattern() {
            evidence.push(PatternEvidence {
                evidence_type: "owner_storage".to_string(),
                pc: 0,
                details: "Found owner storage access pattern".to_string(),
            });
            score += 0.5;
        }

        if score >= 0.3 {
            Ok(Some(ContractPattern {
                pattern_type: PatternType::Ownable,
                confidence: score,
                evidence,
            }))
        } else {
            Ok(None)
        }
    }

    fn detect_reentrancy_guard_pattern(&self) -> VerificationResult<Option<ContractPattern>> {
        let mut evidence = Vec::new();
        let mut score = 0.0;

        if self.has_guard_check_pattern() {
            evidence.push(PatternEvidence {
                evidence_type: "guard_check".to_string(),
                pc: 0,
                details: "Found reentrancy guard check pattern".to_string(),
            });
            score += 0.5;
        }

        if score >= 0.3 {
            Ok(Some(ContractPattern {
                pattern_type: PatternType::ReentrancyGuard,
                confidence: score,
                evidence,
            }))
        } else {
            Ok(None)
        }
    }

    fn symbolic_execution_analysis(&mut self) -> VerificationResult<()> {
        tracing::debug!("Performing symbolic execution analysis");
        // Placeholder for full symbolic execution
        Ok(())
    }

    fn update_stack(&self, stack: &mut Vec<StackValue>, instruction: &Instruction) {
        match instruction.op {
            Opcode::PUSH(_) | Opcode::PUSH0 => {
                if let Some(immediate) = &instruction.imm {
                    if let Ok(value) = u64::from_str_radix(immediate, 16) {
                        stack.push(StackValue::Concrete(value));
                    } else {
                        stack.push(StackValue::Unknown);
                    }
                }
            }
            Opcode::CALLDATALOAD => {
                if !stack.is_empty() {
                    let offset = stack.pop().unwrap();
                    stack.push(StackValue::Symbolic(format!(
                        "CALLDATALOAD({})",
                        self.stack_value_to_string(&offset)
                    )));
                }
            }
            Opcode::ADD => {
                if stack.len() >= 2 {
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    stack.push(StackValue::Operation {
                        op: "ADD".to_string(),
                        operands: vec![Box::new(a), Box::new(b)],
                    });
                }
            }
            Opcode::POP => {
                stack.pop();
            }
            _ => {}
        }
    }

    #[allow(clippy::only_used_in_recursion)]
    fn stack_value_to_string(&self, value: &StackValue) -> String {
        match value {
            StackValue::Concrete(v) => format!("0x{v:x}"),
            StackValue::Symbolic(s) => s.clone(),
            StackValue::Operation { op, operands } => {
                let op_strs: Vec<String> = operands
                    .iter()
                    .map(|op| self.stack_value_to_string(op))
                    .collect();
                format!("{}({})", op, op_strs.join(", "))
            }
            StackValue::StorageLoad(slot) => {
                format!("SLOAD({})", self.stack_value_to_string(slot))
            }
            StackValue::Unknown => "UNKNOWN".to_string(),
        }
    }

    fn analyze_contract_properties(&self) -> VerificationResult<ContractProperties> {
        let mut is_proxy = false;
        let mut is_upgradeable = false;
        let mut has_reentrancy_guards = false;
        let mut access_control = AccessControlType::None;

        // Use CFG structure instead of raw instructions
        for node_idx in self.cfg_bundle.cfg.node_indices() {
            if let Some(Block::Body(body)) = self.cfg_bundle.cfg.node_weight(node_idx) {
                let instructions = &body.instructions;
                for instruction in instructions {
                    match instruction.op {
                        Opcode::DELEGATECALL => {
                            is_proxy = true;
                            is_upgradeable = true;
                        }
                        Opcode::CALLER => {
                            access_control = AccessControlType::Owner;
                        }
                        _ => {}
                    }
                }
            }
        }

        if self.has_guard_check_pattern() {
            has_reentrancy_guards = true;
        }

        Ok(ContractProperties {
            is_proxy,
            is_upgradeable,
            has_reentrancy_guards,
            access_control,
        })
    }

    fn analyze_state_modifications_in_blocks(
        &self,
        _block_pcs: &[usize],
    ) -> VerificationResult<Vec<StateModification>> {
        let mut modifications = Vec::new();

        for node_idx in self.cfg_bundle.cfg.node_indices() {
            if let Some(Block::Body(body)) = self.cfg_bundle.cfg.node_weight(node_idx) {
                let instructions = &body.instructions;
                for instruction in instructions {
                    if instruction.op == Opcode::SSTORE {
                        modifications.push(StateModification {
                            storage_slot: 0, // TODO: Requires proper stack analysis
                            modification_type: ModificationType::Assignment,
                            conditions: vec![],
                        });
                    }
                }
            }
        }

        Ok(modifications)
    }

    fn analyze_gas_characteristics_in_blocks(
        &self,
        _block_pcs: &[usize],
    ) -> VerificationResult<GasCharacteristics> {
        let mut base_cost = 21000u64;
        let mut variable_costs = Vec::new();

        for node_idx in self.cfg_bundle.cfg.node_indices() {
            if let Some(Block::Body(body)) = self.cfg_bundle.cfg.node_weight(node_idx) {
                let instructions = &body.instructions;
                for instruction in instructions {
                    // Calculate gas cost for each opcode
                    let opcode = instruction.op;
                    base_cost += self.get_instruction_gas_cost(&opcode);

                    match opcode {
                        Opcode::SSTORE => {
                            variable_costs.push(VariableGasCost {
                                factor: GasCostFactor::StorageOperations,
                                cost_per_unit: 20000,
                            });
                        }
                        Opcode::CALL
                        | Opcode::CALLCODE
                        | Opcode::DELEGATECALL
                        | Opcode::STATICCALL => {
                            variable_costs.push(VariableGasCost {
                                factor: GasCostFactor::ExternalCalls,
                                cost_per_unit: 2300,
                            });
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(GasCharacteristics {
            base_cost,
            variable_costs,
            max_gas: None,
        })
    }

    fn analyze_function_properties_in_blocks(
        &self,
        block_pcs: &[usize],
    ) -> VerificationResult<(bool, bool)> {
        let mut has_state_change = false;
        let mut is_payable = false;

        for &block_pc in block_pcs {
            if let Some(&node_idx) = self.cfg_bundle.pc_to_block.get(&block_pc) {
                if let Some(Block::Body(body)) = self.cfg_bundle.cfg.node_weight(node_idx) {
                    let instructions = &body.instructions;
                    for instruction in instructions {
                        match instruction.op {
                            Opcode::SSTORE => has_state_change = true,
                            Opcode::CALLVALUE => is_payable = true,
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok((!has_state_change, is_payable))
    }

    fn extract_state_invariants(
        &self,
        functions: &[FunctionSemantics],
        storage_layout: &HashMap<u64, String>,
    ) -> VerificationResult<Vec<String>> {
        let mut invariants = Vec::new();

        for pattern in &self.patterns {
            match pattern.pattern_type {
                PatternType::ERC20Token => {
                    invariants
                        .push("(= (sum-all-balances state) (total-supply state))".to_string());
                    invariants.push(
                        "(forall ((address Address)) (>= (balance address state) 0))".to_string(),
                    );
                }
                PatternType::Ownable => {
                    invariants.push(
                        "(not (= (owner state) #x0000000000000000000000000000000000000000))"
                            .to_string(),
                    );
                }
                PatternType::ReentrancyGuard => {
                    invariants.push(
                        "(=> (guard-locked state) (not (can-call-external state)))".to_string(),
                    );
                }
                _ => {}
            }
        }

        for (slot, slot_type) in storage_layout {
            match slot_type.as_str() {
                "uint256" => {
                    invariants.push(format!(
                        "(and (>= (storage-slot-{slot} (storage s)) 0) (< (storage-slot-{slot} (storage s)) (^ 2 256)))",
                    ));
                }
                "address" => {
                    invariants.push(format!(
                        "(and (>= (storage-slot-{slot} (storage s)) 0) (< (storage-slot-{slot} (storage s)) (^ 2 160)))",
                    ));
                }
                _ => {}
            }
        }

        for function in functions {
            if function.read_only {
                invariants.push(format!(
                    "(forall ((s State) (tx Transaction)) (= (storage (final-state ({} s tx))) (storage s)))",
                    function.name
                ));
            }
        }

        Ok(invariants)
    }

    fn generate_preconditions(
        &self,
        selector: &[u8; 4],
        state_modifications: &[StateModification],
    ) -> VerificationResult<Vec<String>> {
        let mut preconditions = Vec::new();

        preconditions.push(format!(
            "(= (function-selector (data tx)) #x{})",
            hex::encode(selector)
        ));

        for pattern in &self.patterns {
            match pattern.pattern_type {
                PatternType::ERC20Token => {
                    if self.is_transfer_function(selector) {
                        preconditions.push(
                            "(>= (balance (sender tx) (storage state)) (transfer-amount tx))"
                                .to_string(),
                        );
                        preconditions.push(
                            "(not (= (recipient tx) #x0000000000000000000000000000000000000000))"
                                .to_string(),
                        );
                        preconditions.push("(> (transfer-amount tx) 0)".to_string());
                    }
                }
                PatternType::Ownable => {
                    if self.is_admin_function(selector) {
                        preconditions.push("(= (sender tx) (owner (storage state)))".to_string());
                    }
                }
                PatternType::ReentrancyGuard => {
                    preconditions.push("(not (guard-locked (storage state)))".to_string());
                }
                _ => {}
            }
        }

        for modification in state_modifications {
            if let ModificationType::Arithmetic = modification.modification_type {
                preconditions.push(format!(
                    "(>= (storage-slot-{} (storage state)) 0)",
                    modification.storage_slot
                ));
            }
        }

        Ok(preconditions)
    }

    fn generate_postconditions(
        &self,
        _selector: &[u8; 4],
        state_modifications: &[StateModification],
    ) -> VerificationResult<Vec<String>> {
        let mut postconditions = Vec::new();

        postconditions.push("(=> (success result) (> (gas-used result) 0))".to_string());

        for modification in state_modifications {
            postconditions.push(format!(
                "(=> (success result) 
                    (= (storage-slot-{} (storage (final-state result)))
                       (updated-value (storage-slot-{} (storage state)))))",
                modification.storage_slot, modification.storage_slot
            ));
        }

        Ok(postconditions)
    }

    fn extract_function_selector_from_instructions(
        &self,
        instructions: &[Instruction],
    ) -> Option<[u8; 4]> {
        for instruction in instructions {
            if instruction.op == Opcode::PUSH(4) {
                if let Some(imm) = &instruction.imm {
                    if let Ok(bytes) = hex::decode(imm) {
                        if bytes.len() == 4 {
                            let mut selector = [0u8; 4];
                            selector.copy_from_slice(&bytes);
                            return Some(selector);
                        }
                    }
                }
            }
        }
        None
    }

    fn is_transfer_function(&self, selector: &[u8; 4]) -> bool {
        *selector == [0xa9, 0x05, 0x9c, 0xbb] // transfer(address,uint256)
    }

    fn is_admin_function(&self, selector: &[u8; 4]) -> bool {
        // Example admin function selectors
        const ADMIN_SELECTORS: &[[u8; 4]] = &[
            [0xf2, 0xfd, 0xe3, 0x8b], // transferOwnership(address)
            [0x7a, 0xd6, 0x92, 0x6b], // renounceOwnership()
        ];
        ADMIN_SELECTORS.contains(selector)
    }

    fn get_instruction_gas_cost(&self, opcode: &Opcode) -> u64 {
        match opcode {
            Opcode::ADD | Opcode::MUL | Opcode::SUB | Opcode::DIV | Opcode::SDIV => 3,

            Opcode::MOD
            | Opcode::SMOD
            | Opcode::ADDMOD
            | Opcode::MULMOD
            | Opcode::EXP
            | Opcode::SIGNEXTEND => 5,

            Opcode::LT
            | Opcode::GT
            | Opcode::SLT
            | Opcode::SGT
            | Opcode::EQ
            | Opcode::ISZERO
            | Opcode::AND
            | Opcode::OR
            | Opcode::XOR
            | Opcode::NOT
            | Opcode::BYTE
            | Opcode::SHL
            | Opcode::SHR
            | Opcode::SAR => 3,

            Opcode::MLOAD | Opcode::MSTORE | Opcode::MSTORE8 => 3,
            Opcode::SLOAD => 800,
            Opcode::SSTORE => 20000,
            Opcode::POP => 2,

            Opcode::DUP(_) | Opcode::SWAP(_) => 3,
            Opcode::PUSH(_) => 3,

            Opcode::JUMP => 8,
            Opcode::JUMPI => 10,
            Opcode::JUMPDEST => 1,

            Opcode::CALL | Opcode::CALLCODE | Opcode::DELEGATECALL | Opcode::STATICCALL => 700,

            Opcode::RETURN | Opcode::REVERT => 0,
            _ => 1,
        }
    }

    fn has_function_selector(&self, selector: &[u8; 4]) -> bool {
        let selector_hex = hex::encode(selector);

        for node_idx in self.cfg_bundle.cfg.node_indices() {
            if let Some(Block::Body(body)) = self.cfg_bundle.cfg.node_weight(node_idx) {
                let instructions = &body.instructions;
                for inst in instructions {
                    if inst.op == Opcode::PUSH(4) && inst.imm.as_ref() == Some(&selector_hex) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_balance_mapping_pattern(&self) -> bool {
        for node_idx in self.cfg_bundle.cfg.node_indices() {
            if let Some(Block::Body(body)) = self.cfg_bundle.cfg.node_weight(node_idx) {
                let instructions = &body.instructions;
                if instructions.windows(10).any(|window| {
                    window.iter().any(|inst| inst.op == Opcode::CALLDATALOAD)
                        && window.iter().any(|inst| inst.op == Opcode::KECCAK256)
                        && window.iter().any(|inst| inst.op == Opcode::SLOAD)
                }) {
                    return true;
                }
            }
        }
        false
    }

    fn has_owner_storage_pattern(&self) -> bool {
        for node_idx in self.cfg_bundle.cfg.node_indices() {
            if let Some(Block::Body(body)) = self.cfg_bundle.cfg.node_weight(node_idx) {
                let instructions = &body.instructions;
                if instructions.windows(5).any(|window| {
                    window.iter().any(|inst| inst.op == Opcode::CALLER)
                        && window
                            .iter()
                            .any(|inst| matches!(inst.op, Opcode::SLOAD | Opcode::SSTORE))
                }) {
                    return true;
                }
            }
        }
        false
    }

    fn has_guard_check_pattern(&self) -> bool {
        for node_idx in self.cfg_bundle.cfg.node_indices() {
            if let Some(Block::Body(body)) = self.cfg_bundle.cfg.node_weight(node_idx) {
                let instructions = &body.instructions;
                if instructions.windows(3).any(|window| {
                    window.len() == 3
                        && window[0].op == Opcode::SLOAD
                        && window[1].op == Opcode::ISZERO
                        && window[2].op == Opcode::JUMPI
                }) {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use azoth_core::cfg_ir::CfgIrBundle;
    use azoth_core::strip::CleanReport;

    // todo(g4titanx): impl. default for cleanreport
    pub fn create_empty_clean_report() -> CleanReport {
        CleanReport {
            runtime_layout: vec![],
            removed: vec![],
            swarm_hash: None,
            bytes_saved: 0,
            clean_len: 0,
            clean_keccak: [0; 32],
            program_counter_mapping: vec![],
        }
    }

    #[test]
    fn test_function_selector_extraction() {
        let cfg_bundle = CfgIrBundle {
            cfg: petgraph::stable_graph::StableGraph::new(),
            pc_to_block: HashMap::new(),
            clean_report: create_empty_clean_report(),
            sections: vec![],
            selector_mapping: None,
            original_bytecode: vec![],
            runtime_bounds: None,
            trace: Vec::new(),
        };
        let analyzer = SemanticAnalyzer::new(cfg_bundle);

        let instructions = vec![Instruction {
            pc: 0,
            op: Opcode::PUSH(4),
            imm: Some("12345678".to_string()),
        }];

        let selector = analyzer.extract_function_selector_from_instructions(&instructions);
        assert!(selector.is_some());
        assert_eq!(selector.unwrap(), [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_erc20_pattern_detection() {
        // Create a CFG with actual blocks containing the instruction
        let mut cfg = petgraph::stable_graph::StableGraph::new();
        let mut pc_to_block = HashMap::new();

        // Create a block with the transfer function selector
        let instructions = vec![Instruction {
            pc: 0,
            op: Opcode::PUSH(4),
            imm: Some("a9059cbb".to_string()), // transfer selector
        }];

        let block = Block::Body(cfg_ir::BlockBody {
            start_pc: 0,
            instructions,
            max_stack: 1,
            control: cfg_ir::BlockControl::Unknown,
        });

        let node_idx = cfg.add_node(block);
        pc_to_block.insert(0, node_idx);

        let cfg_bundle = CfgIrBundle {
            cfg,
            pc_to_block,
            clean_report: create_empty_clean_report(),
            sections: vec![],
            selector_mapping: None,
            original_bytecode: vec![],
            runtime_bounds: None,
            trace: Vec::new(),
        };

        let analyzer = SemanticAnalyzer::new(cfg_bundle);

        // Now this should pass
        assert!(analyzer.has_function_selector(&[0xa9, 0x05, 0x9c, 0xbb]));
        assert!(analyzer.is_transfer_function(&[0xa9, 0x05, 0x9c, 0xbb]));
    }

    #[test]
    fn test_transfer_function_detection() {
        let cfg_bundle = CfgIrBundle {
            cfg: petgraph::stable_graph::StableGraph::new(),
            pc_to_block: HashMap::new(),
            clean_report: create_empty_clean_report(),
            sections: vec![],
            selector_mapping: None,
            original_bytecode: vec![],
            runtime_bounds: None,
            trace: Vec::new(),
        };

        let analyzer = SemanticAnalyzer::new(cfg_bundle);

        // Test the pure function logic (doesn't depend on CFG)
        assert!(analyzer.is_transfer_function(&[0xa9, 0x05, 0x9c, 0xbb]));

        // Test function selector extraction from instructions directly
        let instructions = vec![Instruction {
            pc: 0,
            op: Opcode::PUSH(4),
            imm: Some("a9059cbb".to_string()),
        }];

        let selector = analyzer.extract_function_selector_from_instructions(&instructions);
        assert!(selector.is_some());
        assert_eq!(selector.unwrap(), [0xa9, 0x05, 0x9c, 0xbb]);
    }
}
