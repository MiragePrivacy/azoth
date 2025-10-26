//! Security property definitions and verification

use serde::{Deserialize, Serialize};

/// Security properties that must be preserved during obfuscation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityProperty {
    /// Access control: Who can call which functions
    AccessControl {
        function_selector: [u8; 4],
        authorized_callers: Vec<[u8; 20]>, // Ethereum addresses
    },
    /// State invariant: Conditions that must always hold
    StateInvariant {
        name: String,
        invariant_formula: String, // SMT-LIB format
    },
    /// Reentrancy protection: Functions protected against reentrancy
    ReentrancyProtection { protected_functions: Vec<[u8; 4]> },
    /// Arithmetic overflow protection
    ArithmeticSafety {
        operations: Vec<ArithmeticOperation>,
    },
    /// Custom property with SMT formula
    Custom {
        name: String,
        property_formula: String,
    },
}

/// Arithmetic operations that need overflow protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArithmeticOperation {
    Addition,
    Subtraction,
    Multiplication,
    Division,
    Modulo,
}

impl SecurityProperty {
    /// Convert property to SMT-LIB formula
    pub fn to_smt_formula(&self) -> String {
        match self {
            SecurityProperty::AccessControl {
                function_selector,
                authorized_callers,
            } => {
                let selector_hex = hex::encode(function_selector);
                let callers: Vec<String> = authorized_callers
                    .iter()
                    .map(|address| format!("0x{}", hex::encode(address)))
                    .collect();

                format!(
                    "(assert (forall ((caller Address) (input Input))
                        (=> (= (function-selector input) #x{})
                            (member caller (list {})))))",
                    selector_hex,
                    callers.join(" ")
                )
            }
            SecurityProperty::StateInvariant {
                name: _,
                invariant_formula,
            } => invariant_formula.clone(),
            SecurityProperty::ReentrancyProtection {
                protected_functions,
            } => {
                let selectors: Vec<String> = protected_functions
                    .iter()
                    .map(|selector| format!("#x{}", hex::encode(selector)))
                    .collect();

                format!(
                    "(assert (forall ((call-stack CallStack) (function-sel FunctionSelector))
                        (=> (member function-sel (list {}))
                            (not (contains-reentrant-call call-stack function-sel)))))",
                    selectors.join(" ")
                )
            }
            SecurityProperty::ArithmeticSafety { operations } => {
                let ops: Vec<&str> = operations
                    .iter()
                    .map(|op| match op {
                        ArithmeticOperation::Addition => "add",
                        ArithmeticOperation::Subtraction => "sub",
                        ArithmeticOperation::Multiplication => "mul",
                        ArithmeticOperation::Division => "div",
                        ArithmeticOperation::Modulo => "mod",
                    })
                    .collect();

                format!(
                    "(assert (forall ((a Int) (b Int) (op Operation))
                        (=> (member op (list {}))
                            (and (>= (apply-op op a b) 0)
                                 (< (apply-op op a b) (^ 2 256))))))",
                    ops.join(" ")
                )
            }
            SecurityProperty::Custom {
                name: _,
                property_formula,
            } => property_formula.clone(),
        }
    }

    /// Get a human-readable description of the property
    pub fn description(&self) -> String {
        match self {
            SecurityProperty::AccessControl {
                function_selector,
                authorized_callers,
            } => {
                format!(
                    "Access Control: Function 0x{} restricted to {} authorized callers",
                    hex::encode(function_selector),
                    authorized_callers.len()
                )
            }
            SecurityProperty::StateInvariant { name, .. } => {
                format!("State Invariant: {name}")
            }
            SecurityProperty::ReentrancyProtection {
                protected_functions,
            } => {
                format!(
                    "Reentrancy Protection: {} functions protected",
                    protected_functions.len()
                )
            }
            SecurityProperty::ArithmeticSafety { operations } => {
                format!(
                    "Arithmetic Safety: {} operations protected from overflow",
                    operations.len()
                )
            }
            SecurityProperty::Custom { name, .. } => {
                format!("Custom Property: {name}")
            }
        }
    }
}
