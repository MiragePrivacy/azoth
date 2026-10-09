//! Experimental SMT formula generation and a deliberately narrow Z3 adapter.
//!
//! Only the formula forms parsed exactly by this module are accepted. Unsupported
//! or incomplete obligations are errors; they are never approximated as `true`.

use crate::semantics::{ContractSemantics, FunctionSemantics, ModificationType, StateModification};
use crate::{Error, VerificationResult};
use serde::Serialize;
use std::time::Duration;
use z3::{
    ast::{self, Ast},
    Config, Context, Solver,
};

/// SMT solver adapter for definitive satisfiability checks.
#[derive(Debug)]
pub struct SmtSolver {
    z3_context: Context,
}

/// SMT formula with declarations and assertions
#[derive(Debug, Clone)]
struct SmtFormula {
    declarations: Vec<String>,
    assertions: Vec<String>,
}

/// A definitive result from the SMT solver.
///
/// Z3's `unknown` result is returned as [`Error::SolverUnknown`], so this type
/// can only represent `sat` or `unsat`.
#[derive(Debug, Clone, Serialize)]
pub struct SmtResult {
    /// Whether the formula is satisfiable
    satisfiable: bool,
    /// Model (if satisfiable)
    model: Option<String>,
    /// Time taken to solve
    solve_time: Duration,
}

impl SmtResult {
    /// Whether Z3 definitively returned `sat`.
    pub fn is_satisfiable(&self) -> bool {
        self.satisfiable
    }

    /// Whether Z3 definitively returned `unsat`.
    pub fn is_unsatisfiable(&self) -> bool {
        !self.satisfiable
    }

    /// The model produced for a satisfiable formula, if Z3 supplied one.
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// Time spent in the definitive solver check.
    pub fn solve_time(&self) -> Duration {
        self.solve_time
    }
}

/// Function parameter information extracted from semantic analysis
#[derive(Debug, Clone)]
struct FunctionParameter {
    name: String,
    type_name: String,
    offset: usize,
}

impl SmtFormula {
    fn new() -> Self {
        Self {
            declarations: Vec::new(),
            assertions: Vec::new(),
        }
    }

    fn build_formula_string(&self) -> String {
        let mut parts = Vec::new();

        // Add all declarations
        for decl in &self.declarations {
            parts.push(decl.clone());
        }

        // Add all assertions
        for assertion in &self.assertions {
            parts.push(assertion.clone());
        }

        // Add check-sat
        parts.push("(check-sat)".to_string());

        parts.join("\n")
    }
}

impl SmtSolver {
    /// Create new SMT solver instance
    pub fn new() -> VerificationResult<Self> {
        let z3_config = Config::new();
        let z3_context = Context::new(&z3_config);

        Ok(Self { z3_context })
    }

    /// Check satisfiability of SMT formulas
    pub async fn check_satisfiability(&self, formulas: &[String]) -> VerificationResult<SmtResult> {
        if formulas.is_empty() {
            return Err(Error::IncompleteProof {
                reason: "no SMT assertions were supplied".to_string(),
            });
        }

        let start_time = std::time::Instant::now();
        let solver = Solver::new(&self.z3_context);

        // Parse and add each formula
        for formula in formulas {
            self.parse_and_add_formula(&solver, formula)?;
        }

        // Check satisfiability
        let satisfiable = Self::definitive_satisfiability(solver.check())?;

        // Get model if satisfiable
        let model = if satisfiable {
            solver.get_model().map(|m| m.to_string())
        } else {
            None
        };

        let solve_time = start_time.elapsed();

        Ok(SmtResult {
            satisfiable,
            model,
            solve_time,
        })
    }

    fn definitive_satisfiability(result: z3::SatResult) -> VerificationResult<bool> {
        match result {
            z3::SatResult::Sat => Ok(true),
            z3::SatResult::Unsat => Ok(false),
            z3::SatResult::Unknown => Err(Error::SolverUnknown(
                "Z3 did not return sat or unsat".to_string(),
            )),
        }
    }

    /// Parse and add SMT formula to solver
    fn parse_and_add_formula(&self, solver: &z3::Solver, formula: &str) -> VerificationResult<()> {
        if formula.trim().starts_with("(assert") {
            let content = self.extract_assertion_content(formula)?;
            let ast = self.parse_assertion_content(&content)?;
            solver.assert(&ast);
            Ok(())
        } else if formula.trim().starts_with("(declare-") {
            Err(Error::Unsupported(
                "standalone declarations are not supported by the typed SMT adapter; no assertion was checked"
                    .to_string(),
            ))
        } else {
            Err(Error::Unsupported(format!(
                "unsupported formula format: {formula}",
            )))
        }
    }

    fn extract_assertion_content(&self, formula: &str) -> VerificationResult<String> {
        let content = Self::exact_application_body(formula, "assert")?;
        if content.is_empty() {
            return Err(Error::IncompleteProof {
                reason: "SMT assertion has an empty body".to_string(),
            });
        }
        Ok(content.to_string())
    }

    /// Return the body of one exact S-expression application.
    ///
    /// This intentionally rejects trailing commands and unbalanced or surplus
    /// parentheses. The adapter must never solve a lossy approximation of the
    /// caller's input.
    fn exact_application_body<'a>(
        expression: &'a str,
        operator: &str,
    ) -> VerificationResult<&'a str> {
        let expression = expression.trim();
        if !expression.starts_with('(') || !expression.ends_with(')') {
            return Err(Error::Unsupported(format!(
                "expected one complete `{operator}` expression: {expression}",
            )));
        }

        let mut depth = 0usize;
        for (offset, character) in expression.char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    if depth == 0 {
                        return Err(Error::Unsupported(format!(
                            "unbalanced SMT expression: {expression}",
                        )));
                    }
                    depth -= 1;
                    if depth == 0 && offset + character.len_utf8() != expression.len() {
                        return Err(Error::Unsupported(format!(
                            "trailing SMT input is not supported: {expression}",
                        )));
                    }
                }
                _ => {}
            }
        }
        if depth != 0 {
            return Err(Error::Unsupported(format!(
                "unbalanced SMT expression: {expression}",
            )));
        }

        let inner = &expression[1..expression.len() - 1];
        let rest = inner.strip_prefix(operator).ok_or_else(|| {
            Error::Unsupported(format!(
                "expected `{operator}` application, got: {expression}",
            ))
        })?;
        if !rest.is_empty() && !rest.chars().next().is_some_and(char::is_whitespace) {
            return Err(Error::Unsupported(format!(
                "invalid `{operator}` application: {expression}",
            )));
        }

        Ok(rest.trim())
    }

    fn parse_assertion_content(&self, content: &str) -> VerificationResult<ast::Bool<'_>> {
        let content = content.trim();

        // Handle basic patterns
        if content == "true" {
            Ok(ast::Bool::from_bool(&self.z3_context, true))
        } else if content == "false" {
            Ok(ast::Bool::from_bool(&self.z3_context, false))
        } else if content.starts_with("(=") {
            self.parse_equality(content)
        } else if content.starts_with("(>=") {
            self.parse_comparison(content, ">=")
        } else if content.starts_with("(<=") {
            self.parse_comparison(content, "<=")
        } else if content.starts_with("(>") {
            self.parse_comparison(content, ">")
        } else if content.starts_with("(<") {
            self.parse_comparison(content, "<")
        } else if content.starts_with("(not") {
            self.parse_not(content)
        } else {
            Err(Error::Unsupported(format!(
                "unsupported SMT assertion: {content}",
            )))
        }
    }

    fn parse_equality(&self, content: &str) -> VerificationResult<ast::Bool<'_>> {
        let inner = Self::exact_application_body(content, "=")?;
        let parts: Vec<&str> = inner.split_whitespace().collect();
        if parts.len() == 2 {
            let left = self.parse_term(parts[0])?;
            let right = self.parse_term(parts[1])?;
            Ok(left._eq(&right))
        } else {
            Err(Error::Unsupported(format!(
                "equality requires exactly two simple terms: {content}",
            )))
        }
    }

    fn parse_comparison(&self, content: &str, op: &str) -> VerificationResult<ast::Bool<'_>> {
        let inner = Self::exact_application_body(content, op)?;
        let parts: Vec<&str> = inner.split_whitespace().collect();
        if parts.len() == 2 {
            let left = self.parse_int_term(parts[0])?;
            let right = self.parse_int_term(parts[1])?;
            match op {
                ">" => Ok(left.gt(&right)),
                ">=" => Ok(left.ge(&right)),
                "<" => Ok(left.lt(&right)),
                "<=" => Ok(left.le(&right)),
                _ => Err(Error::Unsupported(format!(
                    "unsupported comparison operator: {op}",
                ))),
            }
        } else {
            Err(Error::Unsupported(format!(
                "comparison requires exactly two simple terms: {content}",
            )))
        }
    }

    fn parse_not(&self, content: &str) -> VerificationResult<ast::Bool<'_>> {
        let inner = Self::exact_application_body(content, "not")?;
        let inner_ast = self.parse_assertion_content(inner)?;
        Ok(inner_ast.not())
    }

    fn parse_term(&self, term: &str) -> VerificationResult<ast::Dynamic<'_>> {
        // Try to parse as integer first
        if let Ok(value) = term.parse::<i64>() {
            Ok(ast::Int::from_i64(&self.z3_context, value).into())
        } else if let Some(stripped) = term.strip_prefix("#x") {
            if let Ok(value) = i64::from_str_radix(stripped, 16) {
                Ok(ast::Int::from_i64(&self.z3_context, value).into())
            } else {
                Err(Error::Unsupported(format!(
                    "invalid or out-of-range hexadecimal integer literal: {term}",
                )))
            }
        } else {
            self.validate_identifier(term)?;
            Ok(ast::Int::new_const(&self.z3_context, term).into())
        }
    }

    fn parse_int_term(&self, term: &str) -> VerificationResult<ast::Int<'_>> {
        if let Ok(value) = term.parse::<i64>() {
            Ok(ast::Int::from_i64(&self.z3_context, value))
        } else if let Some(stripped) = term.strip_prefix("#x") {
            if let Ok(value) = i64::from_str_radix(stripped, 16) {
                Ok(ast::Int::from_i64(&self.z3_context, value))
            } else {
                Err(Error::Unsupported(format!(
                    "invalid or out-of-range hexadecimal integer literal: {term}",
                )))
            }
        } else {
            self.validate_identifier(term)?;
            Ok(ast::Int::new_const(&self.z3_context, term))
        }
    }

    fn validate_identifier(&self, identifier: &str) -> VerificationResult<()> {
        let mut chars = identifier.chars();
        let starts_validly = chars
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic() || character == '_');
        let remainder_is_valid = chars
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'));
        if starts_validly && remainder_is_valid {
            Ok(())
        } else {
            Err(Error::Unsupported(format!(
                "unsupported SMT identifier: {identifier}",
            )))
        }
    }

    /// Generate SMT formulas from contract semantics
    pub fn encode_contract_semantics(
        &self,
        semantics: &ContractSemantics,
    ) -> VerificationResult<String> {
        let mut formula = SmtFormula::new();

        // Declare basic types
        self.declare_basic_types(&mut formula);

        // Encode storage layout
        self.encode_contract_state(&mut formula, semantics)?;

        // Encode function implementations
        self.encode_execution_semantics(&mut formula, semantics)?;

        // Encode state invariants
        self.encode_state_invariants(&mut formula, semantics)?;

        Ok(formula.build_formula_string())
    }

    fn declare_basic_types(&self, formula: &mut SmtFormula) {
        formula.declarations.extend([
            "; Basic EVM types".to_string(),
            "(declare-sort Address 0)".to_string(),
            "(declare-sort Storage 0)".to_string(),
            "(declare-sort State 0)".to_string(),
            "(declare-sort Transaction 0)".to_string(),
            "(declare-sort ExecResult 0)".to_string(),
            "".to_string(),
            "; Transaction structure with proper calldata model".to_string(),
            "(declare-fun function-selector (Transaction) Int)".to_string(),
            "(declare-fun calldata-word (Transaction Int) Int)".to_string(),
            "(declare-fun calldata-length (Transaction) Int)".to_string(),
            "(declare-fun sender (Transaction) Address)".to_string(),
            "(declare-fun value (Transaction) Int)".to_string(),
            "(declare-fun gas-limit (Transaction) Int)".to_string(),
            "".to_string(),
            "; State access functions".to_string(),
            "(declare-fun storage (State) Storage)".to_string(),
            "(declare-fun block-number (State) Int)".to_string(),
            "(declare-fun block-timestamp (State) Int)".to_string(),
            "".to_string(),
            "; Execution result functions".to_string(),
            "(declare-fun success (ExecResult) Bool)".to_string(),
            "(declare-fun final-state (ExecResult) State)".to_string(),
            "(declare-fun gas-used (ExecResult) Int)".to_string(),
            "(declare-fun revert-reason (ExecResult) Int)".to_string(),
            "".to_string(),
            "; Transaction constraints".to_string(),
            "(assert (forall ((tx Transaction)) (and (>= (function-selector tx) 0) (< (function-selector tx) 4294967296))))".to_string(),
            "(assert (forall ((tx Transaction)) (>= (calldata-length tx) 4)))".to_string(),
            "(assert (forall ((tx Transaction)) (>= (value tx) 0)))".to_string(),
            "(assert (forall ((tx Transaction)) (>= (gas-limit tx) 21000)))".to_string(),
            "".to_string(),
        ]);
    }

    fn encode_contract_state(
        &self,
        formula: &mut SmtFormula,
        semantics: &ContractSemantics,
    ) -> VerificationResult<()> {
        formula
            .declarations
            .push("; Contract storage layout".to_string());

        for (slot, value_type) in &semantics.storage_layout {
            match value_type.as_str() {
                "uint256" => {
                    formula
                        .declarations
                        .push(format!("(declare-fun storage-slot-{slot} (Storage) Int)"));
                    // Add bounds for uint256
                    formula.assertions.push(format!(
                        "(assert (forall ((s Storage)) (and (>= (storage-slot-{slot} s) 0) (< (storage-slot-{slot} s) (^ 2 256)))))",
                    ));
                }
                "address" => {
                    formula.declarations.push(format!(
                        "(declare-fun storage-slot-{slot} (Storage) Address)",
                    ));
                }
                "mapping(address=>uint256)" => {
                    formula.declarations.push(format!(
                        "(declare-fun mapping-{slot} (Storage Address) Int)",
                    ));
                    // Add bounds for balance values
                    formula.assertions.push(format!(
                        "(assert (forall ((s Storage) (address Address)) (>= (mapping-{slot} s address) 0)))",
                    ));
                }
                _ => {
                    // Generic storage slot
                    formula
                        .declarations
                        .push(format!("(declare-fun storage-slot-{slot} (Storage) Int)"));
                }
            }
        }

        formula.declarations.push("".to_string());
        Ok(())
    }

    fn encode_execution_semantics(
        &self,
        formula: &mut SmtFormula,
        semantics: &ContractSemantics,
    ) -> VerificationResult<()> {
        formula
            .declarations
            .push("; Function declarations".to_string());

        for function in &semantics.functions {
            // Declare function
            formula.declarations.push(format!(
                "(declare-fun {} (State Transaction) ExecResult)",
                function.name
            ));

            // Encode function logic
            if let Some(selector) = function.selector {
                self.encode_function_logic(formula, function, selector)?;
            }
        }

        formula.declarations.push("".to_string());
        Ok(())
    }

    fn encode_function_logic(
        &self,
        formula: &mut SmtFormula,
        function: &FunctionSemantics,
        selector: [u8; 4],
    ) -> VerificationResult<()> {
        // Function selector check using proper transaction model
        formula.assertions.push(format!(
            "(assert (forall ((s State) (tx Transaction))
                (=> (not (= (function-selector tx) #x{}))
                    (= (success ({} s tx)) false))))",
            hex::encode(selector),
            function.name
        ));

        // Extract function parameters based on selector
        let parameters = self.extract_function_parameters(function, selector)?;

        // Declare parameter extraction functions
        for param in parameters.iter() {
            formula.declarations.push(format!(
                "(declare-fun {}-{} (Transaction) {})",
                function.name,
                param.name,
                self.solidity_type_to_smt(&param.type_name)
            ));

            // Link to calldata
            formula.assertions.push(format!(
                "(assert (forall ((tx Transaction))
                    (= ({}-{} tx) (calldata-word tx {}))))",
                function.name, param.name, param.offset
            ));
        }

        // Encode preconditions with real parameter references
        for precondition in &function.preconditions {
            let processed_precondition =
                self.process_precondition(precondition, function, &parameters)?;
            formula.assertions.push(format!(
                "(assert (forall ((s State) (tx Transaction))
                    (=> (and (= (function-selector tx) #x{}) (not {}))
                        (= (success ({} s tx)) false))))",
                hex::encode(selector),
                processed_precondition,
                function.name
            ));
        }

        // Encode state modifications with proper parameter references
        for modification in &function.state_modifications {
            self.encode_state_modification_with_params(
                formula,
                function,
                modification,
                &parameters,
            )?;
        }

        // Encode postconditions
        for postcondition in &function.postconditions {
            let processed_postcondition =
                self.process_postcondition(postcondition, function, &parameters)?;
            formula.assertions.push(format!(
                "(assert (forall ((s State) (tx Transaction) (result ExecResult))
                    (=> (and (= result ({} s tx)) (success result))
                        {})))",
                function.name, processed_postcondition
            ));
        }

        // Add revert conditions for common failure cases
        self.encode_revert_conditions(formula, function, selector, &parameters)?;

        Ok(())
    }

    /// Extract function parameters from semantic analysis
    fn extract_function_parameters(
        &self,
        _function: &FunctionSemantics,
        selector: [u8; 4],
    ) -> VerificationResult<Vec<FunctionParameter>> {
        let mut parameters = Vec::new();

        // Common ERC20 function parameters
        match selector {
            [0xa9, 0x05, 0x9c, 0xbb] => {
                // transfer(address,uint256)
                parameters.push(FunctionParameter {
                    name: "recipient".to_string(),
                    type_name: "address".to_string(),
                    offset: 4,
                });
                parameters.push(FunctionParameter {
                    name: "amount".to_string(),
                    type_name: "uint256".to_string(),
                    offset: 36,
                });
            }
            [0x70, 0xa0, 0x82, 0x31] => {
                // balanceOf(address)
                parameters.push(FunctionParameter {
                    name: "account".to_string(),
                    type_name: "address".to_string(),
                    offset: 4,
                });
            }
            [0xa0, 0x71, 0x2d, 0x68] => {
                // mint(uint256)
                parameters.push(FunctionParameter {
                    name: "amount".to_string(),
                    type_name: "uint256".to_string(),
                    offset: 4,
                });
            }
            _ => {
                // Generic parameter extraction based on function name
                tracing::debug!(
                    "Unknown function selector {:?}, using generic parameters",
                    selector
                );
            }
        }

        Ok(parameters)
    }

    fn solidity_type_to_smt(&self, solidity_type: &str) -> &str {
        match solidity_type {
            "address" => "Int", // Simplified as 160-bit integer
            "uint256" | "uint" => "Int",
            "int256" | "int" => "Int",
            "bool" => "Bool",
            "bytes32" => "Int",
            _ => "Int", // Default fallback
        }
    }

    fn process_precondition(
        &self,
        condition: &str,
        function: &FunctionSemantics,
        parameters: &[FunctionParameter],
    ) -> VerificationResult<String> {
        let mut processed = condition.to_string();

        // Replace parameter references
        for param in parameters {
            let param_ref = format!("{}-{}", function.name, param.name);
            processed = processed.replace("(transfer-amount tx)", &format!("({param_ref} tx)"));
            processed = processed.replace("(recipient tx)", &format!("({param_ref} tx)"));
        }

        // Replace common patterns
        processed = processed.replace(
            "(balance sender state)",
            "(mapping-0 (storage state) (sender tx))",
        );

        Ok(processed)
    }

    fn process_postcondition(
        &self,
        condition: &str,
        function: &FunctionSemantics,
        parameters: &[FunctionParameter],
    ) -> VerificationResult<String> {
        // Similar processing to preconditions
        self.process_precondition(condition, function, parameters)
    }

    fn encode_state_modification_with_params(
        &self,
        formula: &mut SmtFormula,
        function: &FunctionSemantics,
        modification: &StateModification,
        parameters: &[FunctionParameter],
    ) -> VerificationResult<()> {
        match modification.modification_type {
            ModificationType::Assignment => {
                // Find the appropriate parameter value
                let value_expr = if parameters.iter().any(|p| p.name == "amount") {
                    format!("{}-amount tx", function.name)
                } else {
                    "0".to_string() // Fallback
                };

                formula.assertions.push(format!(
                    "(assert (forall ((s State) (tx Transaction) (result ExecResult))
                        (=> (and (= result ({} s tx)) (success result))
                            (= (storage-slot-{} (storage (final-state result)))
                               {}))))",
                    function.name, modification.storage_slot, value_expr
                ));
            }
            ModificationType::Collection => {
                // Handle mapping updates (e.g., ERC20 balances)
                if let Some(amount_param) = parameters.iter().find(|p| p.name == "amount") {
                    if let Some(recipient_param) = parameters.iter().find(|p| p.name == "recipient")
                    {
                        // Transfer logic: sender balance decreases, recipient balance increases
                        formula.assertions.push(format!(
                            "(assert (forall ((s State) (tx Transaction) (result ExecResult))
                                (=> (and (= result ({} s tx)) (success result))
                                    (and 
                                        ; Sender balance decreases
                                        (= (mapping-{} (storage (final-state result)) (sender tx))
                                           (- (mapping-{} (storage s) (sender tx)) ({}-{} tx)))
                                        ; Recipient balance increases  
                                        (= (mapping-{} (storage (final-state result)) ({}-{} tx))
                                           (+ (mapping-{} (storage s) ({}-{} tx)) ({}-{} tx)))))))",
                            function.name,
                            modification.storage_slot,
                            modification.storage_slot,
                            function.name,
                            amount_param.name,
                            modification.storage_slot,
                            function.name,
                            recipient_param.name,
                            modification.storage_slot,
                            function.name,
                            recipient_param.name,
                            function.name,
                            amount_param.name
                        ));
                    }
                }
            }
            _ => {
                // Fallback to original implementation
                self.encode_state_modification(formula, function, modification)?;
            }
        }
        Ok(())
    }

    fn encode_revert_conditions(
        &self,
        formula: &mut SmtFormula,
        function: &FunctionSemantics,
        selector: [u8; 4],
        _parameters: &[FunctionParameter],
    ) -> VerificationResult<()> {
        match selector {
            [0xa9, 0x05, 0x9c, 0xbb] => {
                // transfer(address,uint256)
                // Insufficient balance check
                formula.assertions.push(format!(
                    "(assert (forall ((s State) (tx Transaction))
                        (=> (< (mapping-0 (storage s) (sender tx)) ({}-amount tx))
                            (= (success ({} s tx)) false))))",
                    function.name, function.name
                ));

                // Transfer to zero address check
                formula.assertions.push(format!(
                    "(assert (forall ((s State) (tx Transaction))
                        (=> (= ({}-recipient tx) 0)
                            (= (success ({} s tx)) false))))",
                    function.name, function.name
                ));

                // Amount must be positive
                formula.assertions.push(format!(
                    "(assert (forall ((s State) (tx Transaction))
                        (=> (<= ({}-amount tx) 0)
                            (= (success ({} s tx)) false))))",
                    function.name, function.name
                ));
            }
            _ => {
                // Generic revert conditions
                formula.assertions.push(format!(
                    "(assert (forall ((s State) (tx Transaction))
                        (=> (< (gas-limit tx) {})
                            (= (success ({} s tx)) false))))",
                    function.gas_characteristics.base_cost, function.name
                ));
            }
        }
        Ok(())
    }

    fn encode_state_modification(
        &self,
        formula: &mut SmtFormula,
        function: &FunctionSemantics,
        modification: &StateModification,
    ) -> VerificationResult<()> {
        match modification.modification_type {
            ModificationType::Assignment => {
                formula.assertions.push(format!(
                    "(assert (forall ((s State) (tx Transaction) (result ExecResult))
                        (=> (and (= result ({} s tx)) (success result))
                            (= (storage-slot-{} (storage (final-state result)))
                               (value tx)))))",
                    function.name, modification.storage_slot
                ));
            }
            ModificationType::Arithmetic => {
                formula.assertions.push(format!(
                    "(assert (forall ((s State) (tx Transaction) (result ExecResult))
                        (=> (and (= result ({} s tx)) (success result))
                            (= (storage-slot-{} (storage (final-state result)))
                               (+ (storage-slot-{} (storage s)) (value tx))))))",
                    function.name, modification.storage_slot, modification.storage_slot
                ));
            }
            ModificationType::Conditional => {
                // Add conditional logic based on modification conditions
                for condition in &modification.conditions {
                    formula.assertions.push(format!(
                        "(assert (forall ((s State) (tx Transaction) (result ExecResult))
                            (=> (and (= result ({} s tx)) (success result) {})
                                (= (storage-slot-{} (storage (final-state result)))
                                   (value tx)))))",
                        function.name, condition, modification.storage_slot
                    ));
                }
            }
            ModificationType::Collection => {
                // Handle mapping/array updates
                formula.assertions.push(format!(
                    "(assert (forall ((s State) (tx Transaction) (result ExecResult))
                        (=> (and (= result ({} s tx)) (success result))
                            (= (mapping-{} (storage (final-state result)) (sender tx))
                               (value tx)))))",
                    function.name, modification.storage_slot
                ));
            }
        }
        Ok(())
    }

    fn encode_state_invariants(
        &self,
        formula: &mut SmtFormula,
        semantics: &ContractSemantics,
    ) -> VerificationResult<()> {
        formula.assertions.push("; State invariants".to_string());

        for invariant in &semantics.state_invariants {
            formula.assertions.push(format!("(assert {invariant})"));
        }

        Ok(())
    }

    /// Generate equivalence formula for two contracts
    pub fn generate_equivalence_formula(
        &self,
        original: &ContractSemantics,
        obfuscated: &ContractSemantics,
    ) -> VerificationResult<String> {
        let mut formula = SmtFormula::new();

        // Declare types
        self.declare_basic_types(&mut formula);

        // Declare both contract functions
        formula
            .declarations
            .push("; Original contract functions".to_string());
        for function in &original.functions {
            formula.declarations.push(format!(
                "(declare-fun {}-original (State Transaction) ExecResult)",
                function.name
            ));
        }

        formula
            .declarations
            .push("; Obfuscated contract functions".to_string());
        for function in &obfuscated.functions {
            formula.declarations.push(format!(
                "(declare-fun {}-obfuscated (State Transaction) ExecResult)",
                function.name
            ));
        }

        // State equivalence assertion
        formula.assertions.push(
            "(assert (forall ((s State) (tx Transaction))
                (= (final-state (execute-original s tx))
                   (final-state (execute-obfuscated s tx)))))"
                .to_string(),
        );

        // Success equivalence
        formula.assertions.push(
            "(assert (forall ((s State) (tx Transaction))
                (= (success (execute-original s tx))
                   (success (execute-obfuscated s tx)))))"
                .to_string(),
        );

        // Gas bounds (obfuscated should use at most 15% more gas)
        formula.assertions.push(
            "(assert (forall ((s State) (tx Transaction))
                (=> (success (execute-original s tx))
                    (<= (gas-used (execute-obfuscated s tx))
                        (* 115 (div (gas-used (execute-original s tx)) 100))))))"
                .to_string(),
        );

        Ok(formula.build_formula_string())
    }

    /// Prove that two contracts are equivalent
    pub async fn prove_equivalence(
        &self,
        _original: &ContractSemantics,
        _obfuscated: &ContractSemantics,
    ) -> VerificationResult<bool> {
        Err(Error::VerificationUnavailable {
            reason: "the current equivalence encoding is incomplete and does not encode a negated counterexample obligation"
                .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_smt_solver_creation() {
        let solver = SmtSolver::new();
        assert!(solver.is_ok());
    }

    #[tokio::test]
    async fn test_basic_formula_parsing() {
        let solver = SmtSolver::new().unwrap();

        let formulas = vec![
            "(assert true)".to_string(),
            "(assert false)".to_string(),
            "(assert (= x 42))".to_string(),
        ];

        let result = solver.check_satisfiability(&formulas).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.is_satisfiable());
        assert!(result.is_unsatisfiable());
        assert!(result.model().is_none());
        assert!(result.solve_time() <= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn empty_formula_set_is_rejected() {
        let solver = SmtSolver::new().unwrap();

        let error = solver.check_satisfiability(&[]).await.unwrap_err();
        assert!(matches!(error, Error::IncompleteProof { .. }));

        for empty_assertion in ["(assert)", "(assert )"] {
            let error = solver
                .check_satisfiability(&[empty_assertion.to_string()])
                .await
                .unwrap_err();
            assert!(
                matches!(error, Error::IncompleteProof { .. }),
                "{empty_assertion}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn declaration_is_not_silently_dropped() {
        let solver = SmtSolver::new().unwrap();
        let formulas = vec!["(declare-fun x () Int)".to_string()];

        let error = solver.check_satisfiability(&formulas).await.unwrap_err();
        assert!(matches!(error, Error::Unsupported(_)));
    }

    #[tokio::test]
    async fn unsupported_or_malformed_assertions_are_rejected() {
        let solver = SmtSolver::new().unwrap();

        for formula in [
            "(assert (and true true))",
            "(assert (= x))",
            "(assert (forall ((x Int)) true))",
            "(assert (= #xnot-hex 1))",
            "(assert true))",
            "(assert (= x 1)))",
            "(assert (= x 1)",
            "(assert true) (assert false)",
            "(assertion false)",
            "(assert (not))",
        ] {
            let error = solver
                .check_satisfiability(&[formula.to_string()])
                .await
                .unwrap_err();
            assert!(matches!(error, Error::Unsupported(_)), "{formula}: {error}");
        }
    }

    #[tokio::test]
    async fn unsupported_input_is_not_dropped_after_a_contradiction() {
        let solver = SmtSolver::new().unwrap();
        let formulas = vec![
            "(assert false)".to_string(),
            "(assert (and true true))".to_string(),
        ];

        let error = solver.check_satisfiability(&formulas).await.unwrap_err();
        assert!(matches!(error, Error::Unsupported(_)));
    }

    #[test]
    fn solver_unknown_is_not_classified_as_unsat() {
        let error = SmtSolver::definitive_satisfiability(z3::SatResult::Unknown).unwrap_err();
        assert!(matches!(error, Error::SolverUnknown(_)));
    }

    #[test]
    fn test_formula_building() {
        let mut formula = SmtFormula::new();
        formula
            .declarations
            .push("(declare-fun x () Int)".to_string());
        formula.assertions.push("(assert (> x 0))".to_string());

        let formula_str = formula.build_formula_string();
        assert!(formula_str.contains("declare-fun"));
        assert!(formula_str.contains("assert"));
        assert!(formula_str.contains("check-sat"));
    }
}
