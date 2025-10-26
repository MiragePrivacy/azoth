//! End to end ethereum tests.
//!
//! Test variations of obfuscation options:
//!   - Function dispatch only (all options off)
//!   - Each transformation type enabled
//!   - Each combination of 2 transformations
//!   - All options enabled
//!
//! Each test case should assert that the contract is deployable

use color_eyre::eyre::eyre;
use color_eyre::Result;
use revm::primitives::{Address, Bytes, FixedBytes, U256};
use std::collections::HashMap;

/// 4-byte function selector type
pub type Selector = FixedBytes<4>;

/// Mock ERC20 token address used in tests
#[allow(dead_code)]
pub const MOCK_TOKEN_ADDR: Address = Address::new([0x11; 20]);

/// Mock recipient address used in tests
#[allow(dead_code)]
pub const MOCK_RECIPIENT_ADDR: Address = Address::new([0x22; 20]);

/// Returns bytecode for a mock ERC20 token that always returns true
#[allow(dead_code)]
pub fn mock_token_bytecode() -> Bytes {
    Bytes::from_static(&[
        0x60, 0x01, 0x60, 0x00, 0x52, // PUSH1 1, PUSH1 0, MSTORE
        0x60, 0x20, 0x60, 0x00, 0xf3, // PUSH1 32, PUSH1 0, RETURN
    ])
}

#[allow(dead_code)]
pub const ESCROW_CONTRACT_DEPLOYMENT_BYTECODE: &str =
    include_str!("../../../examples/escrow-bytecode/artifacts/deployment_bytecode.hex");

#[allow(dead_code)]
pub const ESCROW_CONTRACT_RUNTIME_BYTECODE: &str =
    include_str!("../../../examples/escrow-bytecode/artifacts/runtime_bytecode.hex");

/// Prepare escrow contract bytecode with constructor arguments
#[allow(dead_code)]
pub fn prepare_bytecode(base_bytecode: &str) -> Result<Bytes> {
    let normalized_hex = azoth_core::normalize_hex_string(base_bytecode)
        .map_err(|e| eyre!("Failed to normalize bytecode: {}", e))?;

    let mut bytecode_bytes =
        hex::decode(&normalized_hex).map_err(|e| eyre!("Failed to decode bytecode: {}", e))?;

    if bytecode_bytes.is_empty() {
        return Err(eyre!("Empty bytecode"));
    }

    // ABI-encode constructor args: (address token, address recipient, uint256, uint256, uint256)
    bytecode_bytes.extend_from_slice(&[0; 12]); // pad token address
    bytecode_bytes.extend_from_slice(MOCK_TOKEN_ADDR.as_slice());
    bytecode_bytes.extend_from_slice(&[0; 12]); // pad recipient
    bytecode_bytes.extend_from_slice(MOCK_RECIPIENT_ADDR.as_slice());
    bytecode_bytes.extend_from_slice(&[0; 32]); // expectedAmount = 0
    bytecode_bytes.extend_from_slice(&[0; 32]); // currentRewardAmount = 0
    bytecode_bytes.extend_from_slice(&[0; 32]); // currentPaymentAmount = 0

    Ok(Bytes::from(bytecode_bytes))
}

/// Define contract selectors and generate mapping struct + helper methods
macro_rules! define_contract_selectors {
    (
        $contract:ident {
            $(
                $fn_name:ident: $selector:literal
            ),* $(,)?
        }
    ) => {
        paste::paste! {
            // Generate const selectors
            $(
                #[allow(dead_code)]
                pub const [<$contract:upper _ $fn_name:upper>]: Selector =
                    Selector::new(hex_literal::hex!($selector));
            )*

            /// Mapping of original selectors to obfuscated tokens
            #[derive(Debug, Clone)]
            pub struct [<$contract Mappings>] {
                $(
                    pub $fn_name: Selector,
                )*
            }

            impl [<$contract Mappings>] {
                /// Create mappings from obfuscator output (HashMap<u32, Vec<u8>>)
                #[allow(dead_code)]
                pub fn from_obfuscator_output(
                    selector_mapping: &HashMap<u32, Vec<u8>>
                ) -> Result<Self, String> {
                    let mut mappings = Self::default();

                    for (&original_u32, token) in selector_mapping {
                        if token.len() != 4 {
                            return Err(format!(
                                "Expected 4-byte token, got {} bytes for selector 0x{:08x}",
                                token.len(),
                                original_u32
                            ));
                        }

                        let obfuscated = Selector::from_slice(token);

                        match original_u32 {
                            $(
                                _ if original_u32 == u32::from_be_bytes([<$contract:upper _ $fn_name:upper>].0) => {
                                    mappings.$fn_name = obfuscated;
                                }
                            )*
                            _ => continue,
                        }
                    }

                    mappings.validate()?;
                    Ok(mappings)
                }

                /// Get obfuscated selector by original selector
                #[allow(dead_code)]
                pub fn get_obfuscated(&self, original: Selector) -> Option<Selector> {
                    match original {
                        $(
                            [<$contract:upper _ $fn_name:upper>] => Some(self.$fn_name),
                        )*
                        _ => None,
                    }
                }
            }

            impl Default for [<$contract Mappings>] {
                fn default() -> Self {
                    Self {
                        $(
                            $fn_name: Selector::ZERO,
                        )*
                    }
                }
            }
        }
    };
}

/// Macro to generate calldata builder methods
macro_rules! impl_calldata_builders {
    (
        $caller:ident for $mappings:ty {
            $(
                fn $method:ident($($param:ident: $type:tt),*) -> $field:ident;
            )*
        }
    ) => {
        pub struct $caller {
            #[allow(dead_code)]
            mappings: $mappings,
        }

        impl $caller {
            #[allow(dead_code)]
            pub fn new(mappings: $mappings) -> Self {
                Self { mappings }
            }

            $(
                #[allow(unused_mut, dead_code)]
                pub fn $method(&self, $($param: $type),*) -> Bytes {
                    let mut data = self.mappings.$field.0.to_vec();
                    $(
                        impl_calldata_builders!(@encode data, $param, $type);
                    )*
                    Bytes::from(data)
                }
            )*

            /// Parse boolean return value
            #[allow(dead_code)]
            pub fn parse_bool(&self, data: &[u8]) -> bool {
                data.len() >= 32 && data[31] != 0
            }

            /// Parse U256 return value
            #[allow(dead_code)]
            pub fn parse_u256(&self, data: &[u8]) -> U256 {
                if data.len() >= 32 {
                    U256::from_be_slice(&data[..32])
                } else {
                    U256::ZERO
                }
            }
        }
    };

    (@encode $data:ident, $param:ident, U256) => {
        $data.extend_from_slice(&$param.to_be_bytes::<32>());
    };

    (@encode $data:ident, $param:ident, Address) => {
        $data.extend_from_slice(&[0u8; 12]);
        $data.extend_from_slice($param.as_slice());
    };

    (@encode $data:ident, $param:ident, bool) => {
        let value = if $param { 1u8 } else { 0u8 };
        $data.extend_from_slice(&[0u8; 31]);
        $data.push(value);
    };
}

// Define escrow contract selectors
define_contract_selectors!(Escrow {
    fund: "a65e2cfd",
    bond: "9940686e",
    request_cancellation: "81972d00",
    resume: "046f7da2",
    collect: "ede7f6a3",
    is_bonded: "cb766a56",
    withdraw: "3ccfd60b",
    current_reward_amount: "5a4fd645",
    bond_amount: "8bd03d0a",
    original_reward_amount: "d415b3f9",
    bonded_executor: "1aa7c0ec",
    execution_deadline: "33ee5f35",
    current_payment_amount: "80f323a7",
    total_bonds_deposited: "fe03a460",
    cancellation_request: "308657d7",
    funded: "f3a504f2",
});

// Custom validation for critical escrow functions
impl EscrowMappings {
    fn validate(&self) -> Result<(), String> {
        let mut missing = Vec::new();

        if self.bond == Selector::ZERO {
            missing.push("bond");
        }
        if self.is_bonded == Selector::ZERO {
            missing.push("is_bonded");
        }
        if self.collect == Selector::ZERO {
            missing.push("collect");
        }

        if !missing.is_empty() {
            return Err(format!(
                "Missing critical selector mappings: {}",
                missing.join(", ")
            ));
        }

        Ok(())
    }
}

// Generate calldata builders for escrow functions
impl_calldata_builders!(ObfuscatedCaller for EscrowMappings {
    fn bond_call_data(amount: U256) -> bond;
    fn is_bonded_call_data() -> is_bonded;
    fn collect_call_data() -> collect;
    fn withdraw_call_data() -> withdraw;
    fn fund_call_data(reward_amount: U256, payment_amount: U256) -> fund;
    fn funded_call_data() -> funded;
});

/// Build standard (non-obfuscated) calldata for comparison tests
#[allow(dead_code)]
pub fn build_standard_calldata(selector: Selector, args: &[u8]) -> Bytes {
    let mut data = selector.0.to_vec();
    data.extend_from_slice(args);
    Bytes::from(data)
}

#[cfg(test)]
mod deploy;

#[cfg(test)]
mod escrow;

#[cfg(test)]
mod test_original;

#[cfg(test)]
mod test_counter;
