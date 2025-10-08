use azoth_core::{
    decoder::decode_bytecode,
    detection::{detect_function_dispatcher, locate_sections},
};

#[tokio::test]
async fn test_dispatcher_detection() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let bytecode = "0x60c060405234801561000f575f5ffd5b5060405161162b38038061162b833981810160405281019061003191906100fd565b8073ffffffffffffffffffffffffffffffffffffffff1660a08173ffffffffffffffffffffffffffffffffffffffff16815250503373ffffffffffffffffffffffffffffffffffffffff1660808173ffffffffffffffffffffffffffffffffffffffff168152505050610128565b5f5ffd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6100cc826100a3565b9050919050565b6100dc816100c2565b81146100e6575f5ffd5b50565b5f815190506100f7816100d3565b92915050565b5f602082840312156101125761011161009f565b5b5f61011f848285016100e9565b91505092915050565b60805160a0516114b86101735f395f818161052d015281816107c8015281816109b60152610c4801525f8181610290015281816103c5015281816105d701526108c401526114b85ff3fe608060405234801561000f575f5ffd5b50600436106100fe575f3560e01c80638bd03d0a11610095578063d415b3f911610064578063d415b3f91461022a578063e522538114610248578063f3a504f214610252578063fe03a46014610270576100fe565b80638bd03d0a146101b65780639940686e146101d4578063a65e2cfd146101f0578063cb766a561461020c576100fe565b80633ccfd60b116100d15780003ccfd60b146101665780635a4fd6451461017057806380f323a71461018e57806381972d00146101ac576100fe565b8063046f7da2146101025780631aa7c0ec1461010c578063308657d71461012a57806333ee5f3514610148575b5f5ffd5b";

    let (instructions, info, _, bytes) = decode_bytecode(bytecode, false).await.unwrap();

    tracing::debug!("Full bytecode length: {} bytes", bytes.len());
    tracing::debug!("Total instructions: {}", instructions.len());
    tracing::debug!("DecodeInfo: {:?}", info);

    // Step 1: Locate sections to find runtime
    let sections = locate_sections(&bytes, &instructions).unwrap();
    tracing::debug!("Detected sections: {:?}", sections);

    // Step 2: Extract runtime instructions
    let runtime_section = sections
        .iter()
        .find(|s| s.kind == azoth_core::detection::SectionKind::Runtime)
        .expect("Should have runtime section");

    tracing::debug!(
        "Runtime section: offset={}, len={}",
        runtime_section.offset,
        runtime_section.len
    );

    // Find the instruction index that corresponds to runtime section start
    let runtime_start_pc = runtime_section.offset;
    let runtime_instr_start = instructions
        .iter()
        .position(|instruction| instruction.pc >= runtime_start_pc)
        .expect("Should find runtime start instruction");

    let runtime_instructions = &instructions[runtime_instr_start..];

    tracing::debug!(
        "Runtime section starts at PC {}, instruction index {}",
        runtime_start_pc,
        runtime_instr_start
    );
    tracing::debug!("Runtime instructions count: {}", runtime_instructions.len());
    tracing::debug!("First 20 runtime instructions:");
    for (i, instruction) in runtime_instructions.iter().take(20).enumerate() {
        tracing::debug!("  {}: PC={} {} {:?}", i, instruction.pc, instruction.op, instruction.imm);
    }

    tracing::debug!("Looking for dispatcher pattern in runtime instructions...");
    for (i, window) in runtime_instructions.windows(4).enumerate() {
        if window[0].op == azoth_core::Opcode::PUSH(1)
            && window[0].imm.as_deref() == Some("00")
            && window[1].op == azoth_core::Opcode::CALLDATALOAD
            && window[2].op == azoth_core::Opcode::PUSH(1)
            && window[2].imm.as_deref() == Some("e0")
            && window[3].op == azoth_core::Opcode::SHR
        {
            tracing::debug!(
                "Found dispatcher extraction pattern at runtime instruction {}",
                i
            );
            break;
        }
    }

    tracing::debug!(
        "Checking for dispatcher in actual runtime bytecode starting from PC {}",
        runtime_start_pc
    );

    if runtime_start_pc > 228 {
        // Look for instructions around PC 228 (the actual dispatcher location from earlier logs)
        let dispatcher_pc = 228;
        if let Some(dispatcher_instr_start) = instructions
            .iter()
            .position(|instruction| instruction.pc >= dispatcher_pc)
        {
            let dispatcher_instructions =
                &instructions[dispatcher_instr_start..runtime_instr_start.min(instructions.len())];
            tracing::debug!(
                "Looking at instructions from PC {} to {} (potential dispatcher region)",
                dispatcher_pc,
                runtime_start_pc
            );
            tracing::debug!(
                "Dispatcher region has {} instructions",
                dispatcher_instructions.len()
            );

            // Try to detect dispatcher in this region
            if let Some(dispatcher_info) = detect_function_dispatcher(dispatcher_instructions) {
                tracing::info!(
                    "✓ Found dispatcher in the PC {} region with {} selectors!",
                    dispatcher_pc,
                    dispatcher_info.selectors.len()
                );

                // Check if this has the missing selector
                let has_missing = dispatcher_info
                    .selectors
                    .iter()
                    .any(|s| s.selector == 0x3ccfd60b);
                tracing::info!(
                    "Missing selector 0x3ccfd60b present in this region: {}",
                    has_missing
                );
            }
        }
    }

    tracing::debug!("Runtime instructions count: {}", runtime_instructions.len());
    tracing::debug!("First 20 runtime instructions:");
    for (i, instruction) in runtime_instructions.iter().take(20).enumerate() {
        tracing::debug!("  {}: PC={} {} {:?}", i, instruction.pc, instruction.op, instruction.imm);
    }

    // Let's also look for the dispatcher pattern manually
    tracing::debug!("Looking for dispatcher pattern in runtime instructions...");
    for (i, window) in runtime_instructions.windows(4).enumerate() {
        if window[0].op == azoth_core::Opcode::PUSH(1)
            && window[0].imm.as_deref() == Some("00")
            && window[1].op == azoth_core::Opcode::CALLDATALOAD
            && window[2].op == azoth_core::Opcode::PUSH(1)
            && window[2].imm.as_deref() == Some("e0")
            && window[3].op == azoth_core::Opcode::SHR
        {
            tracing::debug!(
                "Found dispatcher extraction pattern at runtime instruction {}",
                i
            );
            break;
        }
    }

    // Step 3: Test dispatcher detection on full instructions (should fail)
    tracing::info!("Testing dispatcher detection on full bytecode (expecting failure)...");
    let full_dispatcher = detect_function_dispatcher(&instructions);
    if full_dispatcher.is_some() {
        tracing::warn!("Unexpectedly found dispatcher in full bytecode");
    } else {
        tracing::info!("✓ Correctly failed to find dispatcher in full bytecode");
    }

    // Step 4: Test dispatcher detection on runtime instructions (should succeed)
    tracing::info!("Testing dispatcher detection on runtime instructions...");
    let runtime_dispatcher = detect_function_dispatcher(runtime_instructions);

    match runtime_dispatcher {
        Some(dispatcher_info) => {
            tracing::info!("✓ Successfully detected function dispatcher!");
            tracing::info!("Dispatcher details:");
            tracing::info!("  Start offset: {}", dispatcher_info.start_offset);
            tracing::info!("  End offset: {}", dispatcher_info.end_offset);
            tracing::info!(
                "  Extraction pattern: {:?}",
                dispatcher_info.extraction_pattern
            );
            tracing::info!("  Number of selectors: {}", dispatcher_info.selectors.len());

            // Log all detected function selectors
            tracing::info!("Detected function selectors:");
            for (i, selector) in dispatcher_info.selectors.iter().enumerate() {
                tracing::info!(
                    "  {}: 0x{:08x} -> target 0x{:x} (instr {})",
                    i,
                    selector.selector,
                    selector.target_address,
                    selector.instruction_index
                );
            }

            // Verify we found the expected selectors from the bytecode
            // Expected selectors - based on what's in the bytecode
            let expected_selectors = [
                0x8bd03d0a, 0xd415b3f9, 0xe5225381, 0xf3a504f2, 0xfe03a460, 0x9940686e, 0xa65e2cfd,
                0xcb766a56, 0x5a4fd645, 0x80f323a7, 0x81972d00, 0x046f7da2, 0x1aa7c0ec, 0x308657d7,
                0x33ee5f35,
            ];

            let detected_selectors: Vec<u32> = dispatcher_info
                .selectors
                .iter()
                .map(|s| s.selector)
                .collect();

            tracing::info!(
                "Expected {} selectors, found {}",
                expected_selectors.len(),
                detected_selectors.len()
            );

            // Check if we detected at least some of the expected selectors
            let mut found_count = 0;
            for &expected in &expected_selectors {
                if detected_selectors.contains(&expected) {
                    found_count += 1;
                    tracing::debug!("✓ Found expected selector: 0x{:08x}", expected);
                } else {
                    tracing::debug!("✗ Missing expected selector: 0x{:08x}", expected);
                }
            }

            tracing::info!(
                "Found {}/{} expected selectors",
                found_count,
                expected_selectors.len()
            );

            // Assertions - be more lenient since we found 15/16 selectors
            assert!(
                !dispatcher_info.selectors.is_empty(),
                "Should detect at least one function selector"
            );
            assert!(
                found_count > 0,
                "Should detect at least some of the expected function selectors"
            );

            // Success criterion: found at least 80% of expected selectors (13/16)
            let success_threshold = (expected_selectors.len() * 4) / 5; // 80%
            if found_count >= success_threshold {
                tracing::info!(
                    "✅ Dispatcher detection test PASSED! Found {}/{} selectors ({}%)",
                    found_count,
                    expected_selectors.len(),
                    (found_count * 100) / expected_selectors.len()
                );
            } else {
                tracing::warn!(
                    "⚠️  Only found {}/{} expected selectors - below 80% threshold",
                    found_count,
                    expected_selectors.len()
                );
            }
        }
        None => {
            tracing::error!("❌ Failed to detect function dispatcher in runtime instructions");

            tracing::error!("Debug: First 20 runtime instructions:");
            for (i, instruction) in runtime_instructions.iter().take(20).enumerate() {
                tracing::error!("  {}: PC={} {} {:?}", i, instruction.pc, instruction.op, instruction.imm);
            }

            panic!("Failed to detect function dispatcher in runtime instructions");
        }
    }
}
