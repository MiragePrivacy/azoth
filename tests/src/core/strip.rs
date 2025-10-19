use azoth_core::decoder::decode_bytecode;
use azoth_core::detection;
use azoth_core::strip::strip_bytecode;

#[tokio::test]
async fn test_round_trip() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    // Fixture: Init (6 bytes) + Runtime (2 bytes) + Auxdata (6 bytes)
    let bytecode = hex::decode("600a600e600039600af3deadbeef6001a165627a7a72").unwrap();
    let (instructions, _, _, _) = decode_bytecode(&format!("0x{}", hex::encode(&bytecode)), false)
        .await
        .unwrap();
    let sections = detection::locate_sections(&bytecode, &instructions).unwrap();

    let (clean_runtime, mut report) = strip_bytecode(&bytecode, &sections).unwrap();
    let rebuilt = report.reassemble(&clean_runtime);

    assert_eq!(bytecode, rebuilt, "Round-trip failed");
    assert_eq!(report.clean_len, 2, "Clean runtime length mismatch");
    assert_eq!(
        report.bytes_saved,
        bytecode.len() - clean_runtime.len(),
        "Bytes saved mismatch"
    );
}

#[tokio::test]
async fn test_runtime_only() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    // Fixture: Runtime-only bytecode (2 bytes)
    let bytecode = hex::decode("6001").unwrap();
    let (instructions, _, _, _) = decode_bytecode(&format!("0x{}", hex::encode(&bytecode)), false)
        .await
        .unwrap();
    let sections = detection::locate_sections(&bytecode, &instructions).unwrap();

    let (clean_runtime, mut report) = strip_bytecode(&bytecode, &sections).unwrap();
    let rebuilt = report.reassemble(&clean_runtime);

    assert_eq!(bytecode, rebuilt, "Round-trip failed");
    assert_eq!(report.clean_len, 2, "Clean runtime length mismatch");
    assert_eq!(report.bytes_saved, 0, "Bytes saved should be 0");
    assert!(report.removed.is_empty(), "Removed should be empty");
}
