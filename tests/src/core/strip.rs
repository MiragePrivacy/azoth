use azoth_core::decoder::decode_bytecode;
use azoth_core::detection::{self, SectionKind};
use azoth_core::strip::strip_bytecode;

const COUNTER_DEPLOYMENT_BYTECODE: &str =
    include_str!("../../bytecode/counter/counter_deployment.hex");

const COUNTER_RUNTIME_BYTECODE: &str = include_str!("../../bytecode/counter/counter_runtime.hex");

#[tokio::test]
async fn test_round_trip() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();

    let (instructions, _, _, bytecode) = decode_bytecode(COUNTER_DEPLOYMENT_BYTECODE, false)
        .await
        .unwrap();
    let sections = detection::locate_sections(&bytecode, &instructions).unwrap();

    let (clean_runtime, mut report) = strip_bytecode(&bytecode, &sections).unwrap();
    let rebuilt = report.reassemble(&clean_runtime);

    assert_eq!(bytecode, rebuilt, "Round-trip failed");
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
        .with_ansi(false)
        .without_time()
        .init();

    let (instructions, _, _, bytecode) = decode_bytecode(COUNTER_RUNTIME_BYTECODE, false)
        .await
        .unwrap();
    let sections = detection::locate_sections(&bytecode, &instructions).unwrap();

    let (clean_runtime, mut report) = strip_bytecode(&bytecode, &sections).unwrap();
    let rebuilt = report.reassemble(&clean_runtime);

    assert_eq!(bytecode, rebuilt, "Round-trip failed");

    // runtime only bytecode should not have Init or ConstructorArgs sections
    // but it may have Auxdata that gets stripped
    for section in &report.removed {
        assert!(
            matches!(section.kind, SectionKind::Auxdata),
            "Runtime-only bytecode should only strip Auxdata, not {:?}",
            section.kind
        );
    }

    assert_eq!(
        report.bytes_saved,
        bytecode.len() - clean_runtime.len(),
        "Bytes saved mismatch"
    );
}
