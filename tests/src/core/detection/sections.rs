use azoth_core::{
    decoder::decode_bytecode,
    detection::{locate_sections, Section, SectionKind},
};

const STORAGE_BYTECODE: &str = "6080604052348015600e575f5ffd5b50603e80601a5f395ff3fe60806040525f5ffdfea2646970667358221220e8c66682f723c073c8c5ec2c0de0795c9b8b64e310482b13bc56a554d057842b64736f6c634300081e0033";

#[tokio::test]
async fn test_full_deploy_payload_properties() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let (instructions, info, _, bytes) = decode_bytecode(STORAGE_BYTECODE, false).await.unwrap();

    tracing::debug!("Full deploy bytecode: {:?}", bytes);
    tracing::debug!("Instructions: {:?}", instructions);
    tracing::debug!("DecodeInfo: {:?}", info);

    let sections = locate_sections(&bytes, &instructions).unwrap();

    tracing::debug!("Detected sections: {:?}", sections);
    for (i, section) in sections.iter().enumerate() {
        tracing::debug!(
            "Section {}: kind={:?}, offset={}, len={}",
            i,
            section.kind,
            section.offset,
            section.len
        );
    }

    // Property 1: Sections must be non-overlapping
    assert_sections_non_overlapping(&sections);

    // Property 2: Sections must cover the entire bytecode with no gaps
    assert_full_coverage(&sections, bytes.len());

    // Property 3: Sections must be ordered by offset
    assert_sections_ordered(&sections);

    // Property 4: Each section must have non-zero length
    assert_sections_non_empty(&sections);

    // Property 5: Runtime section must exist for deployment bytecode
    assert_has_runtime_section(&sections);

    // Property 6: If Init exists, it must start at offset 0
    assert_init_starts_at_zero(&sections);

    // Property 7: If Auxdata exists, it must be the last section
    assert_auxdata_is_last(&sections, bytes.len());

    // Property 8: ConstructorArgs must be between Init and Runtime (if all exist)
    assert_constructor_args_position(&sections);

    // Property 9: Padding must come after Runtime but before Auxdata (if they exist)
    assert_padding_position(&sections);

    // Property 10: Section kinds must be unique (except for potential multiple paddings)
    assert_unique_section_kinds(&sections);
}

// Property test helper functions

#[allow(dead_code)]
fn assert_sections_non_overlapping(sections: &[Section]) {
    for i in 0..sections.len() {
        for j in i + 1..sections.len() {
            let a = &sections[i];
            let b = &sections[j];
            assert!(
                a.end() <= b.offset || b.end() <= a.offset,
                "Sections overlap: {a:?} and {b:?}"
            );
        }
    }
}

#[allow(dead_code)]
fn assert_full_coverage(sections: &[Section], total_len: usize) {
    let mut coverage = vec![false; total_len];

    for section in sections {
        let range = section.offset..section.end();
        for (i, covered) in coverage[range.clone()].iter_mut().enumerate() {
            let byte_index = section.offset + i;
            assert!(
                !*covered,
                "Byte {byte_index} is covered by multiple sections"
            );
            *covered = true;
        }
    }

    for (i, &covered) in coverage.iter().enumerate() {
        assert!(covered, "Byte {i} is not covered by any section");
    }
}

#[allow(dead_code)]
fn assert_sections_ordered(sections: &[Section]) {
    for window in sections.windows(2) {
        assert!(
            window[0].offset <= window[1].offset,
            "Sections not ordered by offset: {:?} comes before {:?}",
            window[0],
            window[1]
        );
    }
}

#[allow(dead_code)]
fn assert_sections_non_empty(sections: &[Section]) {
    for section in sections {
        assert!(section.len > 0, "Section has zero length: {section:?}");
    }
}

#[allow(dead_code)]
fn assert_has_runtime_section(sections: &[Section]) {
    let has_runtime = sections.iter().any(|s| s.kind == SectionKind::Runtime);
    assert!(
        has_runtime,
        "Deployment bytecode must have a Runtime section"
    );
}

#[allow(dead_code)]
fn assert_init_starts_at_zero(sections: &[Section]) {
    if let Some(init) = sections.iter().find(|s| s.kind == SectionKind::Init) {
        assert_eq!(init.offset, 0, "Init section must start at offset 0");
    }
}

#[allow(dead_code)]
fn assert_auxdata_is_last(sections: &[Section], total_len: usize) {
    if let Some(auxdata) = sections.iter().find(|s| s.kind == SectionKind::Auxdata) {
        assert_eq!(auxdata.end(), total_len, "Auxdata must be the last section");
    }
}

#[allow(dead_code)]
fn assert_constructor_args_position(sections: &[Section]) {
    let init_pos = sections.iter().position(|s| s.kind == SectionKind::Init);
    let args_pos = sections
        .iter()
        .position(|s| s.kind == SectionKind::ConstructorArgs);
    let runtime_pos = sections.iter().position(|s| s.kind == SectionKind::Runtime);

    if let (Some(init), Some(args), Some(runtime)) = (init_pos, args_pos, runtime_pos) {
        assert!(
            init < args && args < runtime,
            "ConstructorArgs must be between Init and Runtime"
        );
    }
}

#[allow(dead_code)]
fn assert_padding_position(sections: &[Section]) {
    let runtime_pos = sections.iter().position(|s| s.kind == SectionKind::Runtime);
    let padding_pos = sections.iter().position(|s| s.kind == SectionKind::Padding);
    let auxdata_pos = sections.iter().position(|s| s.kind == SectionKind::Auxdata);

    if let (Some(runtime), Some(padding)) = (runtime_pos, padding_pos) {
        assert!(runtime < padding, "Padding must come after Runtime");

        if let Some(auxdata) = auxdata_pos {
            assert!(padding < auxdata, "Padding must come before Auxdata");
        }
    }
}

#[allow(dead_code)]
fn assert_unique_section_kinds(sections: &[Section]) {
    let kinds = [
        SectionKind::Init,
        SectionKind::Runtime,
        SectionKind::ConstructorArgs,
        SectionKind::Auxdata,
        // Note: Padding can appear multiple times, so we don't check it
    ];

    for kind in &kinds {
        let count = sections.iter().filter(|s| s.kind == *kind).count();
        assert!(
            count <= 1,
            "Section kind {kind:?} appears {count} times, but should appear at most once"
        );
    }
}
