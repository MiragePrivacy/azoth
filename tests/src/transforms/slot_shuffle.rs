//! Unit tests for `slot_shuffle::init_literal_slots`.
//!
//! These pin down the invariants SlotShuffle relies on for init-section
//! safety: any storage slot the init section accesses must either be
//! excluded from the shuffle mapping (touched) or force the whole
//! transform to bail out (unresolved). The adjacency scan that shipped
//! before this test module had a latent hole for DUP/SWAP-shared slot
//! sources — a contract that used `PUSH <slot>; DUP1; SLOAD; ...; SSTORE`
//! in its constructor would have its slot silently shuffled,
//! desynchronising init writes from runtime reads. The current
//! implementation decodes init bytes into proper `Instruction`s and runs
//! the same `trace_slot_source` backward walk the runtime collection
//! phase uses, so DUP-shared patterns are caught; anything still
//! unresolved is reported so the caller can fail loud instead of
//! silently corrupting state.

use azoth_transform::slot_shuffle::init_literal_slots;
use std::collections::HashSet;

// Raw opcode byte constants — the helper under test operates on a byte
// slice, so constructing fixtures with these is the most direct form.
const PUSH0: u8 = 0x5f;
const PUSH1: u8 = 0x60;
const PUSH2: u8 = 0x61;
const SLOAD: u8 = 0x54;
const SSTORE: u8 = 0x55;
const DUP1: u8 = 0x80;
const SWAP1: u8 = 0x90;
const POP: u8 = 0x50;
const CALLER: u8 = 0x33;

#[test]
fn init_literal_slots_adjacent_sload() {
    // `PUSH1 0x07; SLOAD` — the simplest case: the slot literal sits
    // directly before the SLOAD.
    let bytes = vec![PUSH1, 0x07, SLOAD];
    let (touched, unresolved) = init_literal_slots(&bytes);
    let expected: HashSet<_> = std::iter::once((1usize, vec![0x07u8])).collect();
    assert_eq!(touched, expected);
    assert!(unresolved.is_empty());
}

#[test]
fn init_literal_slots_adjacent_sstore() {
    // `PUSH1 0x42; PUSH1 0x07; SSTORE` — SSTORE pops slot from top and
    // value from below, so the PUSH immediately before SSTORE (0x07)
    // is the slot.
    let bytes = vec![PUSH1, 0x42, PUSH1, 0x07, SSTORE];
    let (touched, unresolved) = init_literal_slots(&bytes);
    let expected: HashSet<_> = std::iter::once((1usize, vec![0x07u8])).collect();
    assert_eq!(touched, expected);
    assert!(unresolved.is_empty());
}

#[test]
fn init_literal_slots_push0_as_slot() {
    // `PUSH0; SLOAD` — slot 0 via the Shanghai `PUSH0` opcode.
    // Represented as `(width=0, slot_bytes=[])`.
    let bytes = vec![PUSH0, SLOAD];
    let (touched, unresolved) = init_literal_slots(&bytes);
    let expected: HashSet<_> = std::iter::once((0usize, Vec::<u8>::new())).collect();
    assert_eq!(touched, expected);
    assert!(unresolved.is_empty());
}

#[test]
fn init_literal_slots_detects_dup_shared_slot() {
    // The exact Solidity pattern that broke the old adjacency-only
    // scan:
    //
    //     PUSH1 0x07    ; slot
    //     DUP1          ; duplicate slot (stack: [0x07, 0x07])
    //     SLOAD         ; consume the DUP'd copy, leaves
    //                   ;   [0x07, stored_value]
    //     SWAP1         ; [stored_value, 0x07]
    //     SSTORE        ; write stored_value back to slot 0x07
    //
    // Neither SLOAD nor SSTORE is immediately preceded by a PUSH, so
    // the adjacency scan would miss slot 7 entirely; the trace-based
    // path must catch it via the backward walk through DUP1/SWAP1.
    let bytes = vec![PUSH1, 0x07, DUP1, SLOAD, SWAP1, SSTORE];
    let (touched, unresolved) = init_literal_slots(&bytes);
    let expected: HashSet<_> = std::iter::once((1usize, vec![0x07u8])).collect();
    assert_eq!(touched, expected);
    assert!(unresolved.is_empty());
}

#[test]
fn init_literal_slots_multiple_distinct_slots() {
    // Two independent reads of different slots end up as two entries
    // in the touched set.
    let bytes = vec![
        PUSH1, 0x01, SLOAD, POP, //
        PUSH1, 0x02, SLOAD,
    ];
    let (touched, unresolved) = init_literal_slots(&bytes);
    let mut expected: HashSet<(usize, Vec<u8>)> = HashSet::new();
    expected.insert((1, vec![0x01]));
    expected.insert((1, vec![0x02]));
    assert_eq!(touched, expected);
    assert!(unresolved.is_empty());
}

#[test]
fn init_literal_slots_unresolved_sstore_is_reported() {
    // `CALLER; SSTORE` — the slot comes from `CALLER` (msg.sender),
    // which the trace walker recognises as a runtime-provided value
    // and refuses to resolve. The SSTORE is added to the unresolved
    // list, which the caller in `apply()` uses to trigger a fail-loud
    // bail-out rather than silently proceeding with partial init
    // coverage.
    let bytes = vec![CALLER, SSTORE];
    let (touched, unresolved) = init_literal_slots(&bytes);
    assert!(touched.is_empty());
    assert_eq!(unresolved.len(), 1, "expected one unresolved SSTORE");
}

#[test]
fn init_literal_slots_unresolved_sload_is_ignored() {
    // SLOADs with a non-literal slot (e.g. from CALLER or a
    // keccak256-derived mapping key) are SAFE to leave untouched:
    // their slot is computed at runtime and isn't in
    // `slots_by_width` to begin with, so remapping literal slots
    // can't corrupt them. Unlike SSTORE, an unresolved SLOAD should
    // NOT force a bail-out.
    let bytes = vec![CALLER, SLOAD];
    let (touched, unresolved) = init_literal_slots(&bytes);
    assert!(touched.is_empty());
    assert!(unresolved.is_empty());
}

#[test]
fn init_literal_slots_empty_bytes_yields_empty_result() {
    let (touched, unresolved) = init_literal_slots(&[]);
    assert!(touched.is_empty());
    assert!(unresolved.is_empty());
}

#[test]
fn init_literal_slots_truncated_push_terminates_cleanly() {
    // PUSH2 with only 1 immediate byte — decoder stops at the
    // truncated instruction rather than reading out of bounds or
    // producing garbage. The preceding PUSH1 0x05; SSTORE pair is
    // still captured.
    let bytes = vec![PUSH1, 0x09, PUSH1, 0x05, SSTORE, PUSH2, 0x12];
    let (touched, unresolved) = init_literal_slots(&bytes);
    let expected: HashSet<_> = std::iter::once((1usize, vec![0x05u8])).collect();
    assert_eq!(touched, expected);
    assert!(unresolved.is_empty());
}

#[test]
fn init_literal_slots_wider_push_is_normalized() {
    // PUSH2 0x0007 and PUSH1 0x07 should end up as distinct entries
    // because the shuffle groups by width — a PUSH2 slot literal
    // permutes within the width-2 bucket, not the width-1 one. This
    // keeps the exclusion logic in `apply()` aligned with the
    // rewrite's width-keyed mapping.
    let bytes = vec![PUSH2, 0x00, 0x07, SLOAD];
    let (touched, unresolved) = init_literal_slots(&bytes);
    let expected: HashSet<_> = std::iter::once((2usize, vec![0x00u8, 0x07u8])).collect();
    assert_eq!(touched, expected);
    assert!(unresolved.is_empty());
}
