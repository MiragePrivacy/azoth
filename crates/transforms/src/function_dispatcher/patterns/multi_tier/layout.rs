use super::blueprint::{DispatcherBlueprint, RouteDestination, TierAssignment, TierRoute};
use crate::function_dispatcher::storage::StorageRoutingConfig;
use crate::function_dispatcher::FunctionDispatcher;
use crate::Error;
use azoth_core::cfg_ir::{Block, BlockBody, BlockControl, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{DispatcherInfo, FunctionSelector};
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use std::collections::HashMap;
use tracing::debug;

struct TierNodes {
    stub_pc: usize,
    decoy_pc: usize,
}

/// Result produced when a dispatch layout has been synthesised.
pub struct LayoutPlan {
    pub mapping: HashMap<u32, Vec<u8>>,
    pub extraction_modified: bool,
    pub dispatcher_modified: bool,
    #[allow(dead_code)]
    pub routing: StorageRoutingConfig,
}

pub fn apply_layout_plan(
    dispatcher: &FunctionDispatcher,
    ir: &mut CfgIrBundle,
    runtime: &[Instruction],
    index_by_pc: &HashMap<usize, (NodeIndex, usize)>,
    dispatcher_info: &DispatcherInfo,
    rng: &mut StdRng,
    blueprint: &DispatcherBlueprint,
) -> crate::Result<Option<LayoutPlan>> {
    let mut next_pc = highest_pc(ir).saturating_add(1);
    let mut new_nodes = Vec::new(); // Track all new nodes for later edge rebuilding

    let mut tiers: HashMap<usize, Vec<&TierAssignment>> = HashMap::new();
    for assignment in &blueprint.selectors {
        tiers
            .entry(assignment.tier_index)
            .or_default()
            .push(assignment);
    }

    let mut tier_nodes: HashMap<usize, TierNodes> = HashMap::new();
    for (tier_index, assignments) in tiers.iter() {
        if *tier_index == 0 {
            continue;
        }

        let Some(primary) = assignments.first() else {
            continue;
        };

        let target_pc = primary.selector.target_address as usize;
        let (target_node, _) = index_by_pc.get(&target_pc).ok_or_else(|| {
            Error::Generic(format!(
                "multi-tier: missing target pc 0x{target_pc:04x} in CFG mapping"
            ))
        })?;

        let target_node = *target_node;
        let (nodes, nodes_created, updated_pc) = create_tier_nodes(ir, next_pc, target_node)?;
        next_pc = updated_pc;
        new_nodes.extend(nodes_created); // Collect new nodes
        tier_nodes.insert(*tier_index, nodes);
    }

    if let Some((start, end)) = ir.runtime_bounds {
        if next_pc > end {
            ir.runtime_bounds = Some((start, next_pc));
        }
    }

    let result =
        dispatcher.try_apply_byte_pattern(ir, runtime, index_by_pc, dispatcher_info, rng)?;
    let Some(application) = result else {
        debug!("multi-tier layout: byte pattern not applicable");
        return Ok(None);
    };

    let mapping = application.mapping;
    let extraction_modified = application.extraction_modified;
    let mut dispatcher_modified = application.dispatcher_modified;

    let mut selector_entry_pcs = HashMap::new();
    for assignment in &blueprint.selectors {
        let target_pc = assignment.selector.target_address as usize;
        let fallback_pc = target_pc;
        let (stub_pc, decoy_pc) = tier_nodes
            .get(&assignment.tier_index)
            .map(|nodes| (nodes.stub_pc, nodes.decoy_pc))
            .unwrap_or((target_pc, target_pc));

        let tier_routes = routes_for_tier(blueprint, assignment.tier_index);
        let (controller_pc, controller_node, updated_pc) =
            create_selector_controller(ir, next_pc, &tier_routes, stub_pc, decoy_pc, fallback_pc)?;
        next_pc = updated_pc;
        new_nodes.push(controller_node); // Collect controller node
        selector_entry_pcs.insert(assignment.selector.selector, controller_pc);
    }

    let mut edits = Vec::new();
    for assignment in &blueprint.selectors {
        let Some(&controller_pc) = selector_entry_pcs.get(&assignment.selector.selector) else {
            continue;
        };

        if let Some(instr_idx) = locate_target_push(runtime, &assignment.selector) {
            let instr = &runtime[instr_idx];
            let pc = instr.pc;
            let (node, _) = index_by_pc.get(&pc).ok_or_else(|| {
                Error::Generic(format!(
                    "multi-tier: dispatcher instruction at pc 0x{pc:04x} missing from CFG"
                ))
            })?;

            let push_width = match instr.op {
                Opcode::PUSH(width) => width,
                _ => continue,
            };
            let formatted = format!(
                "{:0width$x}",
                controller_pc,
                width = push_width as usize * 2
            );
            edits.push((*node, pc, instr.op, Some(formatted)));
        } else {
            debug!(
                selector = format_args!("0x{:08x}", assignment.selector.selector),
                "multi-tier: unable to locate dispatcher target push"
            );
        }
    }

    if !edits.is_empty() {
        if dispatcher.apply_instruction_replacements(ir, edits)? {
            dispatcher_modified = true;
        }
    }

    // Recalculate PCs after all blocks have been added
    let (pc_mapping, old_runtime_bounds) = ir
        .reindex_pcs()
        .map_err(|e| Error::CoreError(e.to_string()))?;

    // Rebuild edges for all newly created blocks now that PCs are finalized
    for node in &new_nodes {
        ir.rebuild_edges_for_block(*node)
            .map_err(|e| Error::CoreError(e.to_string()))?;
    }

    // Update jump immediates to use the new PCs
    ir.patch_jump_immediates(&pc_mapping, old_runtime_bounds)
        .map_err(|e| Error::CoreError(e.to_string()))?;

    debug!(
        "Multi-tier dispatcher: reindexed {} PCs, rebuilt {} edges, and patched jump immediates",
        pc_mapping.len(),
        new_nodes.len()
    );

    Ok(Some(LayoutPlan {
        mapping,
        extraction_modified,
        dispatcher_modified,
        routing: blueprint.routing.clone(),
    }))
}

fn highest_pc(ir: &CfgIrBundle) -> usize {
    ir.cfg
        .node_indices()
        .filter_map(|idx| match &ir.cfg[idx] {
            Block::Body(body) => body
                .instructions
                .last()
                .map(|instr| instr.pc + instr.byte_size()),
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

fn minimal_push_width(value: usize) -> u8 {
    for width in 1..=32 {
        let max = if width == 32 {
            usize::MAX
        } else {
            (1usize << (width * 8)) - 1
        };
        if value <= max {
            return width as u8;
        }
    }
    32
}

fn minimal_push_width_u128(value: u128) -> u8 {
    if value == 0 {
        return 1;
    }
    for width in 1..=32 {
        let max = if width == 32 {
            u128::MAX
        } else {
            (1u128 << (width * 8)) - 1
        };
        if value <= max {
            return width as u8;
        }
    }
    32
}

fn format_immediate(value: u128, width: u8) -> String {
    format!("{:0width$x}", value, width = width as usize * 2)
}

fn create_tier_nodes(
    ir: &mut CfgIrBundle,
    mut next_pc: usize,
    target_node: NodeIndex,
) -> crate::Result<(TierNodes, usize)> {
    let target_pc = match &ir.cfg[target_node] {
        Block::Body(body) => body.start_pc,
        _ => {
            return Err(Error::Generic(
                "multi-tier: target node is not a body block".into(),
            ))
        }
    };

    let invalid_start = next_pc;
    let invalid_block = BlockBody {
        start_pc: invalid_start,
        instructions: vec![
            Instruction {
                pc: invalid_start,
                op: Opcode::JUMPDEST,
                imm: None,
            },
            Instruction {
                pc: invalid_start + 1,
                op: Opcode::INVALID,
                imm: None,
            },
        ],
        max_stack: 0,
        control: BlockControl::Terminal,
    };
    next_pc += 2;
    let invalid_node = ir.cfg.add_node(Block::Body(invalid_block));
    ir.pc_to_block.insert(invalid_start, invalid_node);
    ir.rebuild_edges_for_block(invalid_node)
        .map_err(|err| Error::CoreError(err.to_string()))?;

    let mut pc = next_pc;
    let decoy_start = pc;
    let invalid_width = minimal_push_width(invalid_start);
    let target_width = minimal_push_width(target_pc);
    let mut decoy_instructions = Vec::new();
    decoy_instructions.push(Instruction {
        pc,
        op: Opcode::JUMPDEST,
        imm: None,
    });
    pc += 1;

    decoy_instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(1),
        imm: Some("01".to_string()),
    });
    pc += 2;

    decoy_instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(1),
        imm: Some("00".to_string()),
    });
    pc += 2;

    decoy_instructions.push(Instruction {
        pc,
        op: Opcode::EQ,
        imm: None,
    });
    pc += 1;

    decoy_instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(invalid_width),
        imm: Some(format_immediate(invalid_start as u128, invalid_width)),
    });
    pc += 1 + invalid_width as usize;

    decoy_instructions.push(Instruction {
        pc,
        op: Opcode::JUMPI,
        imm: None,
    });
    pc += 1;

    decoy_instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(target_width),
        imm: Some(format_immediate(target_pc as u128, target_width)),
    });
    pc += 1 + target_width as usize;

    decoy_instructions.push(Instruction {
        pc,
        op: Opcode::JUMP,
        imm: None,
    });
    pc += 1;

    let decoy_block = BlockBody {
        start_pc: decoy_start,
        instructions: decoy_instructions,
        max_stack: 2,
        control: BlockControl::Unknown,
    };
    let decoy_node = ir.cfg.add_node(Block::Body(decoy_block));
    ir.pc_to_block.insert(decoy_start, decoy_node);
    ir.rebuild_edges_for_block(decoy_node)
        .map_err(|err| Error::CoreError(err.to_string()))?;

    next_pc = pc;

    let stub_start = next_pc;
    let stub_width = minimal_push_width(decoy_start);
    let stub_instructions = vec![
        Instruction {
            pc: stub_start,
            op: Opcode::JUMPDEST,
            imm: None,
        },
        Instruction {
            pc: stub_start + 1,
            op: Opcode::PUSH(stub_width),
            imm: Some(format_immediate(decoy_start as u128, stub_width)),
        },
        Instruction {
            pc: stub_start + 1 + 1 + stub_width as usize,
            op: Opcode::JUMP,
            imm: None,
        },
    ];
    let stub_block = BlockBody {
        start_pc: stub_start,
        instructions: stub_instructions,
        max_stack: 1,
        control: BlockControl::Unknown,
    };
    let stub_node = ir.cfg.add_node(Block::Body(stub_block));
    ir.pc_to_block.insert(stub_start, stub_node);
    ir.set_unconditional_jump(stub_node, decoy_node)
        .map_err(|err| Error::CoreError(err.to_string()))?;

    next_pc = stub_start + stub_width as usize + 3;

    Ok((
        TierNodes {
            stub_pc: stub_start,
            decoy_pc: decoy_start,
        },
        next_pc,
    ))
}

fn routes_for_tier(blueprint: &DispatcherBlueprint, tier_index: usize) -> Vec<TierRoute> {
    blueprint
        .routes
        .get(&tier_index)
        .cloned()
        .unwrap_or_default()
}

fn create_selector_controller(
    ir: &mut CfgIrBundle,
    mut next_pc: usize,
    routes: &[TierRoute],
    stub_pc: usize,
    decoy_pc: usize,
    fallback_pc: usize,
) -> crate::Result<(usize, usize)> {
    let start_pc = next_pc;
    let mut instructions = Vec::new();

    instructions.push(Instruction {
        pc: next_pc,
        op: Opcode::JUMPDEST,
        imm: None,
    });
    next_pc += 1;

    for route in routes {
        let target_pc = match route.destination {
            RouteDestination::Real => stub_pc,
            RouteDestination::Decoy => decoy_pc,
        };

        let slot_width = minimal_push_width_u128(route.slot as u128);
        instructions.push(Instruction {
            pc: next_pc,
            op: Opcode::PUSH(slot_width),
            imm: Some(format_immediate(route.slot as u128, slot_width)),
        });
        next_pc += 1 + slot_width as usize;

        instructions.push(Instruction {
            pc: next_pc,
            op: Opcode::SLOAD,
            imm: None,
        });
        next_pc += 1;

        let value_width = minimal_push_width_u128(route.value);
        instructions.push(Instruction {
            pc: next_pc,
            op: Opcode::PUSH(value_width),
            imm: Some(format_immediate(route.value, value_width)),
        });
        next_pc += 1 + value_width as usize;

        instructions.push(Instruction {
            pc: next_pc,
            op: Opcode::EQ,
            imm: None,
        });
        next_pc += 1;

        let target_width = minimal_push_width(target_pc);
        instructions.push(Instruction {
            pc: next_pc,
            op: Opcode::PUSH(target_width),
            imm: Some(format_immediate(target_pc as u128, target_width)),
        });
        next_pc += 1 + target_width as usize;

        instructions.push(Instruction {
            pc: next_pc,
            op: Opcode::JUMPI,
            imm: None,
        });
        next_pc += 1;
    }

    let fallback_width = minimal_push_width(fallback_pc);
    instructions.push(Instruction {
        pc: next_pc,
        op: Opcode::PUSH(fallback_width),
        imm: Some(format_immediate(fallback_pc as u128, fallback_width)),
    });
    next_pc += 1 + fallback_width as usize;

    instructions.push(Instruction {
        pc: next_pc,
        op: Opcode::JUMP,
        imm: None,
    });
    next_pc += 1;

    let block = BlockBody {
        start_pc,
        instructions: instructions.clone(),
        max_stack: 2,
        control: BlockControl::Unknown,
    };

    let node = ir.cfg.add_node(Block::Body(block));
    ir.pc_to_block.insert(start_pc, node);

    ir.rebuild_edges_for_block(node)
        .map_err(|err| Error::CoreError(err.to_string()))?;

    Ok((start_pc, next_pc))
}

fn locate_target_push(runtime: &[Instruction], selector: &FunctionSelector) -> Option<usize> {
    let target = selector.target_address as usize;
    for idx in (selector.instruction_index + 1)..runtime.len() {
        match runtime[idx].op {
            Opcode::JUMPI => break,
            Opcode::PUSH(_) | Opcode::PUSH0 => {
                if runtime[idx]
                    .imm
                    .as_ref()
                    .and_then(|imm| usize::from_str_radix(imm, 16).ok())
                    == Some(target)
                {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}
