// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate addr2line;
extern crate fallible_iterator;
extern crate gimli;
extern crate object;
extern crate petgraph;

use Context;
use InlineFunctionFrame;
use Invocation;
use InvocationType;
use Procedure;

use callgraph::fallible_iterator::FallibleIterator;
use callgraph::InvocationFinder;

use std::cell::RefCell;
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::rc::Rc;

use capstone::*;

use callgraph::CompilationInfo;
use petgraph::stable_graph::{NodeIndex, StableGraph};
use petgraph::Directed;

/// Enum indicating how a call was encoded in assembly.
#[derive(Debug)]
enum CallType {
    StaticCall { insn: Insn, target: i64 },
    StaticJump { insn: Insn, target: i64 },
}

impl CallType {
    fn invocation_type(&self) -> InvocationType {
        match self {
            CallType::StaticJump { .. } => InvocationType::Jump,
            CallType::StaticCall { .. } => InvocationType::Direct,
        }
    }
}

pub struct StaticCallInvocationFinder;

impl<P, I: Default, F: Default> InvocationFinder<P, I, F> for StaticCallInvocationFinder {
    fn find_invocations(
        &self,
        graph: &mut StableGraph<
            Rc<RefCell<Procedure<P>>>,
            Rc<RefCell<Invocation<I, F>>>,
            Directed,
            u32,
        >,
        proc_index: &mut HashMap<u64, NodeIndex<u32>, RandomState>,
        call_index: &mut HashMap<u64, NodeIndex<u32>, RandomState>,
        ctx: &Context,
        compilation_info: CompilationInfo,
    ) {
        let node_indices: Vec<_> = graph.node_indices().collect();
        node_indices.iter()
            .map(|idx| parse_calls(&graph[*idx].borrow().disassembly, &ctx.capstone))
            .fold(vec!(), |mut vec, mut elem| {
                vec.append(&mut elem);
                vec
            })
            .iter()
            // Map `CallType` to (origin, destination, invocation type, locations) quadruple.
            .filter_map(|call_type| {
                let invocation_type = call_type.invocation_type();
                match call_type {
                    CallType::StaticCall { insn, target } | CallType::StaticJump { insn, target } => {
                        let origin = &call_index[&insn.address()];
                        let destination = proc_index.get(&(*target as u64))?;

                        let frames = ctx.file_context.find_frames(insn.address())
                            .unwrap_or_else(|_| panic!("Creating iterator over static function frames of the given virtual memory address: {} failed", insn.address()))
                            .iterator()
                            .filter_map(|frame_res| frame_res.ok())
                            .map(|frame| InlineFunctionFrame::convert_frame(&frame, compilation_info.compilation_dirs, compilation_info.rust_version.to_owned()))
                            .collect();

                        Some((origin, destination, invocation_type, frames, insn.address()))
                    }
                }
            })
            // Add edges for all invocations
            .for_each(|(origin, destination, invocation_type, frames, instruction_address)| {
                // use addrs2line with call_instr_addr
                graph.add_edge(
                    *origin,
                    *destination,
                    Rc::new(RefCell::new(Invocation {
                        invocation_type,
                        instruction_address,
                        frames,
                        attributes: I::default()
                    })));
            });
    }
}
/// Transform collection of instructions to their corresponding call types.
fn parse_calls(instructions: &Instructions, cs: &Capstone) -> Vec<CallType> {
    instructions
        .iter()
        .flat_map(|insn| get_call_type(insn, cs))
        .collect()
}

/// Extract the call type for a specific instruction.
fn get_call_type(insn: Insn, cs: &Capstone) -> Option<CallType> {
    let jump_group_id = InsnGroupId(1); // Group 1 is jump
    let call_group_id = InsnGroupId(2); // Group 2 is call

    let is_call = cs.insn_group_ids(&insn)
        .unwrap()
        .any(|id| id == call_group_id);
    let is_jump = cs.insn_group_ids(&insn)
        .unwrap()
        .any(|id| id == jump_group_id);

    // Return no call type if instruction is neither a jump nor a call
    if !is_call && !is_jump {
        return None;
    }

    let operands = {
        let details = cs.insn_detail(&insn).unwrap();
        let operands = details.arch_detail().operands();

        if operands.len() != 1 {
            panic!(
                "Call instruction should have one operand, but {} were found. Instruction: {:?}. Details: {:?}",
                operands.len(),
                insn,
                details
            );
        }
        operands
    };

    let operand = match operands[0] {
        arch::ArchOperand::X86Operand(ref operand) => operand,
        _ => panic!("Only x86 instructions are supported"),
    };

    match operand.op_type {
        arch::x86::X86OperandType::Imm(target) if is_call => {
            Some(CallType::StaticCall { insn, target })
        }
        arch::x86::X86OperandType::Imm(target) => Some(CallType::StaticJump { insn, target }),
        arch::x86::X86OperandType::Reg(RegId(_)) | arch::x86::X86OperandType::Mem(_) => None,
        arch::x86::X86OperandType::Fp(_) => {
            panic!("Invalid call operand: call to a float is not a valid call")
        }
        arch::x86::X86OperandType::Invalid => panic!("Invalid call operand"),
    }
}

#[cfg(test)]
mod test {
    extern crate capstone;
    extern crate elf;
    extern crate gimli;
    extern crate object;
    extern crate test_common;

    use super::*;

    use capstone::arch::BuildsCapstone;
    use capstone::prelude::*;
    use capstone::Capstone;

    /// Verify non-calls do not create CallTypes
    #[test]
    pub fn test_invalid_calls() {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Att)
            .detail(true)
            .build()
            .unwrap();

        let assembly = &[25, 50, 75, 100];

        let disassembly = {
            cs.disasm_all(assembly, 0)
                .expect("Failed to disassemble test data")
        };

        let call_types = parse_calls(&disassembly, &cs);

        assert_eq!(call_types.len(), 0);
    }
}
