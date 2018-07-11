// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use callgraph::byteorder::{LittleEndian, ReadBytesExt};
use callgraph::capstone::arch::x86::*;
use callgraph::capstone::arch::DetailsArchInsn;
use callgraph::capstone::Capstone;
use callgraph::capstone::Insn;
use callgraph::capstone::InsnId;
use callgraph::capstone::RegId;
use callgraph::object::Object;
use callgraph::object::ObjectSection;

use callgraph::Context;

use std::io::Cursor;
use std::str::from_utf8;

use AnalysisOptions;
use BackTraceEntry;
use RustigCallGraph;

static REG_ID_RDI: RegId = RegId(39);
static REG_ID_ESI: RegId = RegId(29);

static INS_ID_LEA: InsnId = InsnId(315);
static INS_ID_MOV: InsnId = InsnId(442);

/// Trait that can be implemented by types that can try to retrieve panic messages.
pub trait PanicMessageFinder {
    fn find_panic_message(
        &self,
        backtrace: &[BackTraceEntry],
        call_graph: &RustigCallGraph,
        context: &Context,
    ) -> Option<String>;
}

/// Implementation of `PanicMessageFinder` that can find message for calls to `core::panicking::panic`.
///
/// Works on assembly code looking like:
/// ```text
///    295bb0 6e735472 69656420 746f2073 6872696e  nsTried to shrin
///    295bc0 6b20746f 2061206c 61726765 72206361  k to a larger ca
///    295bd0 70616369 74796c69 62616c6c 6f632f72  pacityliballoc/r
///
///    5d8940 60730d00 00000000 b25b2900 00000000
///    5d8950 24000000 00000000 d65b2900 00000000
///
///    64e06:   48 8d 3d 3b 3b 57 00    lea    0x573b3b(%rip),%rdi  # 5d8948
///    64e0d:   e8 ae 48 22 00          callq  2896c0 <core::panicking::panic>
/// ```
/// Where %rdi points to `5d8948`
/// `5d8948` points to the string literal 'Tried to shrink to a larger capacity' at `295bb2` (`b25b2900` corrected for endianness)
/// `5d8950` points to the size of this string literal (36 in this case (`24000000` corrected for endianness))
struct CorePanickingPanicMessageFinder;

impl PanicMessageFinder for CorePanickingPanicMessageFinder {
    fn find_panic_message(
        &self,
        backtrace: &[BackTraceEntry],
        _call_graph: &RustigCallGraph,
        context: &Context,
    ) -> Option<String> {
        // get_call_instruction guarantees array length of `count`, so indexing is safe
        let instruction = &get_call_instruction(backtrace, 1, "core::panicking::panic")?[0];
        let registers = get_instruction_operand_registers(&context.capstone, &instruction);
        let operands = get_instruction_operand_values(&context.capstone, &instruction);

        // registers[0] is the destination register, which should be equal to RDI
        if registers[0] == Some(REG_ID_RDI) && instruction.id() == INS_ID_LEA {
            // operands[1] is the source operand (i.e. the loaded address)
            if let Some(target_address) = operands[1] {
                let str_bytes = get_bytes_at_address(context, target_address, 16)?;
                assert_eq!(str_bytes.len(), 16, "Return value of get_bytes_at_address for string literal pointer bytes must have length 16.");
                let mut str_cursor = Cursor::new(str_bytes);

                let str_ptr = str_cursor.read_u64::<LittleEndian>().ok()?;
                let str_size = str_cursor.read_u64::<LittleEndian>().ok()?;

                return get_panic_message(context, str_ptr, str_size);
            }
        }

        None
    }
}

/// Implementation of `PanicMessageFinder` that can find message for calls to `std::panicking::begin_panic`.
///
/// ## Target assembly
///
/// This finder works on assembly structures like:
///
/// ### Debug
/// Works on assembly code looking like:
/// ```text
///    6640a0 2f737263 2f64652e 72736173 73657274  /src/de.rsassert
///    6640b0 696f6e20 6661696c 65643a20 73656c66  ion failed: self
///    6640c0 2e6e6578 745f7661 6c75652e 69735f6e  .next_value.is_n
///    6640d0 6f6e6528 29000000 00000000 00000000  one()...........
///
///    860e8:       48 8d 3d bb df 5d 00    lea    0x5ddfbb(%rip),%rdi    # 6640aa
///    860ef:       48 8d 15 da 82 9e 00    lea    0x9e82da(%rip),%rdx    # a6e3d0
///    860fd:       e8 ce 86 30 00          callq  38e7d0 <std::panicking::begin_panic>
/// ```
///
/// Here the following properties hold:
/// * Where the string size is loaded in %eax and %esi.
/// * The string literal pointer is loaded in %rdi, (pointing to `6640aa`, which is the string literal "assertion failed: self.next_value.is_none")
/// * The file name `&str` pointer is loaded in %rdx (but unused by Rustig)
///
/// ### Release
///
/// In release builds, the following optimization usually takes place:
/// ```text
///    860f6:       b8 2b 00 00 00          mov    $0x2b,%eax
///    860fb:       89 c6                   mov    %eax,%esi
/// ```
/// Optimizes to:
/// ```text
///    860f6:       be 2b 00 00 00          mov    $0x2b,%esi
/// ```
/// The `StdPanickingBeginPanicMessageFinder` implementation should find both cases.
struct StdPanickingBeginPanicMessageFinder {
    /// Register id of the register in which the string literal pointer is passed.
    /// Should be `%rdi` in the example above
    string_pointer_reg_id: RegId,
    /// Register id of the register in which the string size is passed.
    /// Should be `%esi` in the example above
    string_size_reg_id: RegId,
    /// Name of the function to which the parameters are passed.
    /// Should be `"std::panicking::begin_panic"` in the example above.
    function_name: &'static str,
}

// Note IN this implementation, we assume %esi and %rdi as parameter registers
// If this assumption turns out to be invalid in the future, DWARF information could be used to find the
// actual parameter location
impl PanicMessageFinder for StdPanickingBeginPanicMessageFinder {
    fn find_panic_message(
        &self,
        backtrace: &[BackTraceEntry],
        _call_graph: &RustigCallGraph,
        context: &Context,
    ) -> Option<String> {
        let instructions = get_call_instruction(backtrace, 4, self.function_name)?;
        let mut instruction_iter = instructions.iter();

        let last_instruction = &instruction_iter.next_back()?;

        // We assumed the last instruction would be a 'mov $..,%esi' or 'mov %eax,%esi'
        // So return if it is not a move
        if last_instruction.id() != INS_ID_MOV {
            return None;
        }

        let instruction_registers =
            get_instruction_operand_registers(&context.capstone, &last_instruction);
        let instruction_operands =
            get_instruction_operand_values(&context.capstone, &last_instruction);

        let str_size = match &instruction_registers[..] {
            // mov $..,%esi case
            // Check if first operand is %esi
            [Some(target_reg_id), None] if target_reg_id == &self.string_size_reg_id => {
                match &instruction_operands[..] {
                    // Check if second operand is a constant
                    [None, Some(size)] => *size,
                    _ => return None,
                }
            }
            // 'mov %eax,%esi' case
            [Some(target_reg_id), Some(source_reg_id)]
                // Check if first operand is %esi
                if target_reg_id == &self.string_size_reg_id =>
            {
                // Retrieve the previous instruction
                let last_instruction = &instruction_iter.next_back()?;
                let instruction_registers =
                    get_instruction_operand_registers(&context.capstone, &last_instruction);
                let instruction_operands =
                    get_instruction_operand_values(&context.capstone, &last_instruction);

                // Check if this instruction matches `mov $.., %<source_reg_id>'
                match &instruction_registers[..] {
                    [Some(next_target_reg_id), None] if next_target_reg_id == source_reg_id => {
                        match &instruction_operands[..] {
                            [None, Some(size)] => *size,
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
            }
            _ => return None,
        };

        let str_ptr = instruction_iter
            .rfind(|insn| {
                let registers = get_instruction_operand_registers(&context.capstone, insn);
                registers.len() == 2 && registers[0] == Some(self.string_pointer_reg_id)
            })
            .and_then(|insn| {
                let operands = get_instruction_operand_values(&context.capstone, insn);
                if operands.len() == 2 {
                    operands[1]
                } else {
                    None
                }
            })?;

        get_panic_message(context, str_ptr, str_size)
    }
}

fn get_panic_message(context: &Context, str_ptr: u64, str_size: u64) -> Option<String> {
    let str_bytes = get_bytes_at_address(context, str_ptr, str_size)?;
    from_utf8(str_bytes).ok().map(|x| x.to_string())
}

fn get_instruction_operand_registers(
    capstone: &Capstone,
    instruction: &Insn,
) -> Vec<Option<RegId>> {
    let insn_details = match capstone.insn_detail(&instruction) {
        Ok(det) => det,
        _ => return vec![],
    };

    let arch_detail = insn_details.arch_detail();
    let x86_arch_details = match arch_detail.x86() {
        Some(arch_det) => arch_det,
        None => return vec![],
    };

    x86_arch_details
        .operands()
        .map(|operand| match operand.op_type {
            X86OperandType::Reg(id) => Some(id),
            _ => None,
        })
        .collect()
}

fn get_instruction_operand_values(capstone: &Capstone, instruction: &Insn) -> Vec<Option<u64>> {
    let instruction_address = instruction.address();
    let instruction_size = instruction.bytes().len();
    let rip_value = instruction_address + instruction_size as u64;

    let insn_details = match capstone.insn_detail(&instruction) {
        Ok(det) => det,
        _ => return vec![],
    };

    let arch_detail = insn_details.arch_detail();
    let x86_arch_details = match arch_detail.x86() {
        Some(arch_det) => arch_det,
        None => return vec![],
    };

    x86_arch_details
        .operands()
        .map(|operand| match operand.op_type {
            X86OperandType::Imm(value) => Some(value as u64),
            X86OperandType::Mem(mem_operand) if mem_operand.base() == RegId(0) => {
                get_mem_op_value(&mem_operand, 0)
            }
            X86OperandType::Mem(mem_operand) if mem_operand.base() == RegId(41) => {
                get_mem_op_value(&mem_operand, rip_value)
            }
            _ => None,
        })
        .collect()
}

fn get_call_instruction(
    backtrace: &[BackTraceEntry],
    count: usize,
    fn_name: &str,
) -> Option<Vec<Insn>> {
    let panic_position = backtrace
        .iter()
        .position(|x| x.procedure.borrow().linkage_name_demangled == fn_name)?;

    // `core::panicking::panic` can never be the first entry in the stack trace.
    assert_ne!(panic_position, 0);
    let caller = backtrace[panic_position - 1].procedure.borrow();
    let panic_invocation = backtrace[panic_position - 1]
        .outgoing_invocation
        .as_ref()
        .expect("Only last invocation in backtrace can be None");
    let panic_call_address = panic_invocation.borrow().instruction_address;

    // fetch last pair of instructions before the actual call, in order to find the loaded address
    let instructions_vec = caller.disassembly.iter().collect::<Vec<_>>();
    let mut target_instructions = instructions_vec.into_iter() // Implements DoubleEndedIterator
        .rev()
        .skip_while(|x| x.address() != panic_call_address)
        .skip(1) // Get the instruction BEFORE call (since we reversed the order)
        .take(count)
        .collect::<Vec<_>>();

    // Undo reverse
    target_instructions.reverse();
    Some(target_instructions)
}

fn get_mem_op_value(mem_operand: &X86OpMem, base_reg_value: u64) -> Option<u64> {
    if mem_operand.index() == RegId(0) {
        Some(base_reg_value + mem_operand.disp() as u64)
    } else {
        None
    }
}

fn get_bytes_at_address<'a>(context: &Context<'a>, address: u64, size: u64) -> Option<&'a [u8]> {
    let section = context.elf.sections().find(|sec| {
        let sec_address = sec.address();
        let sec_size = sec.size();
        sec_address <= address && sec_address + sec_size > address + size
    })?;

    let sec_address = section.address();
    let sec_bytes = section.data();

    let section_offset = (address - sec_address) as usize;
    let section_size = section_offset + size as usize;

    Some(&sec_bytes[section_offset..section_size])
}

/// Get vector of objects that can try to retrieve panic messages
pub fn get_panic_message_finders(_options: &AnalysisOptions) -> Vec<Box<PanicMessageFinder>> {
    vec![
        Box::new(CorePanickingPanicMessageFinder),
        Box::new(StdPanickingBeginPanicMessageFinder {
            string_pointer_reg_id: REG_ID_RDI,
            string_size_reg_id: REG_ID_ESI,
            function_name: "std::panicking::begin_panic",
        }),
        // Implementation to find messages for Result<T, E>::expect
        // Works on release builds only
        Box::new(StdPanickingBeginPanicMessageFinder {
            string_pointer_reg_id: REG_ID_RDI,
            string_size_reg_id: REG_ID_ESI,
            function_name: "core::option::expect_failed",
        }),
        // Implementation to find messages for Option<T>::expect
        // Works on release builds only
        Box::new(StdPanickingBeginPanicMessageFinder {
            string_pointer_reg_id: REG_ID_RDI,
            string_size_reg_id: REG_ID_ESI,
            function_name: "core::result::unwrap_failed",
        }),
    ]
}
