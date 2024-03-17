#![no_std]

use core::mem::MaybeUninit;

use arrayvec::ArrayVec;
use thiserror_no_std::Error;
use zydis_sys::{
    ZyanStatus, ZydisDecodedInstruction, ZydisDecodedOperand, ZydisDecoder, ZydisDecoderContext,
    ZydisDecoderDecodeInstruction, ZydisDecoderDecodeOperands, ZydisDecoderInit, ZydisMachineMode,
    ZydisOperandType, ZydisRegister, ZydisStackWidth, ZYDIS_MAX_OPERAND_COUNT_VISIBLE,
};

const MAX_INSN_VISIBLE_OPERANDS: usize = ZYDIS_MAX_OPERAND_COUNT_VISIBLE as usize;
const ZYAN_IS_ERROR_BIT_MASK: u32 = 0x80000000;
const JMP_RIP_INSN_LEN: usize = 6;
const JMP_RIP_INSN: [u8; JMP_RIP_INSN_LEN] = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];

/// the length of a short relative jumper.
pub const SHORT_REL_JUMPER_LEN: usize = core::mem::size_of::<ShortRelJumper>();

/// the length of a short jumper.
pub const SHORT_JUMPER_LEN: usize = core::mem::size_of::<ShortJumper>();

/// the length of a long jumper.
pub const LONG_JUMPER_LEN: usize = core::mem::size_of::<LongJumper>();

/// the maximum length of a jumper of any kind.
pub const MAX_JUMPER_LEN: usize = LONG_JUMPER_LEN;

/// a type alias for the bytes of a jumper.
pub type JumperBytes = ArrayVec<u8, MAX_JUMPER_LEN>;

/// determines the best jumper kind to use in a specific case.
pub fn determine_best_jumper_kind(
    hooked_function_addr: usize,
    hook_function_addr: usize,
) -> JumperKind {
    let short_rel_hook_offset =
        (hooked_function_addr + SHORT_REL_JUMPER_LEN).wrapping_sub(hook_function_addr) as isize;
    if i32::try_from(short_rel_hook_offset).is_ok() {
        JumperKind::ShortRel
    } else if u32::try_from(hook_function_addr).is_ok() {
        JumperKind::Short
    } else {
        JumperKind::Long
    }
}

/// relocate the instructions at the start of the function so that we can put them in a different memory address and they
/// will still work fine.
pub fn relocate_fn_start(
    hooked_function_content: &[u8],
    relocate_bytes_amount: usize,
) -> Result<RelocateFnStartInfo, RelocateError> {
    let mut cur_index = 0;
    let decoder = Decoder::new();
    while cur_index < relocate_bytes_amount {
        let insn = decoder
            .decode(&hooked_function_content[cur_index..])
            .map_err(|_| RelocateError::FailedToDecodeInsn { offset: cur_index })?;
        if is_insn_rip_relative(&insn) {
            return Err(RelocateError::RipRelativeInsn { offset: cur_index });
        }
        cur_index += insn.insn.length as usize;
    }
    Ok(RelocateFnStartInfo {
        bytes_to_copy: cur_index,
    })
}

/// information needed to relocate the bytes at the start of a function.
pub struct RelocateFnStartInfo {
    /// the amount of bytes that you need to copy to properly relocate the instructions at the start of this function.
    /// this may be larger than the amount of bytes requested to be relocated since that amount may not end on an instruction boundary.
    pub bytes_to_copy: usize,
}

struct Decoder {
    decoder: ZydisDecoder,
}
impl Decoder {
    fn new() -> Self {
        let mut decoder: MaybeUninit<ZydisDecoder> = MaybeUninit::uninit();
        let status = unsafe {
            ZydisDecoderInit(
                decoder.as_mut_ptr(),
                ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64,
                ZydisStackWidth::ZYDIS_STACK_WIDTH_64,
            )
        };
        zyan_check(status).expect("failed to initialize a 64-bit mode zydis decoder");
        Self {
            decoder: unsafe { decoder.assume_init() },
        }
    }

    fn decode(&self, buf: &[u8]) -> Result<DecodedInsnInfo, ()> {
        let mut decoder_ctx_uninit: MaybeUninit<ZydisDecoderContext> = MaybeUninit::uninit();
        let mut insn_uninit: MaybeUninit<ZydisDecodedInstruction> = MaybeUninit::uninit();

        let status = unsafe {
            ZydisDecoderDecodeInstruction(
                &self.decoder,
                decoder_ctx_uninit.as_mut_ptr(),
                buf.as_ptr().cast(),
                buf.len() as u64,
                insn_uninit.as_mut_ptr(),
            )
        };
        zyan_check(status)?;

        let decoder_ctx = unsafe { decoder_ctx_uninit.assume_init() };
        let insn = unsafe { insn_uninit.assume_init() };

        assert!(insn.operand_count_visible <= MAX_INSN_VISIBLE_OPERANDS as u8);

        let mut operands: ArrayVec<ZydisDecodedOperand, MAX_INSN_VISIBLE_OPERANDS> =
            ArrayVec::new();
        let status = unsafe {
            ZydisDecoderDecodeOperands(
                &self.decoder,
                &decoder_ctx,
                &insn,
                operands.as_mut_ptr(),
                insn.operand_count_visible,
            )
        };
        zyan_check(status)?;

        unsafe { operands.set_len(insn.operand_count_visible as usize) }

        Ok(DecodedInsnInfo { insn, operands })
    }
}

fn is_insn_rip_relative(decoded_insn: &DecodedInsnInfo) -> bool {
    for operand in &decoded_insn.operands {
        match operand.type_ {
            ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE => {
                if unsafe { operand.__bindgen_anon_1.imm }.is_relative != 0 {
                    return true;
                }
            }
            ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY => {
                if unsafe { operand.__bindgen_anon_1.mem }.base == ZydisRegister::ZYDIS_REGISTER_RIP
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

struct DecodedInsnInfo {
    insn: ZydisDecodedInstruction,
    operands: ArrayVec<ZydisDecodedOperand, MAX_INSN_VISIBLE_OPERANDS>,
}

/// an error which occured while trying to relocate instructions.
#[derive(Debug, Error)]
pub enum RelocateError {
    #[error("failed to decode instruction at offset {offset}")]
    FailedToDecodeInsn { offset: usize },

    #[error("can't relocate rip relative instruction at offset {offset}")]
    RipRelativeInsn { offset: usize },
}

/// the different kinds of jumper available
pub enum JumperKind {
    /// a short relative jumper, which is a 32 bit relative jump.
    ShortRel,
    /// a short jumper, which is a push 32 bit address followed by a ret instruction.
    Short,
    /// a long jumper, which is a jmp to rip followed by the raw 64 bit address.
    Long,
}
impl JumperKind {
    /// returns the size of the jumper in bytes
    pub fn size_in_bytes(&self) -> usize {
        match self {
            JumperKind::ShortRel => SHORT_REL_JUMPER_LEN,
            JumperKind::Short => SHORT_JUMPER_LEN,
            JumperKind::Long => LONG_JUMPER_LEN,
        }
    }
    /// builds the jumper into an array of bytes.
    pub fn build_jumper(&self, hooked_function_addr: u64, hook_function_addr: u64) -> JumperBytes {
        match self {
            JumperKind::ShortRel => {
                let jmp_insn_end_addr = hooked_function_addr + SHORT_REL_JUMPER_LEN as u64;
                let displacement = hook_function_addr.wrapping_sub(jmp_insn_end_addr) as i64;
                let displacement_i32 = i32::try_from(displacement)
                    .expect("tried to use a short relative jumper for but the distance from the hooked function to the hook does not fit in 32 bits");
                let jumper_union = ShortRelJumperUnion {
                    jumper: ShortRelJumper {
                        jump_opcode: 0xe9,
                        displacement: displacement_i32.to_le(),
                    },
                };
                unsafe { jumper_union.bytes }.as_slice().try_into().unwrap()
            }
            JumperKind::Short => {
                let hook_function_addr_u32 = u32::try_from(hook_function_addr)
                    .expect("tried to use a short jumper but the hook function address does not fit in 32 bits");
                let jumper_union = ShortJumperUnion {
                    jumper: ShortJumper {
                        push: Push32BitImm {
                            push_opcode: 0x68,
                            pushed_value: hook_function_addr_u32.to_le(),
                        },
                        ret: 0xc3,
                    },
                };
                unsafe { jumper_union.bytes }.as_slice().try_into().unwrap()
            }
            JumperKind::Long => {
                let jumper_union = LongJumperUnion {
                    jumper: LongJumper {
                        jmp_rip: JMP_RIP_INSN,
                        target_addr: hook_function_addr,
                    },
                };
                unsafe { jumper_union.bytes }.as_slice().try_into().unwrap()
            }
        }
    }
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Clone, Copy)]
struct ShortRelJumper {
    jump_opcode: u8,
    displacement: i32,
}

#[repr(packed)]
union ShortRelJumperUnion {
    jumper: ShortRelJumper,
    bytes: [u8; SHORT_REL_JUMPER_LEN],
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Clone, Copy)]
struct ShortJumper {
    push: Push32BitImm,
    ret: u8,
}

#[repr(packed)]
union ShortJumperUnion {
    jumper: ShortJumper,
    bytes: [u8; SHORT_JUMPER_LEN],
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Clone, Copy)]
struct Push32BitImm {
    push_opcode: u8,
    pushed_value: u32,
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Clone, Copy)]
struct LongJumper {
    jmp_rip: [u8; JMP_RIP_INSN_LEN],
    target_addr: u64,
}

#[repr(packed)]
union LongJumperUnion {
    jumper: LongJumper,
    bytes: [u8; SHORT_JUMPER_LEN],
}

fn zyan_is_err(status: ZyanStatus) -> bool {
    status & ZYAN_IS_ERROR_BIT_MASK != 0
}
fn zyan_check(status: ZyanStatus) -> Result<(), ()> {
    if zyan_is_err(status) {
        Err(())
    } else {
        Ok(())
    }
}
