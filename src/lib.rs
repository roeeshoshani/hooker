#![cfg_attr(not(feature = "std"), no_std)]

use core::{mem::MaybeUninit, ops::Range};

use arrayvec::ArrayVec;
use thiserror_no_std::Error;
use zydis_sys::{
    ZyanStatus, ZydisDecodedInstruction, ZydisDecodedOperand, ZydisDecoder, ZydisDecoderDecodeFull,
    ZydisDecoderInit, ZydisEncoderDecodedInstructionToEncoderRequest,
    ZydisEncoderEncodeInstruction, ZydisEncoderRequest, ZydisMachineMode, ZydisMnemonic,
    ZydisOperandType, ZydisRegister, ZydisRegisterGetLargestEnclosing, ZydisStackWidth,
    ZYDIS_MAX_INSTRUCTION_LENGTH, ZYDIS_MAX_OPERAND_COUNT,
};

const MAX_INSN_OPERANDS: usize = ZYDIS_MAX_OPERAND_COUNT as usize;
const ZYAN_IS_ERROR_BIT_MASK: u32 = 0x80000000;
const POSSIBLE_TMP_REGS: &[ZydisRegister] = &[
    ZydisRegister::ZYDIS_REGISTER_RAX,
    ZydisRegister::ZYDIS_REGISTER_RBX,
    ZydisRegister::ZYDIS_REGISTER_RCX,
    ZydisRegister::ZYDIS_REGISTER_RDX,
    ZydisRegister::ZYDIS_REGISTER_RSI,
    ZydisRegister::ZYDIS_REGISTER_RDI,
    ZydisRegister::ZYDIS_REGISTER_RBP,
];

const PUSH_RIP_INSN_LEN: usize = 5;
const PUSH_RIP_INSN: [u8; PUSH_RIP_INSN_LEN] = [0xE8, 0x00, 0x00, 0x00, 0x00];

const RET_INSN: u8 = 0xc3;

macro_rules! const_max {
    ($a: expr, $b: expr) => {
        if $a > $b {
            $a
        } else {
            $b
        }
    };
    ($a: expr, $b: expr, $($other: expr),+) => {
        if $a > $b {
            const_max!($a, $($other),+)
        } else {
            const_max!($b, $($other),+)
        }
    }
}
macro_rules! max_size {
    ($($ty: ty),+) => {
        const_max!(
            $(
                core::mem::size_of::<$ty>()
            ),+
        )
    };
}

const MAX_INSN_LEN: usize = ZYDIS_MAX_INSTRUCTION_LENGTH as usize;

/// the amount of bytes added to a relocated [rip+X] addressing instruction.
const RELOCATED_MEM_RIP_INSN_ADDED_LEN: usize =
    core::mem::size_of::<RelocatedMemRipPrefix>() + core::mem::size_of::<RelocatedMemRipPostfix>();

/// the maximum length of a relocated [rip+X] addressing instruction.
const MAX_RELOCATED_MEM_RIP_INSN_LEN: usize = MAX_INSN_LEN + RELOCATED_MEM_RIP_INSN_ADDED_LEN;

/// the maximum length of a relocated instruction
pub const MAX_RELOCATED_INSN_LEN: usize = const_max!(
    max_size!(RelocatedJmpImm, RelocatedCallImm, RelocatedCondJmpImm),
    MAX_RELOCATED_MEM_RIP_INSN_LEN
);

/// the maximum length of an instruction that is either relocated or the original instruction
pub const MAX_MAYBE_RELOCATED_INSN_LEN: usize = const_max!(MAX_RELOCATED_INSN_LEN, MAX_INSN_LEN);

/// the length of a short relative jumper.
pub const SHORT_REL_JUMPER_LEN: usize = core::mem::size_of::<ShortRelJumper>();

/// the length of a short jumper.
pub const SHORT_JUMPER_LEN: usize = core::mem::size_of::<ShortJumper>();

/// the length of a long jumper.
pub const LONG_JUMPER_LEN: usize = core::mem::size_of::<LongJumper>();

/// the maximum length of a jumper of any kind.
pub const MAX_JUMPER_LEN: usize = core::mem::size_of::<JumperUnion>();

/// the maximum length of a trampoiline.
pub const MAX_TRAMPOLINE_LEN: usize = {
    // reserve space for all relocated instructions plus a jumper at the end
    MAX_RELOCATED_INSNS_LEN + MAX_JUMPER_LEN
};

/// the maximum amount of instructions that we may need to relocate when hooking a fn.
pub const MAX_RELOCATED_INSNS_AMOUNT: usize = {
    // at the worst case, every instruction is one byte, so we will have to relocate each of them.
    MAX_JUMPER_LEN
};

/// the maximum total length of all of the relocated instruction when relocating the instructions at the start of a fn.
pub const MAX_RELOCATED_INSNS_LEN: usize = {
    // this is basically the maximum amount of instructions that we may relocate multiplied by the maximum size of the *maybe* relocated
    // instruction, since not all instructions will actually require relocations, some will be copied as is.
    MAX_RELOCATED_INSNS_AMOUNT * MAX_MAYBE_RELOCATED_INSN_LEN
};

/// a type alias for the bytes of a jumper.
pub type JumperBytes = ArrayVec<u8, MAX_JUMPER_LEN>;

/// a type alias for the bytes of a relocated instruction.
pub type RelocatedInsnBytes = ArrayVec<u8, MAX_RELOCATED_INSN_LEN>;

/// a type alias for the bytes of some relocated instructions.
pub type RelocatedInsnsBytes = ArrayVec<u8, MAX_RELOCATED_INSNS_LEN>;

/// a type alias for the bytes of a trampoline.
pub type TrampolineBytes = ArrayVec<u8, MAX_TRAMPOLINE_LEN>;

/// a type alias for the bytes of an instruction.
type InsnBytes = ArrayVec<u8, MAX_INSN_LEN>;

/// generates information needed to hook the given fn.
pub fn gen_hook_info(
    hooked_fn_content: &[u8],
    hooked_fn_runtime_addr: u64,
    hook_fn_runtime_addr: u64,
) -> Result<HookInfo, HookError> {
    let jumper = determine_best_jumper_kind_and_build(hooked_fn_runtime_addr, hook_fn_runtime_addr);
    let relocated_fn = relocate_fn_start(hooked_fn_content, hooked_fn_runtime_addr, jumper.len())?;
    Ok(HookInfo {
        jumper,
        relocated_fn,
    })
}

/// information required for hooking a fn
pub struct HookInfo {
    jumper: JumperBytes,
    relocated_fn: RelocatedFnStart,
}
impl HookInfo {
    /// returns the jumper which should be placed at the start of the hooked fn in order to hook it.
    /// this takes ownership of the hook info. make sure that you first build your trampoline.
    pub fn jumper(&self) -> &JumperBytes {
        &self.jumper
    }
    /// returns the size of the trampoline which will be built for this hooked fn.
    pub fn trampoline_size(&self) -> usize {
        self.relocated_fn.trampoline_size()
    }
    /// builds a trampoline which will be placed at the given runtime address.
    /// the size of the trampoline can be determined by calling [`trampoline_size`].
    ///
    /// [`trampoline_size`]: HookInfo::trampoline_size
    pub fn build_trampoline(&self, trampoline_runtime_addr: u64) -> TrampolineBytes {
        self.relocated_fn.build_trampoline(trampoline_runtime_addr)
    }
}

/// determines the best jumper kind to use in a specific case.
pub fn determine_best_jumper_kind(jumper_addr: u64, target_addr: u64) -> JumperKind {
    let short_rel_hook_offset =
        (jumper_addr + SHORT_REL_JUMPER_LEN as u64).wrapping_sub(target_addr) as i64;
    if i32::try_from(short_rel_hook_offset).is_ok() {
        JumperKind::ShortRel
    } else if u32::try_from(target_addr).is_ok() {
        JumperKind::Short
    } else {
        JumperKind::Long
    }
}

/// determines the best jumper kind to use in a specific case and builds it.
pub fn determine_best_jumper_kind_and_build(
    hooked_fn_runtime_addr: u64,
    hook_fn_runtime_addr: u64,
) -> JumperBytes {
    determine_best_jumper_kind(hooked_fn_runtime_addr, hook_fn_runtime_addr)
        .build(hooked_fn_runtime_addr, hook_fn_runtime_addr)
}

/// relocate the instructions at the start of the fn so that we can put them in a different memory address and they
/// will still work fine.
///
/// # Safety
///
/// the provided `relocate_bytes_amount` must be lower than or equal to the max jumper size, otherwise the function will panic.
pub fn relocate_fn_start(
    hooked_fn_content: &[u8],
    hooked_fn_runtime_addr: u64,
    relocate_bytes_amount: usize,
) -> Result<RelocatedFnStart, HookError> {
    let mut cur_index = 0;
    let decoder = Decoder::new();
    let mut relocated_insns_bytes = RelocatedInsnsBytes::new();
    let relocated_insns_addr_range =
        hooked_fn_runtime_addr..hooked_fn_runtime_addr + relocate_bytes_amount as u64;
    while cur_index < relocate_bytes_amount {
        let insn = decoder
            .decode(
                &hooked_fn_content[cur_index..],
                hooked_fn_runtime_addr + cur_index as u64,
            )
            .map_err(|_| HookError::FailedToDecodeInsn { offset: cur_index })?;
        match relocate_insn(&insn, cur_index, &relocated_insns_addr_range)? {
            Some(relocated_insn) => relocated_insns_bytes
                .try_extend_from_slice(relocated_insn.as_slice())
                .unwrap(),
            None => {
                // copy the instruction as is
                relocated_insns_bytes
                    .try_extend_from_slice(
                        &hooked_fn_content[cur_index..cur_index + insn.insn.length as usize],
                    )
                    .unwrap()
            }
        }
        let insn_end_index = cur_index + insn.insn.length as usize;
        // if we encounter a `ret`, this is the end of this fn, so make sure that this is the last instruction that
        // we need to relocate.
        if insn.insn.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_RET
            && insn_end_index < relocate_bytes_amount
        {
            return Err(HookError::FnTooSmallTooHook {
                fn_size: insn_end_index,
                jumper_size: relocate_bytes_amount,
            });
        }
        cur_index += insn.insn.length as usize;
    }
    let trampoline_jumper_target_offset = cur_index;
    while cur_index < hooked_fn_content.len() {
        let Ok(decoded_insn) = decoder.decode(
            &hooked_fn_content[cur_index..],
            hooked_fn_runtime_addr + cur_index as u64,
        ) else {
            break;
        };
        if mnemonic_is_branch(decoded_insn.insn.mnemonic).is_some() {
            check_jmp_insn_doesnt_jump_into_relocated_insns(
                &decoded_insn,
                cur_index,
                &relocated_insns_addr_range,
            )?;
        }
        // if we encounter a `ret`, this is the end of this fn, so make sure that this is the last instruction that
        // we need to relocate.
        if decoded_insn.insn.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_RET {
            break;
        }
        cur_index += decoded_insn.insn.length as usize;
    }
    Ok(RelocatedFnStart {
        relocated_insns_bytes,
        trampoline_jumper_target_offset,
        hooked_fn_runtime_addr,
    })
}

fn relocate_insn(
    decoded_insn: &DecodedInsnInfo,
    decoded_insn_offset: usize,
    relocated_insns_addr_range: &Range<u64>,
) -> Result<Option<RelocatedInsnBytes>, HookError> {
    if let Some(branch_kind) = mnemonic_is_branch(decoded_insn.insn.mnemonic) {
        return relocate_branch_insn(
            decoded_insn,
            decoded_insn_offset,
            branch_kind,
            relocated_insns_addr_range,
        );
    }
    // for detecting other branch types which we do not support, we can just check for rip relative immediate operands.
    if decoded_insn.does_have_rel_imm_operand() {
        return Err(HookError::UnsupportedRipRelativeInsn {
            offset: decoded_insn_offset,
        });
    }

    let mut rip_relative_operands = decoded_insn
        .visible_operands()
        .iter()
        .enumerate()
        .filter(|(_, operand)| is_operand_rip_relative_mem_access(&operand));
    let Some((rip_relative_operand_index, rip_relative_operand)) = rip_relative_operands.next()
    else {
        // no rip relative operands, so no need to relocate the instruction
        return Ok(None);
    };
    // an instruction can't have multiple rip relative operands
    assert!(rip_relative_operands.next().is_none());

    Ok(Some(relocate_mem_rip_insn(
        decoded_insn,
        decoded_insn_offset,
        rip_relative_operand,
        rip_relative_operand_index,
    )?))
}

fn relocate_mem_rip_insn(
    decoded_insn: &DecodedInsnInfo,
    decoded_insn_offset: usize,
    rip_relative_operand: &zydis_sys::ZydisDecodedOperand_,
    rip_relative_operand_index: usize,
) -> Result<RelocatedInsnBytes, HookError> {
    // if it uses the stack, we can't relocate it, since our relocation involves pushing some registers to the stack,
    // which will corrupt the instruction's behaviour.
    if decoded_insn.does_use_register(ZydisRegister::ZYDIS_REGISTER_RSP) {
        return Err(HookError::UnsupportedRipRelativeInsn {
            offset: decoded_insn_offset,
        });
    }

    // calculate the target address of the `rip+displacement`.
    let mem_operand = unsafe { &rip_relative_operand.__bindgen_anon_1.mem };
    let mem_operand_disp = if mem_operand.disp.has_displacement != 0 {
        mem_operand.disp.value
    } else {
        0
    };
    let mem_rip_target_addr = decoded_insn
        .end_addr()
        .wrapping_add_signed(mem_operand_disp);

    // find a usable temp register
    let tmp_reg = POSSIBLE_TMP_REGS
        .iter()
        .copied()
        .find(|tmp_reg| !decoded_insn.does_use_register(*tmp_reg))
        .expect("instruction uses all possible temporary registers");

    // re-encode the instruction but replace the `rip+displacement` part with `tmp_reg`.
    let mut encoder_req = decoded_insn.to_encoder_request(decoded_insn_offset)?;
    encoder_req.operands[rip_relative_operand_index]
        .mem
        .displacement = 0;
    encoder_req.operands[rip_relative_operand_index].mem.base = tmp_reg;
    let re_encoded = encode_insn(&encoder_req).map_err(|_| HookError::FailedToReEncodeInsn {
        offset: decoded_insn_offset,
    })?;

    // build the prefix and postfix
    let prefix = RelocatedMemRipPrefix::new(tmp_reg, mem_rip_target_addr);
    let postfix = RelocatedMemRipPostfix::new(tmp_reg);

    // combine all parts into a single byte array
    let mut relocated_insn_bytes = RelocatedInsnBytes::new();
    relocated_insn_bytes
        .try_extend_from_slice(as_raw_bytes(&prefix))
        .unwrap();
    relocated_insn_bytes
        .try_extend_from_slice(&re_encoded)
        .unwrap();
    relocated_insn_bytes
        .try_extend_from_slice(as_raw_bytes(&postfix))
        .unwrap();
    Ok(relocated_insn_bytes)
}

fn encode_insn(encoder_req: &ZydisEncoderRequest) -> Result<InsnBytes, ()> {
    let mut insn_bytes = InsnBytes::new();
    let mut insn_len = insn_bytes.capacity() as u64;
    let status = unsafe {
        ZydisEncoderEncodeInstruction(encoder_req, insn_bytes.as_mut_ptr().cast(), &mut insn_len)
    };
    zyan_check(status)?;
    assert!(insn_len <= insn_bytes.capacity() as u64);
    unsafe {
        insn_bytes.set_len(insn_len as usize);
    }
    Ok(insn_bytes)
}

fn relocate_branch_insn(
    decoded_insn: &DecodedInsnInfo,
    decoded_insn_offset: usize,
    branch_kind: BranchKind,
    relocated_insns_addr_range: &Range<u64>,
) -> Result<Option<RelocatedInsnBytes>, HookError> {
    assert_eq!(decoded_insn.visible_operands().len(), 1);
    let operand = &decoded_insn.visible_operands()[0];
    check_jmp_insn_doesnt_jump_into_relocated_insns(
        decoded_insn,
        decoded_insn_offset,
        relocated_insns_addr_range,
    )?;
    match operand.type_ {
        ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER
        | ZydisOperandType::ZYDIS_OPERAND_TYPE_POINTER => Ok(None),
        ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE => {
            let imm_operand = unsafe { &operand.__bindgen_anon_1.imm };
            if imm_operand.is_relative == 0 {
                // if it is not relative, no need to relocate it
                return Ok(None);
            }
            let insn_end_addr = decoded_insn.end_addr();
            let branch_target = insn_end_addr.wrapping_add(unsafe { imm_operand.value.u });
            let relocated_insn_bytes: RelocatedInsnBytes = match branch_kind {
                BranchKind::Jmp => as_raw_bytes(&RelocatedJmpImm::new(branch_target))
                    .try_into()
                    .unwrap(),
                BranchKind::CondJmp => as_raw_bytes(&RelocatedCondJmpImm::new(
                    decoded_insn.insn.mnemonic,
                    branch_target,
                ))
                .try_into()
                .unwrap(),
                BranchKind::Call => as_raw_bytes(&RelocatedCallImm::new(branch_target))
                    .try_into()
                    .unwrap(),
            };
            Ok(Some(relocated_insn_bytes))
        }
        ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY => Err(HookError::UnsupportedRipRelativeInsn {
            offset: decoded_insn_offset,
        }),
        _ => unreachable!(),
    }
}

fn check_jmp_insn_doesnt_jump_into_relocated_insns(
    decoded_insn: &DecodedInsnInfo,
    decoded_insn_offset: usize,
    relocated_insns_addr_range: &Range<u64>,
) -> Result<(), HookError> {
    assert_eq!(decoded_insn.visible_operands().len(), 1);
    let operand = &decoded_insn.visible_operands()[0];
    match operand.type_ {
        ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER
        | ZydisOperandType::ZYDIS_OPERAND_TYPE_POINTER => Ok(()),
        ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE => {
            let imm_operand = unsafe { &operand.__bindgen_anon_1.imm };
            let branch_target = if imm_operand.is_relative == 0 {
                unsafe { imm_operand.value.u }
            } else {
                let insn_end_addr = decoded_insn.end_addr();
                insn_end_addr.wrapping_add(unsafe { imm_operand.value.u })
            };
            if relocated_insns_addr_range.contains(&branch_target) {
                let branch_target_offset = branch_target - relocated_insns_addr_range.start;
                return Err(HookError::InsnJumpsIntoAnotherRelocatedInsn {
                    insn_offset: decoded_insn_offset,
                    target_offset: branch_target_offset as usize,
                });
            }
            Ok(())
        }
        ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY => Ok(()),
        _ => unreachable!(),
    }
}

fn mnemonic_is_branch(mnemonic: ZydisMnemonic) -> Option<BranchKind> {
    match mnemonic {
        ZydisMnemonic::ZYDIS_MNEMONIC_JMP => Some(BranchKind::Jmp),
        ZydisMnemonic::ZYDIS_MNEMONIC_CALL => Some(BranchKind::Call),
        ZydisMnemonic::ZYDIS_MNEMONIC_JB
        | ZydisMnemonic::ZYDIS_MNEMONIC_JBE
        | ZydisMnemonic::ZYDIS_MNEMONIC_JL
        | ZydisMnemonic::ZYDIS_MNEMONIC_JLE
        | ZydisMnemonic::ZYDIS_MNEMONIC_JNB
        | ZydisMnemonic::ZYDIS_MNEMONIC_JNBE
        | ZydisMnemonic::ZYDIS_MNEMONIC_JNL
        | ZydisMnemonic::ZYDIS_MNEMONIC_JNLE
        | ZydisMnemonic::ZYDIS_MNEMONIC_JNO
        | ZydisMnemonic::ZYDIS_MNEMONIC_JNP
        | ZydisMnemonic::ZYDIS_MNEMONIC_JNS
        | ZydisMnemonic::ZYDIS_MNEMONIC_JNZ
        | ZydisMnemonic::ZYDIS_MNEMONIC_JO
        | ZydisMnemonic::ZYDIS_MNEMONIC_JP
        | ZydisMnemonic::ZYDIS_MNEMONIC_JS
        | ZydisMnemonic::ZYDIS_MNEMONIC_JZ => Some(BranchKind::CondJmp),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum BranchKind {
    Jmp,
    CondJmp,
    Call,
}

/// information about relocated instructions from the start of a fn
pub struct RelocatedFnStart {
    /// the bytes of the relocated instructions.
    pub relocated_insns_bytes: RelocatedInsnsBytes,
    /// the offset in the hooked function where the trampoline jumper should jump to in order to continue execution of this function.
    pub trampoline_jumper_target_offset: usize,
    /// the runtime address of the hooked function.
    pub hooked_fn_runtime_addr: u64,
}
impl RelocatedFnStart {
    /// returns the size of the trampoline which will be built for this hooked fn.
    pub fn trampoline_size(&self) -> usize {
        self.relocated_insns_bytes.len() + LONG_JUMPER_LEN
    }

    /// builds a trampoline which will be placed at the given runtime address.
    /// the size of the trampoline can be determined by calling [`trampoline_size`].
    ///
    /// [`trampoline_size`]: HookInfo::trampoline_size
    pub fn build_trampoline(&self, trampoline_runtime_addr: u64) -> TrampolineBytes {
        let mut tramp_bytes = TrampolineBytes::new();
        tramp_bytes
            .try_extend_from_slice(&self.relocated_insns_bytes)
            .unwrap();
        let jumper = JumperKind::Long.build(
            trampoline_runtime_addr + self.relocated_insns_bytes.len() as u64,
            self.hooked_fn_runtime_addr + self.trampoline_jumper_target_offset as u64,
        );
        tramp_bytes.try_extend_from_slice(&jumper).unwrap();
        tramp_bytes
    }
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

    fn decode(&self, buf: &[u8], insn_runtime_addr: u64) -> Result<DecodedInsnInfo, ()> {
        let mut insn_uninit: MaybeUninit<ZydisDecodedInstruction> = MaybeUninit::uninit();
        let mut operands: ArrayVec<ZydisDecodedOperand, MAX_INSN_OPERANDS> = ArrayVec::new();

        let status = unsafe {
            ZydisDecoderDecodeFull(
                &self.decoder,
                buf.as_ptr().cast(),
                buf.len() as u64,
                insn_uninit.as_mut_ptr(),
                operands.as_mut_ptr(),
            )
        };
        zyan_check(status)?;

        let insn = unsafe { insn_uninit.assume_init() };
        assert!(insn.operand_count as usize <= operands.capacity());
        unsafe { operands.set_len(insn.operand_count as usize) }

        Ok(DecodedInsnInfo {
            insn,
            operands,
            addr: insn_runtime_addr,
        })
    }
}

fn is_operand_rip_relative_mem_access(operand: &ZydisDecodedOperand) -> bool {
    match operand.type_ {
        ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY => {
            if unsafe { operand.__bindgen_anon_1.mem }.base == ZydisRegister::ZYDIS_REGISTER_RIP {
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_operand_rip_relative_imm(operand: &ZydisDecodedOperand) -> bool {
    match operand.type_ {
        ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE => {
            unsafe { operand.__bindgen_anon_1.imm }.is_relative != 0
        }
        _ => false,
    }
}

#[derive(Debug)]
struct DecodedInsnInfo {
    addr: u64,
    insn: ZydisDecodedInstruction,
    operands: ArrayVec<ZydisDecodedOperand, MAX_INSN_OPERANDS>,
}
impl DecodedInsnInfo {
    fn end_addr(&self) -> u64 {
        self.addr + self.insn.length as u64
    }
    fn visible_operands(&self) -> &[ZydisDecodedOperand] {
        &self.operands[..self.insn.operand_count_visible as usize]
    }
    fn does_use_register(&self, reg: ZydisRegister) -> bool {
        self.operands
            .iter()
            .any(|operand| does_operand_use_register(operand, reg))
    }
    fn does_have_rel_imm_operand(&self) -> bool {
        self.operands
            .iter()
            .any(|operand| is_operand_rip_relative_imm(operand))
    }
    fn to_encoder_request(&self, insn_offset: usize) -> Result<ZydisEncoderRequest, HookError> {
        let mut encoder_req_uninit: MaybeUninit<ZydisEncoderRequest> = MaybeUninit::uninit();
        let status = unsafe {
            ZydisEncoderDecodedInstructionToEncoderRequest(
                &self.insn,
                self.operands.as_ptr(),
                self.insn.operand_count_visible,
                encoder_req_uninit.as_mut_ptr(),
            )
        };
        zyan_check(status).map_err(|_| HookError::FailedToReEncodeInsn {
            offset: insn_offset,
        })?;
        Ok(unsafe { encoder_req_uninit.assume_init() })
    }
}

fn does_operand_use_register(operand: &ZydisDecodedOperand, reg: ZydisRegister) -> bool {
    match operand.type_ {
        ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER => {
            do_regs_collide(unsafe { operand.__bindgen_anon_1.reg }.value, reg)
        }
        ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE
        | ZydisOperandType::ZYDIS_OPERAND_TYPE_POINTER => false,
        ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY => {
            let mem_operand = unsafe { &operand.__bindgen_anon_1.mem };
            do_regs_collide(mem_operand.segment, reg)
                || do_regs_collide(mem_operand.base, reg)
                || do_regs_collide(mem_operand.index, reg)
        }
        _ => unreachable!(),
    }
}

fn do_regs_collide(reg_a: ZydisRegister, reg_b: ZydisRegister) -> bool {
    if reg_a == reg_b {
        return true;
    }
    let largest_enclosing_reg_a = unsafe {
        ZydisRegisterGetLargestEnclosing(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64, reg_a)
    };
    if largest_enclosing_reg_a == ZydisRegister::ZYDIS_REGISTER_NONE {
        return false;
    }
    let largest_enclosing_reg_b = unsafe {
        ZydisRegisterGetLargestEnclosing(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64, reg_b)
    };
    if largest_enclosing_reg_b == ZydisRegister::ZYDIS_REGISTER_NONE {
        return false;
    }
    largest_enclosing_reg_a == largest_enclosing_reg_b
}

/// an error which occured while trying to relocate instructions.
#[derive(Debug, Error)]
pub enum HookError {
    #[error("failed to decode instruction at offset {offset}")]
    FailedToDecodeInsn { offset: usize },

    #[error("can't relocate rip relative instruction at offset {offset}")]
    UnsupportedRipRelativeInsn { offset: usize },

    #[error("function size {fn_size} is to small for jumper of size {jumper_size}")]
    FnTooSmallTooHook { fn_size: usize, jumper_size: usize },

    #[error("instruction at offset {insn_offset} jumps into a relocated instruction at offset {target_offset}")]
    InsnJumpsIntoAnotherRelocatedInsn {
        insn_offset: usize,
        target_offset: usize,
    },

    #[error("failed to re-encode instruction at offset {offset} while trying to relocate it")]
    FailedToReEncodeInsn { offset: usize },
}

/// the different kinds of jumper available
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
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
    pub fn build(&self, jumper_addr: u64, target_addr: u64) -> JumperBytes {
        match self {
            JumperKind::ShortRel => {
                let jmp_insn_end_addr = jumper_addr + SHORT_REL_JUMPER_LEN as u64;
                let displacement = target_addr.wrapping_sub(jmp_insn_end_addr) as i64;
                let displacement_i32 = i32::try_from(displacement)
                    .expect("tried to use a short relative jumper for but the distance from the hooked fn to the hook does not fit in 32 bits");
                let jumper = ShortRelJumper::new(displacement_i32);
                as_raw_bytes(&jumper).try_into().unwrap()
            }
            JumperKind::Short => {
                let hook_fn_addr_u32 = u32::try_from(target_addr).expect(
                    "tried to use a short jumper but the hook fn address does not fit in 32 bits",
                );
                let jumper = ShortJumper::new(hook_fn_addr_u32);
                as_raw_bytes(&jumper).try_into().unwrap()
            }
            JumperKind::Long => {
                let jumper = LongJumper::new(target_addr);
                as_raw_bytes(&jumper).try_into().unwrap()
            }
        }
    }
}

fn as_raw_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RelocatedMemRipPrefix {
    push_tmp_reg: PushGpr,
    mov_tmp_reg: MovGpr64BitImm,
}
impl RelocatedMemRipPrefix {
    fn new(tmp_reg: ZydisRegister, target_addr: u64) -> Self {
        Self {
            push_tmp_reg: PushGpr::new(tmp_reg),
            mov_tmp_reg: MovGpr64BitImm::new(tmp_reg, target_addr),
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RelocatedMemRipPostfix {
    pop_tmp_reg: PopGpr,
}
impl RelocatedMemRipPostfix {
    fn new(tmp_reg: ZydisRegister) -> Self {
        Self {
            pop_tmp_reg: PopGpr::new(tmp_reg),
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RelocatedJmpImm {
    jumper: LongJumper,
}
impl RelocatedJmpImm {
    fn new(target_addr: u64) -> Self {
        Self {
            jumper: LongJumper::new(target_addr),
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct JmpMemRipPlus {
    opcode: [u8; 2],
    rip_plus: i32,
}
impl JmpMemRipPlus {
    fn new(rip_plus: i32) -> Self {
        Self {
            opcode: [0xff, 0x25],
            rip_plus: rip_plus.to_le(),
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RelJmp8Bit {
    code: [u8; 2],
}
impl RelJmp8Bit {
    fn new(jmp_mnemonic: ZydisMnemonic, displacement: i8) -> Self {
        let mut encoder_request: ZydisEncoderRequest = unsafe { core::mem::zeroed() };
        encoder_request.machine_mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        encoder_request.mnemonic = jmp_mnemonic;
        encoder_request.operand_count = 1;
        encoder_request.operands[0].type_ = ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE;
        encoder_request.operands[0].imm.s = displacement as i64;
        let mut code = [0u8; 2];
        let mut code_len = code.len() as u64;
        let status = unsafe {
            ZydisEncoderEncodeInstruction(&encoder_request, code.as_mut_ptr().cast(), &mut code_len)
        };
        zyan_check(status).expect("failed to encode 2 byte relative conditional jump");
        assert_eq!(code_len, 2);
        Self { code }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PushGpr {
    code: u8,
}
impl PushGpr {
    fn new(gpr: ZydisRegister) -> Self {
        let mut encoder_request: ZydisEncoderRequest = unsafe { core::mem::zeroed() };
        encoder_request.machine_mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        encoder_request.mnemonic = ZydisMnemonic::ZYDIS_MNEMONIC_PUSH;
        encoder_request.operand_count = 1;
        encoder_request.operands[0].type_ = ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER;
        encoder_request.operands[0].reg.value = gpr;
        let mut code = [0u8; 1];
        let mut code_len = code.len() as u64;
        let status = unsafe {
            ZydisEncoderEncodeInstruction(&encoder_request, code.as_mut_ptr().cast(), &mut code_len)
        };
        zyan_check(status).expect("failed to encode 1 byte push gpr");
        assert_eq!(code_len, 1);
        Self { code: code[0] }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PopGpr {
    code: u8,
}
impl PopGpr {
    fn new(gpr: ZydisRegister) -> Self {
        let mut encoder_request: ZydisEncoderRequest = unsafe { core::mem::zeroed() };
        encoder_request.machine_mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        encoder_request.mnemonic = ZydisMnemonic::ZYDIS_MNEMONIC_POP;
        encoder_request.operand_count = 1;
        encoder_request.operands[0].type_ = ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER;
        encoder_request.operands[0].reg.value = gpr;
        let mut code = [0u8; 1];
        let mut code_len = code.len() as u64;
        let status = unsafe {
            ZydisEncoderEncodeInstruction(&encoder_request, code.as_mut_ptr().cast(), &mut code_len)
        };
        zyan_check(status).expect("failed to encode 1 byte pop gpr");
        assert_eq!(code_len, 1);
        Self { code: code[0] }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MovGpr64BitImm {
    code: [u8; 10],
}
impl MovGpr64BitImm {
    fn new(gpr: ZydisRegister, value: u64) -> Self {
        let mut encoder_request: ZydisEncoderRequest = unsafe { core::mem::zeroed() };
        encoder_request.machine_mode = ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64;
        encoder_request.mnemonic = ZydisMnemonic::ZYDIS_MNEMONIC_MOV;
        encoder_request.operand_count = 2;
        encoder_request.operands[0].type_ = ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER;
        encoder_request.operands[0].reg.value = gpr;
        encoder_request.operands[1].type_ = ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE;
        encoder_request.operands[1].imm.u = value;
        let mut code = [0u8; 10];
        let mut code_len = code.len() as u64;
        let status = unsafe {
            ZydisEncoderEncodeInstruction(&encoder_request, code.as_mut_ptr().cast(), &mut code_len)
        };
        zyan_check(status).expect("failed to encode 10 byte mov 64 bit immediate into gpr");
        assert_eq!(code_len, 10);
        Self { code }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RelocatedCondJmpImm {
    original_jmp: RelJmp8Bit,
    jmp_not_taken_jmp: RelJmp8Bit,
    jmp_taken_jumper: LongJumper,
}
impl RelocatedCondJmpImm {
    fn new(cond_jmp_mnemonic: ZydisMnemonic, target_addr: u64) -> Self {
        Self {
            original_jmp: RelJmp8Bit::new(
                cond_jmp_mnemonic,
                // we want it to skip the jmp not taken jmp and go to the jmp taken jumper
                core::mem::size_of::<RelJmp8Bit>() as i8,
            ),
            jmp_not_taken_jmp: RelJmp8Bit::new(
                ZydisMnemonic::ZYDIS_MNEMONIC_JMP,
                // we want it to skip the jmp taken jumper
                LONG_JUMPER_LEN as i8,
            ),
            jmp_taken_jumper: LongJumper::new(target_addr),
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RelocatedCallImm {
    push_rip_insn: [u8; PUSH_RIP_INSN_LEN],
    add_to_mem_rsp: Add8BitImmToMemRsp,
    jumper: LongJumper,
}
impl RelocatedCallImm {
    fn new(target_addr: u64) -> Self {
        Self {
            push_rip_insn: PUSH_RIP_INSN,
            // the pushed rip points to this `add` instruction, we want it to point after the entire relocated call, so skip both the
            // add and the jumper.
            add_to_mem_rsp: Add8BitImmToMemRsp::new(
                (core::mem::size_of::<Add8BitImmToMemRsp>() + LONG_JUMPER_LEN) as i8,
            ),
            jumper: LongJumper::new(target_addr),
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Add8BitImmToMemRsp {
    opcode: [u8; 4],
    add_value: i8,
}
impl Add8BitImmToMemRsp {
    fn new(add_value: i8) -> Self {
        Self {
            opcode: [0x48, 0x83, 0x04, 0x24],
            add_value,
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ShortRelJumper {
    jump_opcode: u8,
    displacement: i32,
}
impl ShortRelJumper {
    fn new(displacement: i32) -> Self {
        Self {
            jump_opcode: 0xe9,
            displacement: displacement.to_le(),
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ShortJumper {
    push: Push32BitImm,
    ret: u8,
}
impl ShortJumper {
    fn new(target_addr: u32) -> Self {
        Self {
            push: Push32BitImm::new(target_addr),
            ret: RET_INSN,
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Push32BitImm {
    push_opcode: u8,
    pushed_value: u32,
}
impl Push32BitImm {
    fn new(pushed_value: u32) -> Self {
        Self {
            push_opcode: 0x68,
            pushed_value: pushed_value.to_le(),
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct LongJumper {
    jmp_rip: JmpMemRipPlus,
    target_addr: u64,
}
impl LongJumper {
    fn new(target_addr: u64) -> Self {
        Self {
            jmp_rip: JmpMemRipPlus::new(0),
            target_addr: target_addr.to_le(),
        }
    }
}

#[allow(dead_code)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
union JumperUnion {
    short_rel: ShortRelJumper,
    short: ShortJumper,
    long: LongJumper,
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
