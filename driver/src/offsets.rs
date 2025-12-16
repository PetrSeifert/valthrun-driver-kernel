use alloc::{
    format,
    string::ToString,
};
use core::cell::SyncUnsafeCell;

use anyhow::Context;
use kapi::{
    KeGetCurrentIrql,
    DISPATCH_LEVEL,
};
use kapi_kmodule::{
    KModule,
    KModuleSection,
};
use obfstr::obfstr;
use utils_pattern::{
    ByteSequencePattern,
    SearchPattern,
    Signature,
    SignatureType,
};
use winapi::{
    shared::ntdef::PVOID,
    um::winnt::{
        IMAGE_SCN_MEM_DISCARDABLE,
        IMAGE_SCN_MEM_READ,
    },
};

/// Undocumented function/struct offsets
/// found by sigscanning
#[allow(non_snake_case)]
pub struct NtOffsets {
    pub PsGetNextProcess: unsafe extern "C" fn(PVOID) -> PVOID,
    pub MmVerifyCallbackFunctionFlags: unsafe extern "C" fn(callback: PVOID, flags: u32) -> bool,

    pub EPROCESS_ThreadListHead: usize,
}

static NT_OFFSETS: SyncUnsafeCell<Option<NtOffsets>> = SyncUnsafeCell::new(None);
pub fn get_nt_offsets() -> &'static NtOffsets {
    let nt_offsets = unsafe { &*NT_OFFSETS.get() };
    nt_offsets.as_ref().unwrap()
}

fn find_mm_verify_callback_function_flags_old(kernel_base: &KModule) -> anyhow::Result<usize> {
    let sig = Signature::relative_address(
        obfstr!("MmVerifyCallbackFunctionFlags"),
        obfstr!("E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 00"),
        0x01,
        0x05,
    );

    NtOffsets::locate_signature(kernel_base, &sig).with_context(|| {
        obfstr!("Failed to compile MmVerifyCallbackFunctionFlags pattern").to_string()
    })
}

fn find_mm_verify_callback_function_flags_new(kernel_base: &KModule) -> anyhow::Result<usize> {
    let pattern = ByteSequencePattern::parse(obfstr!(
        "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 8B FA 48 8B F1"
    ))
    .with_context(|| {
        obfstr!("Failed to compile MmVerifyCallbackFunctionFlags pattern").to_string()
    })?;

    kernel_base
        .find_code_sections()?
        .into_iter()
        .filter(KModuleSection::is_data_valid)
        .find_map(|section| {
            if let Some(data) = section.raw_data() {
                if let Some(offset) = pattern.find(data) {
                    Some(offset + section.raw_data_address())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .with_context(|| {
            format!(
                "failed to find {} pattern",
                obfstr!("MmVerifyCallbackFunctionFlags")
            )
        })
}

pub fn initialize_nt_offsets() -> anyhow::Result<()> {
    assert!(KeGetCurrentIrql() < DISPATCH_LEVEL);
    let ntoskrnl = KModule::find_by_name(obfstr!("ntoskrnl.exe"))?
        .with_context(|| obfstr!("failed to find kernel base").to_string())?;

    let ps_get_next_process = {
        [
            Signature::relative_address(
                obfstr!("PsGetNextProcess (2600.1252)"),
                obfstr!("E8 ? ? ? ? 48 8B D8 48 89 44 24 ? 48 85 C0 48"),
                0x01,
                0x05,
            ),
            /* Windows 11 */
            Signature::relative_address(
                obfstr!("PsGetNextProcess (Win 11)"),
                obfstr!("E8 ? ? ? ? 48 8B D8 48 85 C0 74 24 F7"),
                0x01,
                0x05,
            ),

            /* Win 11 25H2 26200.7462 */
            Signature::offset(
                obfstr!("_EPROCESS.ThreadListHead (26200.7462)"),
                obfstr!("4C 8D B1 ? ? ? ? 48 8B F2"),
                0x03,
            ),
            
            /* Windows 10 19045.4046 */
            Signature::relative_address(
                obfstr!("PsGetNextProcess (19045.4046)"),
                obfstr!("E8 ? ? ? ? 48 8B F8 48 85 C0 74 3B 4C"),
                0x01,
                0x05,
            ),
        ]
        .iter()
        .find_map(|sig| NtOffsets::locate_signature(&ntoskrnl, sig).ok())
        .map(|v| unsafe { core::mem::transmute_copy(&v) })
        .with_context(|| obfstr!("Failed to find PsGetNextProcess").to_string())?
    };

    let mm_verify_callback_function_flags = {
        [
            Signature::relative_address(
                obfstr!("MmVerifyCallbackFunctionFlags (2600.1252)"),
                obfstr!("E8 ? ? ? ? 85 C0 74 6F 48 8B 4E"),
                0x01,
                0x05,
            ),
            Signature::pattern(
                obfstr!("MmVerifyCallbackFunctionFlags (Win 11)"),
                obfstr!("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 8B FA 48 8B F1"),
            ),
            Signature::pattern(
                obfstr!("MmVerifyCallbackFunctionFlags"),
                obfstr!("E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 4D 00"),
            ),
        ]
        .iter()
        .find_map(|sig| NtOffsets::locate_signature(&ntoskrnl, sig).ok())
        .map(|v| unsafe { core::mem::transmute_copy(&v) })
        .with_context(|| obfstr!("Failed to find MmVerifyCallbackFunctionFlags").to_string())?
    };

    log::debug!(
        "{}::{} resolved to {:X} ({:X})",
        &ntoskrnl.file_name,
        obfstr!("MmVerifyCallbackFunctionFlags"),
        (mm_verify_callback_function_flags as u64) - ntoskrnl.base_address as u64,
        mm_verify_callback_function_flags as u64
    );
    let eprocess_thread_list_head = {
        [
            Signature::offset(
                obfstr!("_EPROCESS.ThreadListHead (2600.1252)"),
                obfstr!("4C 8D B1 ? ? ? ? 33 ED 45"),
                0x03,
            ),

            /* Windows 11 */
            Signature::offset(
                obfstr!("_EPROCESS.ThreadListHead (Win 11)"),
                obfstr!("4C 8D A9 ? ? ? ? 33 DB"),
                0x03,
            ),
            /* Windows 11 24H2 26100.7462 - ThreadListHead offset 0x370
             * Pattern from PspGetPreviousProcessThread:
             *   mov r12, gs:[188h]    ; 65 4C 8B 24 25 88 01 00 00
             *   lea r14, [rcx+370h]   ; 4C 8D B1 70 03 00 00  <- ThreadListHead
             *   mov rsi, rdx          ; 48 8B F2
             */
            Signature::offset(
                obfstr!("_EPROCESS.ThreadListHead (26100)"),
                obfstr!("65 4C 8B 24 25 88 01 00 00 4C 8D B1 ? ? ? ? 48 8B F2"),
                0x0C,
            ),
            /* Windows 11 25H2 26200.7462 */
            Signature::offset(
                obfstr!("_EPROCESS.ThreadListHead (26200)"),
                obfstr!("4C 8D B1 ? ? ? ? 48 8B F2"),
                0x03,
            ),
            /* Windows 10 19045.4046 (Actually finds PspGetPreviousProcessThread and PsGetNextProcessThread) */
            Signature::offset(
                obfstr!("_EPROCESS.ThreadListHead (19045.4046)"),
                obfstr!("48 83 EC 20 65 4C 8B 24 25 88 01 00 00 4C 8D B1 ? ? 00 00 45 33 ED"),
                0x10,
            ),
        ]
        .iter()
        .find_map(|sig| NtOffsets::locate_signature(&ntoskrnl, sig).ok())
        .with_context(|| obfstr!("Failed to find _EPROCESS.ThreadListHead").to_string())?
    };

    let offsets = NtOffsets {
        PsGetNextProcess: ps_get_next_process,
        MmVerifyCallbackFunctionFlags: mm_verify_callback_function_flags,

        EPROCESS_ThreadListHead: eprocess_thread_list_head,
    };

    let nt_offsets = unsafe { &mut *NT_OFFSETS.get() };
    *nt_offsets = Some(offsets);

    Ok(())
}

impl NtOffsets {
    pub fn locate_signature(module: &KModule, signature: &Signature) -> anyhow::Result<usize> {
        log::trace!(
            "Resolving '{}' in {}",
            signature.debug_name,
            module.file_name
        );

        let (section, inst_offset) = module
            .find_code_sections()?
            .into_iter()
            .find_map(|section| {
                if (section.characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 {
                    /* Section is discardable and most likely has been discarded */
                    log::debug!(
                        "  Skipping {} as it's discardable ({:X})",
                        section.name,
                        section.characteristics
                    );
                    return None;
                }
                if (section.characteristics & IMAGE_SCN_MEM_READ) == 0 {
                    /* Section is not readable */
                    log::debug!(
                        "  Skipping {} as it's not readable ({:X})",
                        section.name,
                        section.characteristics
                    );
                    return None;
                }

                if let Some(offset) = signature.pattern.find(section.raw_data_unchecked()) {
                    Some((section, offset))
                } else {
                    None
                }
            })
            .with_context(|| format!("failed to find {} pattern", signature.debug_name))
            .inspect_err(|_| log::trace!("  => not found"))?;

        if matches!(&signature.value_type, SignatureType::Pattern) {
            let address = section.raw_data_address().wrapping_add(inst_offset);
            log::trace!("  => {:X} ({:X})", address, inst_offset);
            return Ok(address);
        }

        let value = unsafe {
            (section.raw_data_address() as *const ())
                .byte_add(inst_offset)
                .byte_add(signature.offset as usize)
                .cast::<u32>()
                .read_unaligned()
        };
        match &signature.value_type {
            SignatureType::Offset => {
                let value = value as usize;
                log::trace!("  => {:X} (inst at {:X})", value, inst_offset);
                Ok(value)
            }
            SignatureType::RelativeAddress { inst_length } => {
                let value = section
                    .raw_data_address()
                    .wrapping_add(inst_offset)
                    .wrapping_add(*inst_length)
                    .wrapping_add_signed(value as i32 as isize);
                log::trace!("  => {:X} ({:X})", value, value - module.base_address,);
                Ok(value)
            }
            SignatureType::Pattern => unreachable!(),
        }
    }
}
