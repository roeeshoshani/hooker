use hooker::{
    determine_best_jumper_kind, determine_best_jumper_kind_and_build, gen_hook_info,
    relocate_fn_start,
};
use memmap::{MmapMut, MmapOptions};
use proc_maps::{get_process_maps, MapRange, Pid};
use rand::random;

/// find the memory mapping of the `.text` section, where our code is
fn find_text_section_mapping() -> MapRange {
    let hooked_function_addr = hooked_function as usize;
    let existing_mappings = get_process_maps(std::process::id() as Pid)
        .expect("failed to get current process memory maps");
    existing_mappings
        .into_iter()
        .find(|mapping| {
            let mapping_range = mapping.start()..mapping.start() + mapping.size();
            mapping_range.contains(&hooked_function_addr)
        })
        .expect("failed to find text section mapping")
}

/// creates a new anonymous memory mapping and copies the contents of the given mapping into it.
fn remap_and_copy_mapping(mapping: &MapRange) -> MmapMut {
    let mut created_mapping = alloc_anon_mapping(mapping.size());
    created_mapping.copy_from_slice(unsafe {
        core::slice::from_raw_parts(mapping.start() as *const u8, mapping.size())
    });
    created_mapping
}

/// allocate an anonymous memory mapping of the given size.
fn alloc_anon_mapping(size: usize) -> MmapMut {
    MmapOptions::new()
        .len(size)
        .map_anon()
        .expect("failed to create anonymous memory mapping")
}

fn main() {
    let text_section_mapping = find_text_section_mapping();
    let mut created_mapping = remap_and_copy_mapping(&text_section_mapping);

    // calculate the address of the hooked function in the new mapping
    let hooked_function_offset_in_mapping = hooked_function as usize - text_section_mapping.start();
    let hooked_function_remapped_addr =
        hooked_function_offset_in_mapping + created_mapping.as_ptr() as usize;

    // build the jumper
    let hook_info = gen_hook_info(
        &created_mapping[hooked_function_offset_in_mapping..],
        hooked_function_remapped_addr as u64,
        hook_function as u64,
    )
    .expect("");

    // allocate and build trampoline
    let mut trampoline_mapping = alloc_anon_mapping(hook_info.trampoline_size());
    let trampoline = hook_info.build_trampoline(trampoline_mapping.as_mut_ptr() as u64);
    trampoline_mapping[..trampoline.len()].copy_from_slice(&trampoline);

    // write the jumper to the start of the hooked function
    let jumper = hook_info.jumper();
    created_mapping[hooked_function_offset_in_mapping..][..jumper.len()].copy_from_slice(&jumper);

    // make the remapped text section executable
    let _executable_created_mapping = created_mapping
        .make_exec()
        .expect("failed to make mapping executable");
    let hooked_function_remapped: extern "C" fn(u32) -> u32 =
        unsafe { core::mem::transmute(hooked_function_remapped_addr) };

    // call the hooked function
    println!("calling hooked function");
    let result = hooked_function_remapped(1337);
    println!("hooked function returned {}", result);

    // make the trampoline executable
    let executable_trampoline_mapping = trampoline_mapping
        .make_exec()
        .expect("failed to make mapping executable");
    let trampoline_fn: extern "C" fn(u32) -> u32 =
        unsafe { core::mem::transmute(executable_trampoline_mapping.as_ptr()) };

    // call the trampoline to call the original function
    println!("calling trampoline");
    let tramp_result = trampoline_fn(5);
    println!("trampoline returned {}", tramp_result);
}

extern "C" fn hooked_function(input: u32) -> u32 {
    let mut result = 1u32;
    for i in 2..input {
        result *= i;
    }
    result
}

extern "C" fn hook_function(input: u32) -> u32 {
    println!("hook was called, input: {}", input);
    33
}
