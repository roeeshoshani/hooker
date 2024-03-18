use hooker::gen_hook_info;
use region::{Allocation, Protection, Region};

/// find the memory mapping of the `.text` section, where our code is
fn mem_region_of_hooked_fn() -> Region {
    region::query(hooked_fn as *const u8)
        .expect("failed to find memory region containing hooked fn")
}

/// make the memory region containing the hooked fn writable.
fn make_rwx(region: &Region) {
    unsafe {
        region::protect(
            region.as_ptr::<u8>(),
            region.len(),
            Protection::READ_WRITE_EXECUTE,
        )
        .expect("failed to make region rwx")
    };
}

/// allocate an anonymous memory mapping of the given size.
fn alloc_rwx(size: usize) -> Allocation {
    region::alloc(size, Protection::READ_WRITE_EXECUTE).expect("failed to allocate rwx memory")
}

fn main() {
    // make the hooked fn writable
    let hooked_fn_region = mem_region_of_hooked_fn();
    make_rwx(&hooked_fn_region);

    // generate a slice of the possible content of the hooked fn, that is the content from the start of the hooked fn to the
    // end of the region which contains it.
    let hooked_fn_region_end_addr =
        hooked_fn_region.as_ptr::<u8>() as usize + hooked_fn_region.len();
    let hooked_fn_possible_content = unsafe {
        core::slice::from_raw_parts(
            hooked_fn as *const u8,
            hooked_fn_region_end_addr - hooked_fn as usize,
        )
    };

    // generate the hook info
    let hook_info = gen_hook_info(hooked_fn_possible_content, hooked_fn as u64, hook_fn as u64)
        .expect("failed to generate hook info");

    // allocate and build trampoline
    let mut trampoline_alloc = alloc_rwx(hook_info.trampoline_size());
    let trampoline = hook_info.build_trampoline(trampoline_alloc.as_mut_ptr::<u8>() as u64);
    println!("trampoline code: {:02x?}", trampoline.as_slice());
    unsafe {
        trampoline_alloc
            .as_mut_ptr::<u8>()
            .copy_from_nonoverlapping(trampoline.as_ptr(), trampoline.len())
    };

    // write the jumper to the start of the hooked fn
    let jumper = hook_info.jumper();
    println!("jumper code: {:02x?}", jumper.as_slice());
    let hooked_fn_content_ptr = hooked_fn as *mut u8;

    // call the hooked fn
    unsafe { hooked_fn_content_ptr.copy_from_nonoverlapping(jumper.as_ptr(), jumper.len()) };
    println!("calling hooked fn");
    let result = hooked_fn(1337);
    println!("hooked fn returned {}", result);

    // call the trampoline to call the original fn
    let trampoline_fn: extern "C" fn(u32) -> u32 =
        unsafe { core::mem::transmute(trampoline_alloc.as_ptr::<u8>()) };
    println!("calling trampoline");
    let tramp_result = trampoline_fn(5);
    println!("trampoline returned {}", tramp_result);
}

#[inline(never)]
extern "C" fn hooked_fn(mut input: u32) -> u32 {
    // force some conditional branches at the start of the function so that relocation is performed
    if input == 0 {
        77
    } else {
        for i in 2..10 {
            input ^= input / i;
        }
        input * 1000
    }
}

#[inline(never)]
extern "C" fn hook_fn(input: u32) -> u32 {
    println!("hook was called, input: {}", input);
    33
}
