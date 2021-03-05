# Memo

## WASM Reversing IDA tips (from jinmo123)

1. Rebase binary to non-zero address (e.g., 0x4000000)
    * Edit -> Segments -> Rebase
2. Allocate segment at 0x100000, size (0x1000000)
    * Edit -> Segments -> Create segment
2. Check the `init_memory()` function
    * `memcpy((void *)(memory + 0x100000), &data_segment_data_0, 0x32F1u)`
    * Address of `data_segment_data_0` = 0x004684E0
3. Patch bytes with IDAPython
    * `idaapi.patch_bytes(0x100000, idaapi.get_bytes(0x004684E0, 0x32F1))`
4. IDA has a bug handling `jmp rax`. Patch the first byte as null.

If a value is an address but IDA recognizes it as an integer, go to the disassembly view and press O key.

## Reversing memo

* Vtable
    * Fat pointer: (data, vtable)
    * (vtable + 12) is `inspect()`
    * New Sword vtable: (0B, 18, 4, 0C, 0D)
    * Rusty Sword vtable: (0E, 0C, 4, 0F, 10)
* Function Table
    * T0 is the function table
    * Function table also stores a fat pointer: (type, address)
        * This is C implementation detail
* Main stack layout (Decimal offset)
    * ....-2400
    * 2072-2328: log
    * 2070-2072: input_buf
    * 0016-2064: stock
* Misc
    * Stack starts at 0x100000
    * global 0 and local 0 are sp
    * String is ((addr, cap), len)
    * "excalibur.txt" is at 0x100390
