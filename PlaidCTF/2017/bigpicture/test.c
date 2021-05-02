//$ gcc -fPIE -pie test.c -o test

#include <stdio.h>
#include <stdlib.h>

char *buf1, *buf2;

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    buf1 = calloc(300, 1);
    buf2 = calloc(100, 10000);

    printf("Main:\t\t%p\n", main);
    printf("calloc buffer:\t%p\n", buf1);
    printf("mmap buffer:\t%p\n", buf2);
    printf("libc system:\t%p\n", system);

    printf("mmap - libc = %lx\n", (void*)buf2-(void*)system);

    return 0;
}
