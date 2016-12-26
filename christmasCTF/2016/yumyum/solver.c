// g++ -o solver -O2 -std=c++0x solver.c

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>

char cerial[] = "!qw/LF6V|RY'/]e/bqFVtB9;Z}]{-";
char rev[1031][0xBF], res[30];

int main() {
    memset(rev, -1, sizeof(rev));

    for (int i = 0; i < 1031; i++) {
        for (char j = 32; j <= 126; j++) {
            int out = (17161 * (j * i + 415) - 566051) % 0xBFu;
            rev[i][out] = j;
        }
    }

    uint64_t now = time(0);

    int len = strlen(cerial);
    res[len] = 0;
    while (now) {
        srand(now - 80000 * (((int64_t)(( (unsigned __int128) 3777893186295716171LL * now) >> 64) >> 14) - (now >> 63)));
        int i = 0;
        for (; i < len; i++) {
            res[i] = rev[rand() % 1031][cerial[i]];
            if (res[i] == -1) break;
        }
        if (i == len) {
            printf("Current now: %lu\n", now);
            puts(res);
        }

        now--;
    }

    return 0;
}
