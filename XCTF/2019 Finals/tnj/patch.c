// gcc patch.c -fPIC -shared -o defender.so

#include <unistd.h>

typedef struct Attack
{
    int size;
    int loc;
    const char *buf;
} Attack;

// https://onlinedisassembler.com/odaweb/
// https://www.nxp.com/docs/en/reference-manual/M68000PRM.pdf
const char *start = "\x45\xF8\x00\x00";
const char *c = "\xF6\x0A\x4A\xFC\x4A\xFC";
const char *end = "\x4E\xF9\x00\x80\x04\x84";

void gen_defender(int *pipe, Attack attack)
{
    int cnt = 192;
    int payload_size = 4 + cnt * 6 + 6;
    write(pipe[1], &payload_size, 4);

    write(pipe[1], start, 4);
    for (int i = 0; i < cnt; i++)
    {
        write(pipe[1], c, 6);
    }
    write(pipe[1], end, 6);
}
