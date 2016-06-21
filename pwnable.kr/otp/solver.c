#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
        if (argc != 2) {
                printf("Usage: %s target\n", argv[0]);
                exit(0);
        }

        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGXFSZ);

        sigprocmask(SIG_BLOCK, &mask, NULL);

        char *arg[] = { "otp", "0", NULL };
        char *env[] = { NULL };

        execve(argv[1], arg, env);

        return 0;
}
