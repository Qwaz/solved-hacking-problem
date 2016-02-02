#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

extern char **environ;

int main() {
	char *argv[101];

	int i;
	for (i = 0; i < 100; i++) {
		argv[i] = "a";
	}
	argv[100] = NULL;

	argv['A'] = "\x00";
	argv['B'] = "\x20\x0a\x0d";
	argv['C'] = "1231";

	putenv("\xde\xad\xbe\xef=\xca\xfe\xba\xbe");

	FILE *fp = fopen("\x0a", "w");
	fwrite("\x00\x00\x00\x00", sizeof(char), 4, fp);
	fclose(fp);

	fp = fopen("deadbeef", "w");
	fwrite("\xde\xad\xbe\xef", sizeof(char), 4, fp);
	fclose(fp);

	int p0[2], p1[2];
	pipe(p0);
	pipe(p1);

	pid_t pid;
	if ((pid = fork()) == -1) {
		puts("fork fail");
		return 0;
	}

	if (pid == 0) {
		//child
		close(p0[1]);
		close(p1[1]);

		//redirect pipe
		dup2(p0[0], 0);
		dup2(p1[0], 2);
		close(p0[0]);
		close(p1[0]);

		execve("/home/input/input", argv, environ);
	} else {
		//parent
		close(p0[0]);
		close(p1[0]);

		write(p0[1], "\x00\x0a\x00\xff", 4);
		write(p1[1], "\x00\x0a\x02\xff", 4);

		system("cat deadbeef | nc localhost 1231");
	}

	return 0;
}

