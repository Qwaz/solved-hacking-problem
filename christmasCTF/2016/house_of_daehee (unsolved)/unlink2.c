// gcc -o unlink2 unlink2.c -fPIC -pie -Wl,-z,now
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
typedef struct tagOBJ{
	struct tagOBJ* fd;
	struct tagOBJ* bk;
	char buf[8];
}OBJ;

OBJ* A;
OBJ* B;
OBJ* C;
void unlink(OBJ* P){
	printf("First, we declare two OBJ pointers, to save the fd/bk of P\n");
	OBJ* BK;
	OBJ* FD;

	printf("P is actually the pointer of B that we made in main() function.\n");
	printf("To unlink B, we first need to get pointers of A (bk of B) and C (fd of B)\n");
	BK=P->bk;
	FD=P->fd;

	printf("Remember, FD here is P->fd, which is the pointer of C, inside object B\n");
	printf("Also, BK here is P->bk, which is the pointer of A, inside object B\n");
	printf("Therefore, we can control both FD and BK :)\n");
	printf("This, gives us 'arbitrary memory write' from the following step\n");

	// unlinking corrupted object!
	FD->bk=BK;
	BK->fd=FD;

	printf("using this primitive, change a function pointer (hint: GOT) into 'system' address that I gave you\n");
	printf("for example, overwrite the free.got into system. then free(P) becomes system(P)!! right?\n");
	free(P);    // put "/bin/sh" in P and get shell!
}

int main(int argc, char* argv[], char* envp[]){
	int i, j;
	i=0;
	while(argv[i]){
		j=0;
		while(argv[i][j]) argv[i][j++]=0;
		i++;
	}
	i=0;
	while(envp[i]){
		j=0;
		while(envp[i][j]) envp[i][j++]=0;
		i++;
	}

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IONBF, 0);
	
	printf("Welcome to house of daehee!\n");
	printf("This is simple tutorial to teach you basic heap exploitation technique!\n");
	printf("First, lets allocate three objects (A, B, C) that has small buffer and forward/backward pointers\n");

	A = (OBJ*)malloc(sizeof(OBJ));
	B = (OBJ*)malloc(sizeof(OBJ));
	C = (OBJ*)malloc(sizeof(OBJ));

	printf("Now, A B C is allocated inside heap (%p, %p, %p) respectively\n", A, B, C);
	printf("This time, lets make double-linked list with these objects\n");

	// make double linked list: A <-> B <-> C
	printf("First, lets set A's forward pointer (A->fd) to point B\n");
	A->fd = B;
	printf("Now, lets set B's backward pointer (B->bk) to point A\n");
	B->bk = A;
	printf("At this point, A and B is pointing each other.\n");
	printf("Now, lets do the same thing for B and C.\n");
	printf("let B->fd point C\n");
	B->fd = C;
	printf("Now, let C->bk point B\n");
	C->bk = B;

	printf("Ok, now we have the following object structure: A <-> B <-> C\n");
	printf("Assuming that we have memory leak, here is system address: %p. we will use this later to get shell :)\n", system);
	printf("Now, lets simulate a BOF vulnerability. Do some calculation and give me proper input to corrupt the B's fd/bk pointer\n");

	// heap overflow!
	gets(A->buf);

	printf("Goodjob. At this point, you have full control over B's forward and backword pointer\n");
	printf("Now, lets see what happens while unlinking B with fd/bk pointer of your control\n");

	// exploit this unlink!
	unlink(B);

	// cleanup
	free(C);
	free(B);
	free(A);

	printf("Thank you for watching this tutorial. I hope you understand the basics of unlink exploit now :D\n");
	getchar();
	return 0;
}

