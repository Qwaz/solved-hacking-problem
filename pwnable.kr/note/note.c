#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#define PAGE_SIZE 4096

void* mmap_s(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
void* mem_arr[257];

void clear_newlines(void){
	int c;
	do{
		c = getchar();
	}while (c != '\n' && c != EOF);
}

void create_note(){
	int i;
	void* ptr;
	for(i=0; i<256; i++){
		if(mem_arr[i] == NULL){
			ptr = mmap_s((void*)NULL, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			mem_arr[i] = ptr;
			printf("note created. no %d\n [%08x]", i, (int)ptr);
			return;
		}
	}
	printf("memory sults are fool\n");
	return;
}

void write_note(){
	unsigned int no;
	printf("note no?\n");
	scanf("%d", &no);
	clear_newlines();
	if(no>256){
		printf("index out of range\n");
		return;
	}
	if(mem_arr[no]==NULL){
		printf("empty slut!\n");
		return;
	}
	printf("paste your note (MAX : 4096 byte)\n");
	gets(mem_arr[no]);
}

void read_note(){
	unsigned int no;
	printf("note no?\n");
	scanf("%d", &no);
	clear_newlines();
	if(no>256){
		printf("index out of range\n");
		return;
	}
	if(mem_arr[no]==NULL){
		printf("empty slut!\n");
		return;
	}
	printf("%s\n", mem_arr[no]);
}

void delete_note(){
	unsigned int no;
	printf("note no?\n");
	scanf("%d", &no);
	clear_newlines();
	if(no>256){
		printf("index out of range\n");
		return;
	}
	if(mem_arr[no]==NULL){
		printf("already empty slut!\n");
		return;
	}
	munmap(mem_arr[no], PAGE_SIZE);
	mem_arr[no] = NULL;
}

void select_menu(){
	// menu
	int menu;
	char command[1024];

	printf("- Select Menu -\n");
	printf("1. create note\n");
	printf("2. write note\n");
	printf("3. read note\n");
	printf("4. delete note\n");
	printf("5. exit\n");
	scanf("%d", &menu);
	clear_newlines();

	switch(menu){
		case 1:
			create_note();
			break;

		case 2:
			write_note();
			break;

		case 3:
			read_note();
			break;

		case 4:
			delete_note();
			break;6


		case 5:
			printf("bye\n");
			return;

		case 0x31337:
			printf("welcome to hacker's secret menu\n");
			printf("i'm sure 1byte overflow will be enough for you to pwn this\n");
			fgets(command, 1025, stdin);
			break;

		default:
			printf("invalid menu\n");
			break;
	}

	select_menu();
}

int main(){
	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("welcome to pwnable.kr\n\n");
	sleep(2);
	printf("recently I noticed that in 32bit system with no ASLR,\n");
	printf(" mmap(NULL... gives predictable address\n\n");
	sleep(2);
	printf("I believe this is not secure in terms of software exploit mitigation\n");
	printf("so I fixed this feature and called mmap_s\n\n");
	sleep(2);
	printf("please try out this sample note application to see how mmap_s works\n");
	printf("you will see mmap_s() giving true random address despite no ASLR\n\n");
	sleep(2);
	printf("I think security people will thank me for this :)\n\n");
	sleep(2);

	select_menu();
	return 0;
}

// secure mmap
void* mmap_s(void* addr, size_t length, int prot, int flags, int fd, off_t offset){

	// security fix: current version of mmap(NULL.. is not giving secure random address
	if(addr == NULL && !(flags & MAP_FIXED) ){
		void* tmp=0;
		int fd = open("/dev/urandom", O_RDONLY);
		if(fd==-1) exit(-1);
		if(read(fd, &addr, 4)!=4) exit(-1);
		close(fd);
		// to avoid heap fragmentation, lets skip malloc area
		addr = (void*)( ((int)addr & 0xFFFFF000) | 0x80000000 );

		while(1){
			// linearly search empty page (maybe this can be improved)
			tmp = mmap(addr, length, prot, flags | MAP_FIXED, fd, offset);
			if(tmp != MAP_FAILED){
				return tmp;
			}
			else{
				// memory already in use!
				addr = (void*)((int)addr + PAGE_SIZE);	// choose adjacent page
			}
		}
	}

	return mmap(addr, length, prot, flags, fd, offset);
}
