// gcc -o lokihardt lokihardt.c -fPIC -pie -Wl,-z,now
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>

#define LONG unsigned long long

typedef struct _OBJ{
    char rdata[256];
    char* wdata;
    LONG length;
    char* type;
}OBJ, *POBJ;

char g_buf[16];

POBJ AllocOBJ(){
    POBJ res = (POBJ)malloc(sizeof(OBJ));
    memset(res, 0, sizeof(OBJ));
    res->type = "null";
    fread(&(res->rdata), 1, 256, stdin);
    res->wdata = g_buf;
    res->length = sizeof(g_buf);
    fread(res->wdata, 1, res->length, stdin);
    return res;
}

#define MAXOBJ 16
void* randomPadding;
POBJ theOBJ;
POBJ ArrayBuffer[MAXOBJ];
int refCount;

void gc(){
    if(refCount == 0 && theOBJ != NULL){
        free(theOBJ);
        free(randomPadding);
        theOBJ = NULL;
    }
}

void Delete(unsigned int idx){
    ArrayBuffer[idx] = NULL;
    refCount--;
}

void Alloc(unsigned int idx){
    unsigned int rlen;
    if(refCount==0){
        // According to some research papers, random-heap-padding mitigates heap exploits!
        rlen = abs((rand()*1337) % 1024);
        randomPadding = malloc( rlen );
        memset(randomPadding, 0xcc, rlen);
        theOBJ = AllocOBJ();
    }
    ArrayBuffer[idx] = theOBJ;
    refCount++;
}

void Use(unsigned int idx){
    if(idx >= MAXOBJ){
        printf("runtime error: ArrayBuffer[%d] is out-of-range\n", idx);
        return;
    }

    POBJ p = ArrayBuffer[idx];
    if(p==NULL){
        printf("runtime error: ArrayBuffer[%d] is null\n", idx);
        return;
    }

    if(!strcmp(p->type, "read")){
        fwrite(&(p->rdata), 1, 256, stdout);
    }
    int n;
    if(!strcmp(p->type, "write")){
        printf("your data?");
        fread(p->wdata, 1, p->length, stdin);
    }
}

int main(){
    int fd = open("/dev/urandom", O_RDONLY);
    unsigned int seed;
    if(read(fd, &seed, 4)!=4){
        printf("urandom error\n");
        return 0;
    }
    srand(seed);
    alarm(100);
    setvbuf(stdout, 0, _IONBF, 0);	
    setvbuf(stdin, 0, _IONBF, 0);

    int menu = 0;
    int idx = 0;
    while(1){
        printf("- menu -\n");
        printf("- 1. : Alloc\n");
        printf("- 2. : Delete\n");
        printf("- 3. : Use\n");
        printf("- 4. : GarbageCollect\n");
        printf("- 5. : HeapSpray\n");
        printf("> ");
		
        scanf("%d", &menu);
        getchar();	// eat newline

        switch(menu){
            case 1: 
                printf("idx? ");
                scanf("%d", &idx);
                getchar();	// eat newline
                Alloc(idx);
                printf("ArrayBuffer[%d] = new Object()\n", idx);
                break;

            case 2: 
                printf("idx? ");
                scanf("%d", &idx);
                getchar();	// eat newline
                Delete(idx);
                printf("ArrayBuffer[%d] is deleted\n", idx);
                break;

            case 3: 
                printf("idx? ");
                scanf("%d", &idx);
                getchar();	// eat newline
                Use(idx);
                break;

            case 4:
                gc();
                break;

            case 5:
                AllocOBJ();
                break;

            default:
                printf("bye\n");
                exit(0);
                break;
        }
    }
    return 0;
}


