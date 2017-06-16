/*
 this is poorly coded version of Heap allocator that mimics the Windows LFH.
 this implementation assumes single-threaded program, also it sucks in terms of performance and stability and etc.
 but the point of this implementation is security PoC.
 I only spent a few hours to make this allocator, so don't blame it although its ridiculous :) - daehee.
*/

#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define SECURE_HEAP 1
#define INSECURE_HEAP 0
#define BUCKET_SIZE 0x4000
typedef unsigned int UINT;
typedef unsigned int BOOL;
using namespace std;

class Bucket{
public:
	Bucket* next;
	UINT security_mode;
	UINT chunk_class;
	UINT n_total_chunk;
	UINT n_alloc_chunk;
	char* bitarray;
	char* mem;
	char getBit(int index){ return (bitarray[index/8] >> 7-(index & 0x7)) & 0x1; }
	void setBit(int index){ bitarray[index/8] = bitarray[index/8] | 1 << 7-(index & 0x7); }
	void clearBit(int index){ bitarray[index/8] = bitarray[index/8] & ~(1 << 7-(index & 0x7)); }

	Bucket(UINT m_class, UINT mode){
		this->next = NULL;
		this->security_mode = mode;
		this->chunk_class = m_class;
		this->n_total_chunk = BUCKET_SIZE / this->chunk_class;
		this->n_alloc_chunk = 0;
		this->mem = (char*)mmap(0, BUCKET_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
		mmap(0, 0x1000, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);		// guard page
		this->bitarray = (char*)malloc( (this->n_total_chunk/8) + 1 );
	}

	void* Alloc(){
		if(this->n_alloc_chunk == n_total_chunk) return NULL;	// bucket is full.
		// R = rand number between (0 ~ n_free_chunk-1)
		UINT n_free_chunk = this->n_total_chunk - this->n_alloc_chunk;
		UINT R = ((UINT)rand() * 0xdeadbeef) % (n_free_chunk);
		UINT i = 0;
		UINT idx = 0;

		// find the index of first available chunk
		while(this->getBit(idx)){
			idx++;
		}

		// secure non-deterministic allocation for heap layout randomization
		if(this->security_mode == SECURE_HEAP){
			for(i=0; i<R; i++){
				// find the index of next available chunk
				do{
					idx++;
				}while(this->getBit(idx));
			}
		}

		if(idx >= this->n_total_chunk){
			exit(0);
		}

		this->setBit(idx);	// mark as allocated
		void* result;
		result = this->mem + (this->chunk_class * idx);
		this->n_alloc_chunk++;
		return result;
	}

	void Free(void* p){
		UINT idx=0;
		while(idx < this->n_total_chunk){
			// chunk to free
			if( (this->mem + (this->chunk_class * idx)) == p){
				this->clearBit(idx);
				this->n_alloc_chunk--;
				break;
			}
			idx++;
		}
	}
};

typedef struct _tagMETA{
	void* chunk_addr;
	Bucket* bucket;
	struct _tagMETA* next;
}META;

class LFH{
public:
	META* meta;
	UINT security_mode;	// security mode. 0:deterministic 1:non-deterministic
	Bucket* pbuck;

	LFH(UINT mode){
		this->meta = NULL;
		this->security_mode = mode;
		this->pbuck = NULL;
	}
	void* Alloc(UINT size){
			UINT chunk_class = (size/0x10) * 0x10 + 0x10;

		if(size>BUCKET_SIZE){
			printf("use different allocator for this size\n");
			return NULL;
		}
		if(this->pbuck==NULL){
			this->pbuck = new Bucket(chunk_class, this->security_mode);
			return this->pbuck->Alloc();
		}

		Bucket* bk = this->pbuck;
		void* r;
		META* m;

		while(1){
			// proper bucket found
			if(bk->chunk_class == chunk_class){
				r = bk->Alloc();
				if(r){
					m = (META*)malloc(sizeof(META));
					m->chunk_addr = r;
					m->bucket = bk;
					m->next = this->meta;
					this->meta = m;
					return r;	// allocation success! if not -> keep going
				}
			}
			if(bk->next==NULL) break;
			else bk = bk->next;
		}

		bk->next = new Bucket(chunk_class, this->security_mode);
		r = bk->next->Alloc();
		if(r){
			m = (META*)malloc(sizeof(META));
			m->chunk_addr = r;
			m->bucket = bk->next;
			m->next = this->meta;
			this->meta = m;
			return r;
		}

		return NULL;
	}
	void Free(void* p){
		META* m = this->meta;
		while(m){
			if(m->chunk_addr == p){
				m->bucket->Free(p);
				break;
			}
			m = m->next;
		}
	}
};

LFH* lfh;
void* HeapAlloc(UINT size){
	return lfh->Alloc(size);
}
void HeapFree(void* p){
	lfh->Free(p);
}

#pragma pack(1)
typedef struct _tagBOOK{
	char title[32];
	char abstract[256];
	void (*fptr)(struct _tagBOOK*);
	UINT content_len;
	BOOL is_unicode;
	char* content;
	struct _tagBOOK* next;
}BOOK;

void release_book(BOOK* p){
	HeapFree( p->content );
};

typedef struct _tagBOOKS{
	UINT n_total;
	BOOK* head;
}BOOKS;

BOOKS* load_file(const char* fname){
	int fd = open(fname, O_RDONLY);
	if(fd<0){
		printf("can't open %s\n", fname);
		exit(0);
	}

	// read file header
	UINT header;
	UINT r;
	r = read(fd, &header, 4);
	if(r!=4){
		printf("can't read file header\n");
		exit(0);
	}

	// check file header
	if(header!=0x4b4f4f42){
		printf("invalid file magic\n");
		exit(0);
	}

	// parse books
	BOOKS* books = (BOOKS*)HeapAlloc(sizeof(BOOKS));
	books->head = 0;
	books->n_total = 0;

	BOOK* pbook;
	UINT len=0;
	while(1){
		pbook = (BOOK*)HeapAlloc(sizeof(BOOK));
		r = read(fd, pbook, sizeof(BOOK));
		if(r!=sizeof(BOOK)){
			break;
		}

		pbook->title[31]=0;
		pbook->abstract[255]=0;
		pbook->content = 0;
		pbook->fptr = release_book;
		pbook->next = books->head;
		books->head = pbook;

		// restrict large string
		if(pbook->content_len > 0x1000){
			break;
		}
		pbook->content = (char*)HeapAlloc(pbook->content_len);
		memset(pbook->content, 0, pbook->content_len);
		len = pbook->content_len;
		if(pbook->is_unicode) len *= 2;

		r = read(fd, pbook->content, len);
		if(r!=len){
			break;
		}

		pbook->content[ len - 1 ] = 0;
		books->n_total++;
	}

	close(fd);
	return books;
}

int main(int argc, char* argv[]){

	// usage
	if(argc!=3){
		printf("usage: %s [file] [0|1]\n", argv[0]);
		exit(0);
	}

	// check file validity
	struct stat sb;
	if(stat(realpath(argv[1],0), &sb)==-1){
		printf("%s is not a valid file\n", realpath(argv[1],0));
		exit(0);
	}

	// setup pseudo-random seed
	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1){
		printf("cannot open /dev/urandom\n");
		exit(0);
	}

	int seed;
	read(fd, &seed, 4);
	srand(seed);
	close(fd);

	UINT mode = atoi(argv[2]);
	if(mode == SECURE_HEAP){
		printf("using secure non-deterministic heap.\n");
		printf("this option fortifies your heap from corruption. continue?(y/n)\n");
	}
	else if(mode == INSECURE_HEAP){
		printf("using unsecure deterministic heap.\n");
		printf("the program could be vulnerable to heap exploit attack. continue?(y/n)\n");
	}
	else{
		printf("unknown allocator mode\n");
		exit(0);
	}

	char c = getchar();
	if(c!='y'){
		printf("abort file processing.\n");
		exit(0);
	}

	lfh = new LFH(mode);
	BOOKS* books = load_file(argv[1]);		// input rendering
	BOOK* p = books->head;
	while(p){
		// display the book
		printf("title: %s\n", p->title);
		printf("abstract: %s\n", p->abstract);
		printf("content: %s\n", p->content);
		p = p->next;
	}

	printf("file processing done. terminating the program\n");

	p = books->head;
	BOOK* p2;
	while(p){
		p2 = p->next;
		p->fptr(p);		// typical destructor for objects.
		p = p2;
	}

	printf("%d books in %s file were successfully parsed\n", books->n_total, realpath(argv[1], 0));
	return 0;
}


