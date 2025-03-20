#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <errno.h>
#include <proto/exec.h>

static APTR mempool;

#define ALLOC_EXTRA_BYTES 0

int setup_malloc(void) {
	mempool = CreatePool(MEMF_ANY, 8192, 2048);
	return mempool != NULL;
}

void cleanup_malloc(void) {
	DeletePool(mempool);
}

void *malloc(size_t size) {
	size_t *pmem = AllocPooled(mempool, size + sizeof(size_t) + ALLOC_EXTRA_BYTES);
	if (pmem != NULL) {
		*pmem++ = size;
	} else
		errno = ENOMEM;
	return pmem;
}

void free(void *ptr) {
	if (ptr != NULL) {
		size_t *pmem = ptr;
		size_t size = *--pmem;
		FreePooled(mempool, pmem, size + sizeof(size_t) + ALLOC_EXTRA_BYTES);
	}
}

static inline size_t get_malloc_size(const void *ptr) {
	if (ptr != NULL) {
		const size_t *pmem = ptr;
		return *--pmem;
	} else {
		return 0;
	}
}

void *calloc(size_t num, size_t size) {
	size *= num;
	void *ptr = malloc(size);
#if defined(__AROS__)
	// -O2 on GCC 6.5.0 leads to wrong code generation,
	// no call to malloc or bzero and jmp to calloc again
	if (ptr != NULL)
	{
		char *p = (char *)ptr;
		while(size-- != 0) {*p = 0; p++;}
	}
#else
	if (ptr != NULL) bzero(ptr, size);
#endif
	return ptr;
}

void *realloc(void *ptr, size_t size) {
	size_t osize;
	void *nptr;
	if (ptr == NULL) return malloc(size);
	osize = get_malloc_size(ptr);
	if (size == osize) return ptr;
	nptr = malloc(size);
	if (nptr != NULL) memcpy(nptr, ptr, MIN(size, osize));
	free(ptr);
	return nptr;
}

