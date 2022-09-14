#ifndef WRAPPER_H
#define WRAPPER_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*LOLI_ALLOC_FPTR)(void*, size_t);
typedef void* (*MALLOC_FPTR)(size_t);
typedef void (*FREE_FPTR)(void*);
typedef void* (*CALLOC_FPTR)(int, int);
typedef void* (*MEMALIGN_FPTR)(size_t, size_t);
typedef int (*POSIX_MEMALIGN_FPTR)(void**, size_t, size_t);
typedef void* (*REALLOC_FPTR)(void*, size_t);
// typedef int (*BACKTRACE_FPTR)(void** buffer, size_t max);


typedef struct _hook_info {
    char* so_name = nullptr;
    uintptr_t so_baseaddr = 0;
    LOLI_ALLOC_FPTR custom_alloc;
    MALLOC_FPTR malloc;
    FREE_FPTR free;
    CALLOC_FPTR calloc;
    MEMALIGN_FPTR memalign;
    POSIX_MEMALIGN_FPTR posix_memalign;
    REALLOC_FPTR realloc;
    // BACKTRACE_FPTR backtrace = nullptr;
    ~_hook_info();
} HOOK_INFO;


bool wrapper_init();
HOOK_INFO* wrapper_by_index(int index);
HOOK_INFO* wrapper_by_name(const char* name);



#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* WRAPPER_H */