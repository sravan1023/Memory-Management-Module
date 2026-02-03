#ifndef _HEAP_H_
#define _HEAP_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Default heap parameters */
#ifndef HEAP_DEFAULT_SIZE
#define HEAP_DEFAULT_SIZE   (2 * 1024 * 1024)   /* 2MB default heap */
#endif

#ifndef HEAP_MIN_BLOCK
#define HEAP_MIN_BLOCK      32                   /* Minimum block size */
#endif

#ifndef HEAP_ALIGNMENT
#define HEAP_ALIGNMENT      8                    /* Memory alignment */
#endif

/* Magic numbers for integrity checking */
#define HEAP_MAGIC_FREE     0xFEEDFACE
#define HEAP_MAGIC_ALLOC    0xDEADBEEF

typedef struct heapblock {
    uint32_t            magic;      /* Magic number for validation */
    uint32_t            size;       /* Block size (including header) */
    struct heapblock   *next;       /* Next block in free list */
    struct heapblock   *prev;       /* Previous block in free list */
    uint32_t            flags;      /* Block flags */
    uint32_t            pad;        /* Padding for alignment */
} heapblock_t;

/* Block flags */
#define HEAP_FLAG_FREE      0x00    /* Block is free */
#define HEAP_FLAG_ALLOC     0x01    /* Block is allocated */
#define HEAP_FLAG_FIRST     0x02    /* First block in heap */
#define HEAP_FLAG_LAST      0x04    /* Last block in heap */

typedef struct heapstats {
    uint32_t total_size;        /* Total heap size */
    uint32_t free_size;         /* Total free memory */
    uint32_t used_size;         /* Total used memory */
    uint32_t block_count;       /* Number of free blocks */
    uint32_t largest_free;      /* Largest free block */
    uint32_t smallest_free;     /* Smallest free block */
    uint32_t total_allocs;      /* Total allocation requests */
    uint32_t total_frees;       /* Total free requests */
    uint32_t alloc_failures;    /* Failed allocations */
    uint32_t coalesce_count;    /* Block coalescing operations */
    uint32_t split_count;       /* Block split operations */
} heapstats_t;

bool heap_init(uint32_t base, uint32_t size);
void *heap_alloc(uint32_t size);
void *heap_alloc_aligned(uint32_t size, uint32_t align);
void *heap_calloc(uint32_t size);
void heap_free(void *ptr);
void heap_free_sized(void *ptr, uint32_t size);
void *heap_realloc(void *ptr, uint32_t oldsize, uint32_t newsize);

uint32_t heap_total(void);
uint32_t heap_free_mem(void);
uint32_t heap_used_mem(void);
uint32_t heap_largest_block(void);
int32_t heap_block_count(void);
heapstats_t heap_stats(void);
bool heap_validate(void);
void heap_dump(void);
int32_t heap_compact(void);

heapblock_t *heap_find_block(uint32_t size);
bool heap_split_block(heapblock_t *block, uint32_t size);
heapblock_t *heap_coalesce(heapblock_t *block);
void heap_add_to_freelist(heapblock_t *block);
void heap_remove_from_freelist(heapblock_t *block);

#endif /* _HEAP_H_ */


