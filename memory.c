#include "memory.h"
#include "heap.h"
#include "paging.h"
#include "../include/kernel.h"
#include "../include/interrupts.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static bool memory_initialized = false;

/* Memory regions */
static memregion_t memory_regions[16];
static int num_regions = 0;

/* Default memory pool */
#ifndef __LINKER_DEFINED_HEAP__
static char heap_pool[HEAP_SIZE] __attribute__((aligned(4096)));
static char stack_pool[STACK_POOL_SIZE] __attribute__((aligned(4096)));
#endif

/* Stack pool state */
static uint32_t stack_base = 0;
static uint32_t stack_end = 0;
static uint32_t stack_free = 0;

void mem_init(void) {
    uint32_t heap_start, heap_end_addr;
    
    if (memory_initialized) {
        return;
    }
    
    /* Clear region list */
    memset(memory_regions, 0, sizeof(memory_regions));
    num_regions = 0;
    
#ifndef __LINKER_DEFINED_HEAP__
    /* Use static pools */
    heap_start = (uint32_t)heap_pool;
    heap_end_addr = heap_start + HEAP_SIZE;
    
    stack_base = (uint32_t)stack_pool;
    stack_end = stack_base + STACK_POOL_SIZE;
    stack_free = STACK_POOL_SIZE;
#else
    /* Use linker-defined regions */
    extern char _heap_start, _heap_end;
    extern char _stack_pool_start, _stack_pool_end;
    
    heap_start = (uint32_t)&_heap_start;
    heap_end_addr = (uint32_t)&_heap_end;
    
    stack_base = (uint32_t)&_stack_pool_start;
    stack_end = (uint32_t)&_stack_pool_end;
    stack_free = stack_end - stack_base;
#endif
    
    /* Initialize heap */
    if (!heap_init(heap_start, heap_end_addr - heap_start)) {
        /* Critical error - can't continue without heap */
        return;
    }
    
    /* Record heap region */
    memory_regions[num_regions].base = heap_start;
    memory_regions[num_regions].size = heap_end_addr - heap_start;
    memory_regions[num_regions].type = MEM_TYPE_HEAP;
    memory_regions[num_regions].flags = 0;
    num_regions++;
    
    /* Record stack region */
    memory_regions[num_regions].base = stack_base;
    memory_regions[num_regions].size = stack_end - stack_base;
    memory_regions[num_regions].type = MEM_TYPE_STACK;
    memory_regions[num_regions].flags = 0;
    num_regions++;
    
    /* Initialize paging */
    paging_init();
    
    memory_initialized = true;
}

void mem_init_region(uint32_t base, uint32_t size) {
    if (num_regions >= 16) {
        return;
    }
    
    memory_regions[num_regions].base = base;
    memory_regions[num_regions].size = size;
    memory_regions[num_regions].type = MEM_TYPE_USABLE;
    memory_regions[num_regions].flags = 0;
    num_regions++;
}

void *getmem(uint32_t nbytes) {
    if (!memory_initialized) {
        mem_init();
    }
    return heap_alloc(nbytes);
}

syscall freemem(void *block, uint32_t nbytes) {
    if (!memory_initialized || block == NULL) {
        return SYSERR;
    }
    
    heap_free_sized(block, nbytes);
    return OK;
}

void *getmem_aligned(uint32_t nbytes, uint32_t align) {
    if (!memory_initialized) {
        mem_init();
    }
    return heap_alloc_aligned(nbytes, align);
}

void *realloc(void *ptr, uint32_t oldsize, uint32_t newsize) {
    if (!memory_initialized) {
        mem_init();
    }
    return heap_realloc(ptr, oldsize, newsize);
}

void *calloc(uint32_t count, uint32_t size) {
    void *ptr;
    uint32_t total = count * size;
    
    if (!memory_initialized) {
        mem_init();
    }
    
    /* Check for overflow */
    if (count != 0 && total / count != size) {
        return NULL;
    }
    
    ptr = heap_alloc(total);
    if (ptr != NULL) {
        memzero(ptr, total);
    }
    
    return ptr;
}

typedef struct stackblock {
    struct stackblock *next;
    uint32_t size;
} stackblock_t;

static stackblock_t *stack_freelist = NULL;
static bool stack_initialized = false;

static void stack_init_allocator(void) {
    if (stack_initialized) {
        return;
    }
    
    /* Create initial free block */
    stack_freelist = (stackblock_t *)stack_base;
    stack_freelist->next = NULL;
    stack_freelist->size = stack_end - stack_base;
    
    stack_initialized = true;
}

void *getstk(uint32_t nbytes) {
    stackblock_t *curr, *prev;
    uint32_t needed;
    intmask mask;
    
    if (!memory_initialized) {
        mem_init();
    }
    
    if (!stack_initialized) {
        stack_init_allocator();
    }
    
    if (nbytes == 0) {
        return (void *)SYSERR;
    }
    
    /* Round up to alignment */
    needed = ROUNDUP(nbytes + sizeof(stackblock_t), MEM_ALIGN);
    
    mask = disable();
    
    /* First-fit search */
    prev = NULL;
    curr = stack_freelist;
    
    while (curr != NULL) {
        if (curr->size >= needed) {
            /* Found suitable block */
            
            if (curr->size >= needed + sizeof(stackblock_t) + 64) {
                /* Split block */
                stackblock_t *new_block;
                new_block = (stackblock_t *)((char *)curr + needed);
                new_block->next = curr->next;
                new_block->size = curr->size - needed;
                
                curr->size = needed;
                
                if (prev != NULL) {
                    prev->next = new_block;
                } else {
                    stack_freelist = new_block;
                }
            } else {
                /* Use entire block */
                if (prev != NULL) {
                    prev->next = curr->next;
                } else {
                    stack_freelist = curr->next;
                }
            }
            
            stack_free -= curr->size;
            
            restore(mask);
            
            /* Return top of stack (high address) */
            return (void *)((char *)curr + curr->size - sizeof(stackblock_t));
        }
        
        prev = curr;
        curr = curr->next;
    }
    
    restore(mask);
    return (void *)SYSERR;
}

syscall freestk(void *stktop, uint32_t nbytes) {
    stackblock_t *block, *curr, *prev;
    uint32_t size;
    intmask mask;
    
    if (!memory_initialized || stktop == NULL || nbytes == 0) {
        return SYSERR;
    }
    
    size = ROUNDUP(nbytes + sizeof(stackblock_t), MEM_ALIGN);
    
    /* Calculate block start from stack top */
    block = (stackblock_t *)((char *)stktop - size + sizeof(stackblock_t));
    block->size = size;
    
    mask = disable();
    
    /* Insert into free list (sorted by address) */
    prev = NULL;
    curr = stack_freelist;
    
    while (curr != NULL && curr < block) {
        prev = curr;
        curr = curr->next;
    }
    
    block->next = curr;
    if (prev != NULL) {
        prev->next = block;
    } else {
        stack_freelist = block;
    }
    
    /* Coalesce with next */
    if (curr != NULL && (char *)block + block->size == (char *)curr) {
        block->size += curr->size;
        block->next = curr->next;
    }
    
    /* Coalesce with previous */
    if (prev != NULL && (char *)prev + prev->size == (char *)block) {
        prev->size += block->size;
        prev->next = block->next;
    }
    
    stack_free += size;
    
    restore(mask);
    return OK;
}

void *alloc_page(void) {
    if (!memory_initialized) {
        mem_init();
    }
    return paging_alloc_page();
}

void *alloc_pages(uint32_t count) {
    if (!memory_initialized) {
        mem_init();
    }
    return paging_alloc_pages(count);
}

void free_page(void *page) {
    if (!memory_initialized || page == NULL) {
        return;
    }
    paging_free_page(page);
}

void free_pages(void *page, uint32_t count) {
    if (!memory_initialized || page == NULL) {
        return;
    }
    paging_free_pages(page, count);
}

memstats_t mem_stats(void) {
    memstats_t stats;
    heapstats_t hstats;
    paging_stats_t pstats;
    
    memset(&stats, 0, sizeof(stats));
    
    if (!memory_initialized) {
        return stats;
    }
    
    /* Get heap stats */
    hstats = heap_stats();
    stats.heap_total = hstats.total_size;
    stats.heap_free = hstats.free_size;
    stats.heap_used = hstats.used_size;
    stats.heap_blocks = hstats.block_count;
    stats.heap_largest = hstats.largest_free;
    stats.heap_allocs = hstats.total_allocs;
    stats.heap_frees = hstats.total_frees;
    stats.heap_failures = hstats.alloc_failures;
    
    /* Get stack stats */
    stats.stack_total = stack_end - stack_base;
    stats.stack_free = stack_free;
    stats.stack_used = stats.stack_total - stack_free;
    
    /* Get paging stats */
    pstats = paging_stats();
    stats.frames_total = pstats.frames_total;
    stats.frames_free = pstats.frames_free;
    stats.frames_used = pstats.frames_used;
    stats.pages_total = pstats.frames_total;
    stats.pages_free = pstats.frames_free;
    stats.pages_used = pstats.frames_used;
    stats.page_faults = pstats.page_faults;
    
    return stats;
}

uint32_t mem_avail(void) {
    if (!memory_initialized) {
        return 0;
    }
    return heap_free_mem();
}

uint32_t mem_largest(void) {
    if (!memory_initialized) {
        return 0;
    }
    return heap_largest_block();
}

void mem_info(void) {
    memstats_t stats;
    int i;
    
    if (!memory_initialized) {
        kprintf("Memory system not initialized\n");
        return;
    }
    
    stats = mem_stats();
    
    kprintf("\n===== Memory Information =====\n");
    
    kprintf("\nHeap Memory:\n");
    kprintf("  Total:       %lu bytes (%lu KB)\n", 
            stats.heap_total, stats.heap_total / 1024);
    kprintf("  Free:        %lu bytes (%lu KB)\n", 
            stats.heap_free, stats.heap_free / 1024);
    kprintf("  Used:        %lu bytes (%lu KB)\n", 
            stats.heap_used, stats.heap_used / 1024);
    kprintf("  Free blocks: %lu\n", stats.heap_blocks);
    kprintf("  Largest:     %lu bytes\n", stats.heap_largest);
    kprintf("  Allocations: %lu\n", stats.heap_allocs);
    kprintf("  Frees:       %lu\n", stats.heap_frees);
    kprintf("  Failures:    %lu\n", stats.heap_failures);
    
    kprintf("\nStack Pool:\n");
    kprintf("  Total:       %lu bytes (%lu KB)\n", 
            stats.stack_total, stats.stack_total / 1024);
    kprintf("  Free:        %lu bytes (%lu KB)\n", 
            stats.stack_free, stats.stack_free / 1024);
    kprintf("  Used:        %lu bytes (%lu KB)\n", 
            stats.stack_used, stats.stack_used / 1024);
    
    kprintf("\nPhysical Frames:\n");
    kprintf("  Total:       %lu (%lu KB)\n", 
            stats.frames_total, stats.frames_total * 4);
    kprintf("  Free:        %lu (%lu KB)\n", 
            stats.frames_free, stats.frames_free * 4);
    kprintf("  Used:        %lu (%lu KB)\n", 
            stats.frames_used, stats.frames_used * 4);
    kprintf("  Page faults: %lu\n", stats.page_faults);
    
    if (num_regions > 0) {
        kprintf("\nMemory Regions:\n");
        for (i = 0; i < num_regions; i++) {
            const char *type_name;
            switch (memory_regions[i].type) {
                case MEM_TYPE_USABLE:  type_name = "Usable";   break;
                case MEM_TYPE_RESERVED: type_name = "Reserved"; break;
                case MEM_TYPE_KERNEL:  type_name = "Kernel";   break;
                case MEM_TYPE_HEAP:    type_name = "Heap";     break;
                case MEM_TYPE_STACK:   type_name = "Stack";    break;
                default:               type_name = "Unknown";  break;
            }
            kprintf("  [%d] 0x%08X - 0x%08X (%lu KB) %s\n",
                    i, memory_regions[i].base,
                    memory_regions[i].base + memory_regions[i].size,
                    memory_regions[i].size / 1024, type_name);
        }
    }
    
    kprintf("==============================\n\n");
}

void memcopy(void *dest, const void *src, uint32_t n) {
    char *d = (char *)dest;
    const char *s = (const char *)src;
    
    if (d == s || n == 0) {
        return;
    }
    
    if (d < s || d >= s + n) {
        /* No overlap or dest before src - copy forward */
        while (n >= 4) {
            *(uint32_t *)d = *(const uint32_t *)s;
            d += 4;
            s += 4;
            n -= 4;
        }
        while (n-- > 0) {
            *d++ = *s++;
        }
    } else {
        /* Overlap with dest after src - copy backward */
        d += n;
        s += n;
        while (n-- > 0) {
            *--d = *--s;
        }
    }
}

void memzero(void *dest, uint32_t n) {
    uint32_t *d32 = (uint32_t *)dest;
    uint8_t *d8;
    
    /* Zero 4 bytes at a time */
    while (n >= 4) {
        *d32++ = 0;
        n -= 4;
    }
    
    /* Zero remaining bytes */
    d8 = (uint8_t *)d32;
    while (n-- > 0) {
        *d8++ = 0;
    }
}

void memset_byte(void *dest, uint8_t value, uint32_t n) {
    uint32_t value32;
    uint32_t *d32;
    uint8_t *d8 = (uint8_t *)dest;
    
    /* Fill unaligned prefix */
    while (n > 0 && ((uint32_t)d8 & 3)) {
        *d8++ = value;
        n--;
    }
    
    if (n >= 4) {
        /* Create 4-byte value */
        value32 = value | (value << 8) | (value << 16) | (value << 24);
        d32 = (uint32_t *)d8;
        
        /* Fill 4 bytes at a time */
        while (n >= 4) {
            *d32++ = value32;
            n -= 4;
        }
        
        d8 = (uint8_t *)d32;
    }
    
    /* Fill remaining bytes */
    while (n-- > 0) {
        *d8++ = value;
    }
}

int memcmp(const void *s1, const void *s2, uint32_t n) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;
    
    while (n-- > 0) {
        if (*p1 != *p2) {
            return (*p1 < *p2) ? -1 : 1;
        }
        p1++;
        p2++;
    }
    
    return 0;
}

struct bufpool {
    void        *base;          /* Base of buffer memory */
    uint32_t    bufsize;        /* Size of each buffer */
    uint32_t    count;          /* Total number of buffers */
    uint32_t    avail;          /* Available buffers */
    void        **freelist;     /* Free buffer list */
    sid32       mutex;          /* Access mutex */
    sid32       items;          /* Available items semaphore */
};

bufpool_t *bufpool_create(uint32_t bufsize, uint32_t count) {
    bufpool_t *pool;
    uint32_t total_size;
    uint32_t i;
    char *buf;
    
    if (bufsize == 0 || count == 0) {
        return NULL;
    }
    
    /* Round buffer size up for alignment */
    bufsize = ROUNDUP(bufsize, MEM_ALIGN);
    
    /* Allocate pool structure */
    pool = (bufpool_t *)getmem(sizeof(bufpool_t));
    if (pool == NULL) {
        return NULL;
    }
    
    /* Allocate free list array */
    pool->freelist = (void **)getmem(count * sizeof(void *));
    if (pool->freelist == NULL) {
        freemem(pool, sizeof(bufpool_t));
        return NULL;
    }
    
    /* Allocate buffer memory */
    total_size = bufsize * count;
    pool->base = getmem(total_size);
    if (pool->base == NULL) {
        freemem(pool->freelist, count * sizeof(void *));
        freemem(pool, sizeof(bufpool_t));
        return NULL;
    }
    
    /* Create semaphores */
    pool->mutex = semcreate(1);
    pool->items = semcreate(count);
    
    if (pool->mutex == SYSERR || pool->items == SYSERR) {
        if (pool->mutex != SYSERR) semdelete(pool->mutex);
        if (pool->items != SYSERR) semdelete(pool->items);
        freemem(pool->base, total_size);
        freemem(pool->freelist, count * sizeof(void *));
        freemem(pool, sizeof(bufpool_t));
        return NULL;
    }
    
    /* Initialize */
    pool->bufsize = bufsize;
    pool->count = count;
    pool->avail = count;
    
    /* Build free list */
    buf = (char *)pool->base;
    for (i = 0; i < count; i++) {
        pool->freelist[i] = buf;
        buf += bufsize;
    }
    
    return pool;
}

void bufpool_destroy(bufpool_t *pool) {
    if (pool == NULL) {
        return;
    }
    
    semdelete(pool->mutex);
    semdelete(pool->items);
    freemem(pool->base, pool->bufsize * pool->count);
    freemem(pool->freelist, pool->count * sizeof(void *));
    freemem(pool, sizeof(bufpool_t));
}

void *bufpool_get(bufpool_t *pool) {
    void *buf;
    
    if (pool == NULL) {
        return NULL;
    }
    
    /* Wait for available buffer */
    wait(pool->items);
    
    /* Get buffer from free list */
    wait(pool->mutex);
    buf = pool->freelist[--pool->avail];
    signal(pool->mutex);
    
    return buf;
}

void bufpool_put(bufpool_t *pool, void *buf) {
    if (pool == NULL || buf == NULL) {
        return;
    }
    
    /* Add buffer to free list */
    wait(pool->mutex);
    pool->freelist[pool->avail++] = buf;
    signal(pool->mutex);
    
    /* Signal available */
    signal(pool->items);
}

uint32_t bufpool_avail(bufpool_t *pool) {
    if (pool == NULL) {
        return 0;
    }
    return pool->avail;
}
