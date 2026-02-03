
#include "heap.h"
#include "memory.h"
#include "../include/kernel.h"
#include "../include/interrupts.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Heap boundaries */
static uint32_t     heap_base = 0;          /* Start of heap */
static uint32_t     heap_end = 0;           /* End of heap */
static uint32_t     heap_size = 0;          /* Total size */
static heapblock_t *freelist = NULL;
static heapstats_t  stats;
static bool         heap_initialized = false;

/* Round up size to alignment */
#define ALIGN_SIZE(size)    (((size) + HEAP_ALIGNMENT - 1) & ~(HEAP_ALIGNMENT - 1))

/* Minimum allocation including header */
#define MIN_ALLOC_SIZE      (sizeof(heapblock_t) + HEAP_MIN_BLOCK)

/* Get data pointer from block */
#define BLOCK_TO_PTR(block) ((void *)((char *)(block) + sizeof(heapblock_t)))

/* Get block from data pointer */
#define PTR_TO_BLOCK(ptr)   ((heapblock_t *)((char *)(ptr) - sizeof(heapblock_t)))

#define IN_HEAP(ptr)        ((uint32_t)(ptr) >= heap_base && (uint32_t)(ptr) < heap_end)

#define NEXT_PHYSICAL(block) \
    ((heapblock_t *)((char *)(block) + (block)->size))

#define IS_LAST_BLOCK(block) \
    ((uint32_t)NEXT_PHYSICAL(block) >= heap_end)


bool heap_init(uint32_t base, uint32_t size) {
    heapblock_t *first;
    
    if (base == 0 || size < MIN_ALLOC_SIZE * 2) {
        return false;
    }
    
    /* Align base address up */
    base = ALIGN_SIZE(base);
    
    /* Adjust size for alignment */
    size = size - (base - base);
    size = size & ~(HEAP_ALIGNMENT - 1);
    
    if (size < MIN_ALLOC_SIZE * 2) {
        return false;
    }
    
    /* Set heap boundaries */
    heap_base = base;
    heap_end = base + size;
    heap_size = size;
    
    /* Create initial free block spanning entire heap */
    first = (heapblock_t *)base;
    first->magic = HEAP_MAGIC_FREE;
    first->size = size;
    first->next = NULL;
    first->prev = NULL;
    first->flags = HEAP_FLAG_FREE | HEAP_FLAG_FIRST | HEAP_FLAG_LAST;
    first->pad = 0;
    
    freelist = first;
    
    /* Initialize statistics */
    memset(&stats, 0, sizeof(stats));
    stats.total_size = size;
    stats.free_size = size - sizeof(heapblock_t);
    stats.used_size = sizeof(heapblock_t);  /* Header overhead */
    stats.block_count = 1;
    stats.largest_free = size - sizeof(heapblock_t);
    stats.smallest_free = size - sizeof(heapblock_t);
    
    heap_initialized = true;
    
    return true;
}

void heap_add_to_freelist(heapblock_t *block) {
    heapblock_t *curr, *prev;
    
    if (block == NULL) {
        return;
    }
    
    block->magic = HEAP_MAGIC_FREE;
    block->flags = HEAP_FLAG_FREE;
    
    /* Empty list */
    if (freelist == NULL) {
        block->next = NULL;
        block->prev = NULL;
        freelist = block;
        return;
    }
    
    /* Find insertion point (sorted by address) */
    prev = NULL;
    curr = freelist;
    
    while (curr != NULL && curr < block) {
        prev = curr;
        curr = curr->next;
    }
    
    /* Insert block */
    block->next = curr;
    block->prev = prev;
    
    if (prev != NULL) {
        prev->next = block;
    } else {
        freelist = block;
    }
    
    if (curr != NULL) {
        curr->prev = block;
    }
    
    stats.block_count++;
}

/* heap_remove_from_freelist - Remove block from free list */
void heap_remove_from_freelist(heapblock_t *block) {
    if (block == NULL) {
        return;
    }
    
    if (block->prev != NULL) {
        block->prev->next = block->next;
    } else {
        freelist = block->next;
    }
    
    if (block->next != NULL) {
        block->next->prev = block->prev;
    }
    
    block->next = NULL;
    block->prev = NULL;
    
    if (stats.block_count > 0) {
        stats.block_count--;
    }
}

/* Block Splitting and Coalescing */

/* heap_split_block - Split a block if it's large enough */
 */
bool heap_split_block(heapblock_t *block, uint32_t size) {
    heapblock_t *new_block;
    uint32_t remaining;
    
    if (block == NULL) {
        return false;
    }
    
    /* Ensure size is aligned */
    size = ALIGN_SIZE(size + sizeof(heapblock_t));
    
    /* Check if we can split */
    remaining = block->size - size;
    if (remaining < MIN_ALLOC_SIZE) {
        return false;  /* Not enough space for new block */
    }
    
    /* Create new free block */
    new_block = (heapblock_t *)((char *)block + size);
    new_block->magic = HEAP_MAGIC_FREE;
    new_block->size = remaining;
    new_block->flags = HEAP_FLAG_FREE;
    new_block->pad = 0;
    
    /* Inherit last flag if original had it */
    if (block->flags & HEAP_FLAG_LAST) {
        new_block->flags |= HEAP_FLAG_LAST;
        block->flags &= ~HEAP_FLAG_LAST;
    }
    
    /* Update original block size */
    block->size = size;
    
    /* Add new block to free list */
    heap_add_to_freelist(new_block);
    
    stats.split_count++;
    stats.free_size += sizeof(heapblock_t);  /* Adjust for new header */
    
    return true;
}

/* heap_coalesce - Coalesce adjacent free blocks */
heapblock_t *heap_coalesce(heapblock_t *block) {
    heapblock_t *next_phys;
    
    if (block == NULL || !(block->flags & HEAP_FLAG_FREE)) {
        return block;
    }
    
    /* Try to coalesce with next physical block */
    if (!(block->flags & HEAP_FLAG_LAST)) {
        next_phys = NEXT_PHYSICAL(block);
        
        if (IN_HEAP(next_phys) && 
            next_phys->magic == HEAP_MAGIC_FREE &&
            (next_phys->flags & HEAP_FLAG_FREE)) {
            
            /* Remove next block from free list */
            heap_remove_from_freelist(next_phys);
            
            /* Merge blocks */
            block->size += next_phys->size;
            
            /* Inherit last flag */
            if (next_phys->flags & HEAP_FLAG_LAST) {
                block->flags |= HEAP_FLAG_LAST;
            }
            
            /* Clear merged block (optional, for debugging) */
            next_phys->magic = 0;
            
            stats.coalesce_count++;
        }
    }
    
    /* Try to coalesce with previous block (through free list) */
    if (block->prev != NULL) {
        heapblock_t *prev = block->prev;
        heapblock_t *prev_next_phys = NEXT_PHYSICAL(prev);
        
        if (prev_next_phys == block) {
            /* Previous free block is physically adjacent */
            heap_remove_from_freelist(block);
            
            prev->size += block->size;
            
            if (block->flags & HEAP_FLAG_LAST) {
                prev->flags |= HEAP_FLAG_LAST;
            }
            
            block->magic = 0;
            block = prev;
            
            stats.coalesce_count++;
        }
    }
    
    return block;
}

/* Block Finding */

/* heap_find_block - Find a free block of given size (first-fit) */
 */
heapblock_t *heap_find_block(uint32_t size) {
    heapblock_t *curr;
    uint32_t needed;
    
    /* Calculate total size needed */
    needed = ALIGN_SIZE(size + sizeof(heapblock_t));
    if (needed < MIN_ALLOC_SIZE) {
        needed = MIN_ALLOC_SIZE;
    }
    
    /* First-fit search */
    curr = freelist;
    while (curr != NULL) {
        if (curr->size >= needed) {
            return curr;
        }
        curr = curr->next;
    }
    
    return NULL;  /* No suitable block found */
}

/* Memory Allocation */

/* heap_alloc - Allocate memory from heap */
void *heap_alloc(uint32_t size) {
    heapblock_t *block;
    uint32_t needed;
    intmask mask;
    
    if (!heap_initialized || size == 0) {
        stats.alloc_failures++;
        return NULL;
    }
    
    /* Calculate needed size */
    needed = ALIGN_SIZE(size + sizeof(heapblock_t));
    if (needed < MIN_ALLOC_SIZE) {
        needed = MIN_ALLOC_SIZE;
    }
    
    mask = disable();
    
    /* Find suitable block */
    block = heap_find_block(size);
    if (block == NULL) {
        stats.alloc_failures++;
        restore(mask);
        return NULL;
    }
    
    /* Remove from free list */
    heap_remove_from_freelist(block);
    
    /* Split if block is significantly larger */
    if (block->size >= needed + MIN_ALLOC_SIZE) {
        heap_split_block(block, needed);
    }
    
    /* Mark as allocated */
    block->magic = HEAP_MAGIC_ALLOC;
    block->flags = HEAP_FLAG_ALLOC;
    
    /* Update statistics */
    stats.free_size -= block->size;
    stats.used_size += block->size;
    stats.total_allocs++;
    
    restore(mask);
    
    return BLOCK_TO_PTR(block);
}

/* heap_alloc_aligned - Allocate aligned memory */
void *heap_alloc_aligned(uint32_t size, uint32_t align) {
    void *ptr;
    void *aligned;
    uint32_t extra;
    intmask mask;
    
    if (!heap_initialized || size == 0) {
        return NULL;
    }
    
    /* Alignment must be power of 2 */
    if (align == 0 || (align & (align - 1)) != 0) {
        return NULL;
    }
    
    /* If alignment is <= heap alignment, use regular alloc */
    if (align <= HEAP_ALIGNMENT) {
        return heap_alloc(size);
    }
    
    mask = disable();
    
    /* Allocate extra space for alignment and original pointer storage */
    extra = align + sizeof(void *);
    ptr = heap_alloc(size + extra);
    
    if (ptr == NULL) {
        restore(mask);
        return NULL;
    }
    
    /* Align the pointer */
    aligned = (void *)(((uint32_t)ptr + sizeof(void *) + align - 1) & ~(align - 1));
    
    /* Store original pointer before aligned address */
    *((void **)aligned - 1) = ptr;
    
    restore(mask);
    return aligned;
}

/* heap_calloc - Allocate and zero memory */
void *heap_calloc(uint32_t size) {
    void *ptr;
    
    ptr = heap_alloc(size);
    if (ptr != NULL) {
        memset(ptr, 0, size);
    }
    
    return ptr;
}

/* Memory Deallocation */

/* heap_free - Free heap memory */
void heap_free(void *ptr) {
    heapblock_t *block;
    intmask mask;
    
    if (!heap_initialized || ptr == NULL) {
        return;
    }
    
    /* Check if pointer is in heap */
    if (!IN_HEAP(ptr)) {
        return;
    }
    
    mask = disable();
    
    /* Get block header */
    block = PTR_TO_BLOCK(ptr);
    
    /* Validate block */
    if (block->magic != HEAP_MAGIC_ALLOC) {
        /* Invalid or double-free */
        restore(mask);
        return;
    }
    
    /* Mark as free */
    block->magic = HEAP_MAGIC_FREE;
    block->flags = HEAP_FLAG_FREE;
    
    /* Update statistics */
    stats.free_size += block->size;
    stats.used_size -= block->size;
    stats.total_frees++;
    
    /* Add to free list */
    heap_add_to_freelist(block);
    
    /* Coalesce with neighbors */
    heap_coalesce(block);
    
    restore(mask);
}

/* heap_free_sized - Free heap memory with size validation */
void heap_free_sized(void *ptr, uint32_t size) {
    heapblock_t *block;
    
    if (!heap_initialized || ptr == NULL) {
        return;
    }
    
    block = PTR_TO_BLOCK(ptr);
    
    /* Validate size (optional - just for debugging) */
    if (block->magic == HEAP_MAGIC_ALLOC) {
        uint32_t actual_size = block->size - sizeof(heapblock_t);
        if (actual_size < size) {
            /* Size mismatch - possible corruption */
        }
    }
    
    heap_free(ptr);
}

/**
 * heap_realloc - Resize allocated memory
 */
void *heap_realloc(void *ptr, uint32_t oldsize, uint32_t newsize) {
    heapblock_t *block;
    void *newptr;
    uint32_t copysize;
    
    /* Handle NULL pointer (like malloc) */
    if (ptr == NULL) {
        return heap_alloc(newsize);
    }
    
    /* Handle zero size (like free) */
    if (newsize == 0) {
        heap_free(ptr);
        return NULL;
    }
    
    if (!IN_HEAP(ptr)) {
        return NULL;
    }
    
    block = PTR_TO_BLOCK(ptr);
    
    /* Validate block */
    if (block->magic != HEAP_MAGIC_ALLOC) {
        return NULL;
    }
    
    /* Check if current block is large enough */
    uint32_t current_size = block->size - sizeof(heapblock_t);
    if (current_size >= newsize) {
        /* Existing block is sufficient */
        return ptr;
    }
    
    /* Need to allocate new block */
    newptr = heap_alloc(newsize);
    if (newptr == NULL) {
        return NULL;
    }
    
    /* Copy data */
    copysize = (oldsize < current_size) ? oldsize : current_size;
    if (copysize > newsize) {
        copysize = newsize;
    }
    memcpy(newptr, ptr, copysize);
    
    /* Free old block */
    heap_free(ptr);
    
    return newptr;
}

/* Heap Information */

uint32_t heap_total(void) {
    return heap_size;
}

uint32_t heap_free_mem(void) {
    return stats.free_size;
}

/**
 * heap_used_mem - Get used heap memory
 */
uint32_t heap_used_mem(void) {
    return stats.used_size;
}

/**
 * heap_largest_block - Get largest free block
 */
uint32_t heap_largest_block(void) {
    heapblock_t *curr;
    uint32_t largest = 0;
    intmask mask;
    
    if (!heap_initialized) {
        return 0;
    }
    
    mask = disable();
    
    curr = freelist;
    while (curr != NULL) {
        if (curr->size > largest) {
            largest = curr->size;
        }
        curr = curr->next;
    }
    
    restore(mask);
    
    /* Return usable size (minus header) */
    if (largest > sizeof(heapblock_t)) {
        return largest - sizeof(heapblock_t);
    }
    return 0;
}

/**
 * heap_block_count - Get number of free blocks
 */
int32_t heap_block_count(void) {
    return stats.block_count;
}

/**
 * heap_stats - Get heap statistics
 */
heapstats_t heap_stats(void) {
    heapstats_t result;
    intmask mask;
    
    mask = disable();
    
    result = stats;
    result.largest_free = heap_largest_block();
    
    /* Calculate smallest free block */
    heapblock_t *curr = freelist;
    result.smallest_free = 0xFFFFFFFF;
    while (curr != NULL) {
        if (curr->size < result.smallest_free) {
            result.smallest_free = curr->size;
        }
        curr = curr->next;
    }
    if (result.smallest_free == 0xFFFFFFFF) {
        result.smallest_free = 0;
    } else if (result.smallest_free > sizeof(heapblock_t)) {
        result.smallest_free -= sizeof(heapblock_t);
    }
    
    restore(mask);
    
    return result;
}

/* heap_validate - Validate heap integrity */
bool heap_validate(void) {
    heapblock_t *curr, *prev;
    intmask mask;
    bool valid = true;
    
    if (!heap_initialized) {
        return false;
    }
    
    mask = disable();
    
    /* Check free list integrity */
    prev = NULL;
    curr = freelist;
    
    while (curr != NULL) {
        /* Check address is in heap */
        if (!IN_HEAP(curr)) {
            valid = false;
            break;
        }
        
        /* Check magic number */
        if (curr->magic != HEAP_MAGIC_FREE) {
            valid = false;
            break;
        }
        
        /* Check flags */
        if (!(curr->flags & HEAP_FLAG_FREE)) {
            valid = false;
            break;
        }
        
        /* Check ordering (ascending by address) */
        if (prev != NULL && curr <= prev) {
            valid = false;
            break;
        }
        
        /* Check for overlap */
        if (prev != NULL) {
            if ((char *)prev + prev->size > (char *)curr) {
                valid = false;
                break;
            }
        }
        
        /* Check size sanity */
        if (curr->size < sizeof(heapblock_t) || 
            (uint32_t)curr + curr->size > heap_end) {
            valid = false;
            break;
        }
        
        /* Check back pointer */
        if (curr->prev != prev) {
            valid = false;
            break;
        }
        
        prev = curr;
        curr = curr->next;
    }
    
    restore(mask);
    return valid;
}

/* heap_dump - Dump heap for debugging */
void heap_dump(void) {
    heapblock_t *curr;
    int count = 0;
    intmask mask;
    
    if (!heap_initialized) {
        kprintf("Heap not initialized\n");
        return;
    }
    
    mask = disable();
    
    kprintf("\n Heap Dump n");
    kprintf("Base: 0x%08X  End: 0x%08X  Size: %u bytes\n",
            heap_base, heap_end, heap_size);
    kprintf("Free: %u bytes  Used: %u bytes\n",
            stats.free_size, stats.used_size);
    kprintf("Allocations: %u  Frees: %u  Failures: %u\n",
            stats.total_allocs, stats.total_frees, stats.alloc_failures);
    kprintf("Splits: %u  Coalesces: %u\n",
            stats.split_count, stats.coalesce_count);
    
    kprintf("\nFree List:\n");
    curr = freelist;
    while (curr != NULL && count < 100) {
        kprintf("  [%2d] 0x%08X: size=%u magic=0x%08X flags=0x%02X\n",
                count, (uint32_t)curr, curr->size, curr->magic, curr->flags);
        curr = curr->next;
        count++;
    }
    
    if (curr != NULL) {
        kprintf("  ... (more blocks)\n");
    }
    
    restore(mask);
}

/* heap_compact - Compact the heap */
int32_t heap_compact(void) {
    heapblock_t *curr;
    int32_t coalesced = 0;
    intmask mask;
    
    if (!heap_initialized) {
        return 0;
    }
    
    mask = disable();
    
    curr = freelist;
    while (curr != NULL) {
        heapblock_t *next = curr->next;
        heapblock_t *result = heap_coalesce(curr);
        
        if (result != curr) {
            coalesced++;
        }
        
        curr = (result->next != next) ? result->next : next;
    }
    
    restore(mask);
    return coalesced;
}
