#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Memory region boundaries*/
#ifndef MEM_MIN
#define MEM_MIN         0x00100000      /* 1MB - start of usable memory */
#endif

#ifndef MEM_MAX
#define MEM_MAX         0x00800000      /* 8MB - end of usable memory */
#endif

/* Page and frame sizes */
#define PAGE_SIZE       4096            /* 4KB pages */
#define PAGE_SHIFT      12              /* log2(PAGE_SIZE) */
#define PAGE_MASK       (PAGE_SIZE - 1) /* Mask for page offset */

/* Memory alignment */
#define MEM_ALIGN       8               /* Default alignment */
#define MEM_ALIGN_MASK  (MEM_ALIGN - 1)

/* Pool sizes */
#define HEAP_SIZE       (2 * 1024 * 1024)   /* 2MB default heap */
#define STACK_POOL_SIZE (512 * 1024)        /* 512KB stack pool */

/* Frame allocation */
#define MAX_FRAMES      4096            /* Maximum physical frames */
#define FRAME_SIZE      PAGE_SIZE       /* Frame = physical page */

/* Virtual memory */
#define KERNEL_VBASE    0xC0000000      /* Kernel virtual base (3GB) */
#define USER_VBASE      0x00400000      /* User virtual base (4MB) */
#define USER_STACK_TOP  0xBFFFFFFF      /* Top of user stack */

/* Round up to alignment boundary */
#define ROUNDUP(x, align)   (((x) + (align) - 1) & ~((align) - 1))
#define ROUNDDOWN(x, align) ((x) & ~((align) - 1))

/* Page alignment */
#define PAGE_ROUNDUP(x)     ROUNDUP(x, PAGE_SIZE)
#define PAGE_ROUNDDOWN(x)   ROUNDDOWN(x, PAGE_SIZE)

/* Check alignment */
#define IS_ALIGNED(x, align)    (((x) & ((align) - 1)) == 0)
#define IS_PAGE_ALIGNED(x)      IS_ALIGNED(x, PAGE_SIZE)

typedef struct memblock {
    struct memblock *next;      /* Next block in free list */
    uint32_t        size;       /* Size of this block (including header) */
    uint32_t        magic;      /* Magic number for validation */
    uint8_t         flags;      /* Block flags */
} memblock_t;

/* Memory block flags */
#define MEM_FREE        0x00    /* Block is free */
#define MEM_ALLOC       0x01    /* Block is allocated */
#define MEM_STACK       0x02    /* Block is stack memory */
#define MEM_PAGE        0x04    /* Block is page-aligned */
#define MEM_DMA         0x08    /* Block is DMA-safe */

/* Magic number for validation */
#define MEM_MAGIC       0xDEADBEEF
#define MEM_FREE_MAGIC  0xFEEDFACE

typedef struct memstats {
    /* Heap statistics */
    uint32_t heap_total;        /* Total heap size */
    uint32_t heap_free;         /* Free heap memory */
    uint32_t heap_used;         /* Used heap memory */
    uint32_t heap_blocks;       /* Number of free blocks */
    uint32_t heap_largest;      /* Largest free block */
    uint32_t heap_allocs;       /* Total allocations */
    uint32_t heap_frees;        /* Total frees */
    uint32_t heap_failures;     /* Allocation failures */
    
    /* Stack pool statistics */
    uint32_t stack_total;       /* Total stack pool size */
    uint32_t stack_free;        /* Free stack memory */
    uint32_t stack_used;        /* Used stack memory */
    
    /* Page statistics */
    uint32_t pages_total;       /* Total pages */
    uint32_t pages_free;        /* Free pages */
    uint32_t pages_used;        /* Used pages */
    uint32_t page_faults;       /* Page fault count */
    
    /* Frame statistics */
    uint32_t frames_total;      /* Total physical frames */
    uint32_t frames_free;       /* Free frames */
    uint32_t frames_used;       /* Used frames */
} memstats_t;

typedef struct memregion {
    uint32_t base;              /* Base address */
    uint32_t size;              /* Size in bytes */
    uint32_t type;              /* Region type */
    uint32_t flags;             /* Region flags */
} memregion_t;

/* Memory region types */
#define MEM_TYPE_USABLE     1   /* Usable RAM */
#define MEM_TYPE_RESERVED   2   /* Reserved (BIOS, etc.) */
#define MEM_TYPE_ACPI       3   /* ACPI tables */
#define MEM_TYPE_NVS        4   /* ACPI Non-Volatile Storage */
#define MEM_TYPE_BAD        5   /* Bad memory */
#define MEM_TYPE_KERNEL     6   /* Kernel code/data */
#define MEM_TYPE_HEAP       7   /* Kernel heap */
#define MEM_TYPE_STACK      8   /* Stack pool */
#define MEM_TYPE_DMA        9   /* DMA buffer area */

#define PTE_PRESENT     0x001   /* Page is present in memory */
#define PTE_WRITABLE    0x002   /* Page is writable */
#define PTE_USER        0x004   /* Page is accessible from user mode */
#define PTE_PWT         0x008   /* Write-through caching */
#define PTE_PCD         0x010   /* Cache disabled */
#define PTE_ACCESSED    0x020   /* Page has been accessed */
#define PTE_DIRTY       0x040   /* Page has been written */
#define PTE_LARGE       0x080   /* Large page (4MB) */
#define PTE_GLOBAL      0x100   /* Global page  */

void        mem_init(void);
void        mem_init_region(uint32_t base, uint32_t size);

void       *getmem(uint32_t nbytes);
syscall     freemem(void *block, uint32_t nbytes);
void       *getmem_aligned(uint32_t nbytes, uint32_t align);
void       *realloc(void *ptr, uint32_t oldsize, uint32_t newsize);
void       *calloc(uint32_t count, uint32_t size);

void       *getstk(uint32_t nbytes);
syscall     freestk(void *stktop, uint32_t nbytes);

void       *alloc_page(void);
void       *alloc_pages(uint32_t count);
void        free_page(void *page);
void        free_pages(void *page, uint32_t count);

memstats_t  mem_stats(void);
uint32_t    mem_avail(void);
uint32_t    mem_largest(void);
void        mem_info(void);

void        memcopy(void *dest, const void *src, uint32_t n);
void        memzero(void *dest, uint32_t n);
void        memset_byte(void *dest, uint8_t value, uint32_t n);
int         memcmp(const void *s1, const void *s2, uint32_t n);

void        heap_init(uint32_t base, uint32_t size);
void       *heap_alloc(uint32_t size);
void       *heap_alloc_aligned(uint32_t size, uint32_t align);
void        heap_free(void *ptr);
void        heap_free_sized(void *ptr, uint32_t size);
uint32_t    heap_free_mem(void);
uint32_t    heap_total_mem(void);
uint32_t    heap_largest_block(void);
int32_t     heap_block_count(void);
memstats_t  heap_stats(void);
bool        heap_validate(void);
void        heap_dump(void);

void        paging_init(void);
void        paging_enable(void);
void        paging_disable(void);

uint32_t    frame_alloc(void);
void        frame_free(uint32_t frame);
uint32_t    frame_alloc_range(uint32_t count);
void        frame_free_range(uint32_t frame, uint32_t count);
bool        frame_is_free(uint32_t frame);

bool        page_map(uint32_t vaddr, uint32_t paddr, uint32_t flags);
void        page_unmap(uint32_t vaddr);
uint32_t    page_translate(uint32_t vaddr);
uint32_t    page_get_flags(uint32_t vaddr);
bool        page_set_flags(uint32_t vaddr, uint32_t flags);

uint32_t   *page_dir_create(void);
void        page_dir_destroy(uint32_t *pd);
void        page_dir_switch(uint32_t *pd);
uint32_t   *page_dir_current(void);

void        tlb_flush(void);
void        tlb_flush_page(uint32_t vaddr);

void        page_fault_handler(uint32_t error_code, uint32_t fault_addr);

void        vmem_init(void);
void       *vmem_alloc(uint32_t size);
void        vmem_free(void *addr, uint32_t size);
bool        vmem_map(uint32_t vaddr, uint32_t paddr, uint32_t size, uint32_t flags);
void        vmem_unmap(uint32_t vaddr, uint32_t size);
uint32_t    vmem_find_free(uint32_t size);

typedef struct bufpool bufpool_t;

bufpool_t  *bufpool_create(uint32_t bufsize, uint32_t count);
void        bufpool_destroy(bufpool_t *pool);
void       *bufpool_get(bufpool_t *pool);
void        bufpool_put(bufpool_t *pool, void *buf);
uint32_t    bufpool_avail(bufpool_t *pool);

static inline uint32_t addr_to_page(uint32_t addr) {
    return addr >> PAGE_SHIFT;
}

static inline uint32_t page_to_addr(uint32_t page) {
    return page << PAGE_SHIFT;
}

static inline uint32_t page_offset(uint32_t addr) {
    return addr & PAGE_MASK;
}

static inline bool is_kernel_addr(uint32_t addr) {
    return addr >= KERNEL_VBASE;
}

static inline bool is_user_addr(uint32_t addr) {
    return addr >= USER_VBASE && addr < KERNEL_VBASE;
}

#endif
