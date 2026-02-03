#ifndef _PAGING_H_
#define _PAGING_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Page and frame sizes */
#ifndef PAGE_SIZE
#define PAGE_SIZE           4096        /* 4KB pages */
#endif

#define PAGE_SHIFT          12          /* PAGE_SIZE */
#define PAGE_MASK           (PAGE_SIZE - 1)

#define ENTRIES_PER_TABLE   1024        /* Entries per page table */
#define PAGE_DIR_SIZE       1024        /* Page directory entries */
#define PAGE_TABLE_SIZE     1024        /* Page table entries */
#ifndef MAX_FRAMES
#define MAX_FRAMES          16384       /* Maximum physical frames (64MB) */
#endif

#define FRAME_SIZE          PAGE_SIZE
#define FRAME_SHIFT         PAGE_SHIFT

#define PTE_P               0x001       /* Present */
#define PTE_W               0x002       /* Writable */
#define PTE_U               0x004       /* User accessible */
#define PTE_PWT             0x008       /* Write-through */
#define PTE_PCD             0x010       /* Cache disable */
#define PTE_A               0x020       /* Accessed */
#define PTE_D               0x040       /* Dirty */
#define PTE_PS              0x080       /* Page size */
#define PTE_G               0x100       /* Global */

/* Custom flags (in available bits) */
#define PTE_COW             0x200       /* Copy-on-write */
#define PTE_SHARED          0x400       /* Shared page */
#define PTE_LOCKED          0x800       /* Page is locked in memory */

/* Address extraction masks */
#define PTE_ADDR_MASK       0xFFFFF000  /* Physical address mask */
#define PTE_FLAGS_MASK      0x00000FFF  /* Flags mask */

/* Macros to get indices from virtual address */
#define PD_INDEX(addr)      (((uint32_t)(addr) >> 22) & 0x3FF)
#define PT_INDEX(addr)      (((uint32_t)(addr) >> 12) & 0x3FF)
#define PAGE_OFFSET(addr)   ((uint32_t)(addr) & 0xFFF)
#define MAKE_VADDR(pd, pt, off) \((((pd) & 0x3FF) << 22) | (((pt) & 0x3FF) << 12) | ((off) & 0xFFF))
#define FRAME_TO_ADDR(frame)    ((frame) << FRAME_SHIFT)
#define ADDR_TO_FRAME(addr)     ((addr) >> FRAME_SHIFT)
#define PAGE_ALIGN(addr)        ((addr) & ~PAGE_MASK)
#define PAGE_ALIGN_UP(addr)     (((addr) + PAGE_MASK) & ~PAGE_MASK)

typedef uint32_t pde_t;     /* Page directory entry */

/* Page directory entry macros */
#define PDE_PRESENT(pde)    ((pde) & PTE_P)
#define PDE_ADDRESS(pde)    ((pde) & PTE_ADDR_MASK)
#define PDE_FLAGS(pde)      ((pde) & PTE_FLAGS_MASK)

typedef uint32_t pte_t;     /* Page table entry */

/* Page table entry macros */
#define PTE_PRESENT(pte)    ((pte) & PTE_P)
#define PTE_ADDRESS(pte)    ((pte) & PTE_ADDR_MASK)
#define PTE_FLAGS(pte)      ((pte) & PTE_FLAGS_MASK)

typedef struct page_table {
    pte_t entries[PAGE_TABLE_SIZE];
} page_table_t;

typedef struct page_directory {
    pde_t entries[PAGE_DIR_SIZE];
    page_table_t *tables[PAGE_DIR_SIZE];
    uint32_t phys_addr;
} page_directory_t;

#define PF_PRESENT      0x01    /* Page was present */
#define PF_WRITE        0x02    /* Fault was write access */
#define PF_USER         0x04    /* Fault from user mode */
#define PF_RESERVED     0x08    /* Reserved bit was set */
#define PF_FETCH        0x10    /* Instruction fetch */

typedef void (*page_fault_handler_t)(uint32_t error_code, uint32_t fault_addr);

typedef struct paging_stats {
    uint32_t frames_total;      /* Total physical frames */
    uint32_t frames_free;       /* Free frames */
    uint32_t frames_used;       /* Used frames */
    uint32_t frames_kernel;     /* Kernel frames */
    uint32_t frames_user;       /* User frames */
    uint32_t page_faults;       /* Total page faults */
    uint32_t page_maps;         /* Page mapping operations */
    uint32_t page_unmaps;       /* Page unmapping operations */
    uint32_t tlb_flushes;       /* TLB flush operations */
} paging_stats_t;

void paging_init(void);
void paging_enable(void);
void paging_disable(void);
bool paging_is_enabled(void);

uint32_t frame_alloc(void);
void frame_free(uint32_t frame);
uint32_t frame_alloc_range(uint32_t count);
void frame_free_range(uint32_t frame, uint32_t count);
bool frame_is_free(uint32_t frame);
void frame_reserve_range(uint32_t start_frame, uint32_t count);
uint32_t frame_free_count(void);
uint32_t frame_total_count(void);

page_directory_t *page_dir_create(void);
page_directory_t *page_dir_clone(page_directory_t *src);
void page_dir_destroy(page_directory_t *pd);
void page_dir_switch(page_directory_t *pd);
page_directory_t *page_dir_current(void);
page_directory_t *page_dir_kernel(void);

bool page_map(uint32_t vaddr, uint32_t paddr, uint32_t flags);
bool page_map_in(page_directory_t *pd, uint32_t vaddr, uint32_t paddr, uint32_t flags);
void page_unmap(uint32_t vaddr);
void page_unmap_in(page_directory_t *pd, uint32_t vaddr);
bool page_map_range(uint32_t vaddr, uint32_t paddr, uint32_t size, uint32_t flags);
void page_unmap_range(uint32_t vaddr, uint32_t size);

uint32_t page_translate(uint32_t vaddr);
uint32_t page_translate_in(page_directory_t *pd, uint32_t vaddr);
uint32_t page_get_flags(uint32_t vaddr);
bool page_set_flags(uint32_t vaddr, uint32_t flags);
bool page_is_present(uint32_t vaddr);
bool page_is_writable(uint32_t vaddr);
bool page_is_user(uint32_t vaddr);

void tlb_flush(void);
void tlb_flush_page(uint32_t vaddr);
void tlb_flush_range(uint32_t vaddr, uint32_t size);

void page_fault_handler(uint32_t error_code, uint32_t fault_addr);
void page_fault_register(page_fault_handler_t handler);

void *paging_alloc_page(void);
void *paging_alloc_pages(uint32_t count);
void paging_free_page(void *page);
void paging_free_pages(void *page, uint32_t count);

paging_stats_t paging_stats(void);
void page_dir_dump(page_directory_t *pd);
void paging_info(void);

#endif 

