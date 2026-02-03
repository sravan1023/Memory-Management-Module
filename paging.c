#include "paging.h"
#include "memory.h"
#include "heap.h"
#include "../include/kernel.h"
#include "../include/interrupts.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Paging State Variables */


static uint32_t frame_bitmap[MAX_FRAMES / 32];
static uint32_t total_frames = 0;
static uint32_t free_frames = 0;
static page_directory_t *kernel_directory = NULL;
static page_directory_t *current_directory = NULL;
static bool paging_enabled = false;
static paging_stats_t stats;
static page_fault_handler_t custom_fault_handler = NULL;
static bool paging_initialized = false;

/* Frame Bitmap Operations */

static inline void bitmap_set(uint32_t frame) {
    if (frame < MAX_FRAMES) {
        frame_bitmap[frame / 32] |= (1 << (frame % 32));
    }
}

static inline void bitmap_clear(uint32_t frame) {
    if (frame < MAX_FRAMES) {
        frame_bitmap[frame / 32] &= ~(1 << (frame % 32));
    }
}

static inline bool bitmap_test(uint32_t frame) {
    if (frame >= MAX_FRAMES) {
        return true;  /* Out of range = allocated */
    }
    return (frame_bitmap[frame / 32] & (1 << (frame % 32))) != 0;
}

static uint32_t bitmap_find_free(void) {
    uint32_t i, j;
    
    for (i = 0; i < MAX_FRAMES / 32; i++) {
        if (frame_bitmap[i] != 0xFFFFFFFF) {
            for (j = 0; j < 32; j++) {
                if (!(frame_bitmap[i] & (1 << j))) {
                    return i * 32 + j;
                }
            }
        }
    }
    
    return 0;  /* No free frames (0 is reserved anyway) */
}

/* Find contiguous free frames */
static uint32_t bitmap_find_range(uint32_t count) {
    uint32_t start = 1;  /* Skip frame 0 */
    uint32_t found = 0;
    uint32_t i;
    
    for (i = 1; i < total_frames; i++) {
        if (bitmap_test(i)) {
            /* Frame is allocated, reset search */
            start = i + 1;
            found = 0;
        } else {
            found++;
            if (found >= count) {
                return start;
            }
        }
    }
    
    return 0;  /* Not enough contiguous frames */
}

/* Paging Initialization */

void paging_init(void) {
    uint32_t i;
    uint32_t kernel_end;
    
    if (paging_initialized) {
        return;
    }
    
    /* Initialize frame bitmap - all free initially */
    memset(frame_bitmap, 0, sizeof(frame_bitmap));
    
    /* Calculate total frames based on available memory */
    total_frames = (MEM_MAX - MEM_MIN) / PAGE_SIZE;
    if (total_frames > MAX_FRAMES) {
        total_frames = MAX_FRAMES;
    }
    free_frames = total_frames;
    
    /* Reserve frame 0 (null pointer protection) */
    bitmap_set(0);
    free_frames--;
    
    /* Reserve frames for kernel (0 to 1MB typically) */
    uint32_t kernel_frames = MEM_MIN / PAGE_SIZE;
    for (i = 0; i < kernel_frames && i < total_frames; i++) {
        if (!bitmap_test(i)) {
            bitmap_set(i);
            free_frames--;
        }
    }
    
    /* Initialize statistics */
    memset(&stats, 0, sizeof(stats));
    stats.frames_total = total_frames;
    stats.frames_free = free_frames;
    stats.frames_used = total_frames - free_frames;
    stats.frames_kernel = kernel_frames;
    
    /* Create kernel page directory */
    kernel_directory = page_dir_create();
    if (kernel_directory == NULL) {
        /* Fatal error */
        return;
    }
    
    /* Identity map first 4MB (kernel) */
    for (i = 0; i < 1024; i++) {
        uint32_t addr = i * PAGE_SIZE;
        page_map_in(kernel_directory, addr, addr, PTE_P | PTE_W);
    }
    
    /* Map additional kernel memory if needed */
    kernel_end = MEM_MIN + (4 * 1024 * 1024);  /* 4MB of kernel space */
    for (i = MEM_MIN; i < kernel_end; i += PAGE_SIZE) {
        page_map_in(kernel_directory, i, i, PTE_P | PTE_W);
    }
    
    current_directory = kernel_directory;
    
    paging_initialized = true;
}

/* paging_enable - Enable paging */
void paging_enable(void) {
#if defined(__i386__) || defined(__x86_64__)
    if (current_directory == NULL) {
        return;
    }
    
#endif
    
    paging_enabled = true;
}

/* paging_disable - Disable paging */
void paging_disable(void) {
#if defined(__i386__) || defined(__x86_64__)

#endif
    
    paging_enabled = false;
}

/* paging_is_enabled - Check if paging is enabled */
bool paging_is_enabled(void) {
    return paging_enabled;
}

/* Frame Management */

/* frame_alloc - Allocate a physical frame */
uint32_t frame_alloc(void) {
    uint32_t frame;
    intmask mask;
    
    if (!paging_initialized) {
        return 0;
    }
    
    mask = disable();
    
    if (free_frames == 0) {
        restore(mask);
        return 0;
    }
    
    frame = bitmap_find_free();
    if (frame == 0 || frame >= total_frames) {
        restore(mask);
        return 0;
    }
    
    bitmap_set(frame);
    free_frames--;
    
    stats.frames_free = free_frames;
    stats.frames_used = total_frames - free_frames;
    
    restore(mask);
    return frame;
}

/* frame_free - Free a physical frame */
void frame_free(uint32_t frame) {
    intmask mask;
    
    if (!paging_initialized || frame == 0 || frame >= total_frames) {
        return;
    }
    
    mask = disable();
    
    if (bitmap_test(frame)) {
        bitmap_clear(frame);
        free_frames++;
        
        stats.frames_free = free_frames;
        stats.frames_used = total_frames - free_frames;
    }
    
    restore(mask);
}

/* frame_alloc_range - Allocate contiguous frames */
uint32_t frame_alloc_range(uint32_t count) {
    uint32_t start, i;
    intmask mask;
    
    if (!paging_initialized || count == 0) {
        return 0;
    }
    
    mask = disable();
    
    if (free_frames < count) {
        restore(mask);
        return 0;
    }
    
    start = bitmap_find_range(count);
    if (start == 0) {
        restore(mask);
        return 0;
    }
    
    /* Mark frames as allocated */
    for (i = 0; i < count; i++) {
        bitmap_set(start + i);
    }
    free_frames -= count;
    
    stats.frames_free = free_frames;
    stats.frames_used = total_frames - free_frames;
    
    restore(mask);
    return start;
}

/* frame_free_range - Free a range of frames */
void frame_free_range(uint32_t frame, uint32_t count) {
    uint32_t i;
    intmask mask;
    
    if (!paging_initialized || frame == 0) {
        return;
    }
    
    mask = disable();
    
    for (i = 0; i < count && frame + i < total_frames; i++) {
        if (bitmap_test(frame + i)) {
            bitmap_clear(frame + i);
            free_frames++;
        }
    }
    
    stats.frames_free = free_frames;
    stats.frames_used = total_frames - free_frames;
    
    restore(mask);
}

/* frame_is_free - Check if frame is free */
bool frame_is_free(uint32_t frame) {
    if (frame >= total_frames) {
        return false;
    }
    return !bitmap_test(frame);
}

/* frame_reserve_range - Reserve frames (mark as allocated) */
void frame_reserve_range(uint32_t start_frame, uint32_t count) {
    uint32_t i;
    intmask mask;
    
    if (!paging_initialized) {
        return;
    }
    
    mask = disable();
    
    for (i = 0; i < count && start_frame + i < total_frames; i++) {
        if (!bitmap_test(start_frame + i)) {
            bitmap_set(start_frame + i);
            free_frames--;
        }
    }
    
    stats.frames_free = free_frames;
    stats.frames_used = total_frames - free_frames;
    
    restore(mask);
}

/* frame_free_count - Get number of free frames */
uint32_t frame_free_count(void) {
    return free_frames;
}

/* frame_total_count - Get total number of frames */

uint32_t frame_total_count(void) {
    return total_frames;
}


/* Page Directory Management */

/* page_dir_create - Create a new page directory */
page_directory_t *page_dir_create(void) {
    page_directory_t *pd;
    uint32_t frame;
    uint32_t i;
    
    /* Allocate page directory structure */
    pd = (page_directory_t *)heap_alloc(sizeof(page_directory_t));
    if (pd == NULL) {
        return NULL;
    }
    
    /* Clear the directory */
    memset(pd, 0, sizeof(page_directory_t));
    
    /* Allocate frame for directory entries */
    frame = frame_alloc();
    if (frame == 0) {
        heap_free(pd);
        return NULL;
    }
    
    pd->phys_addr = FRAME_TO_ADDR(frame);
    
    /* Clear all entries */
    for (i = 0; i < PAGE_DIR_SIZE; i++) {
        pd->entries[i] = 0;
        pd->tables[i] = NULL;
    }
    
    return pd;
}

/* page_dir_clone - Clone a page directory */
page_directory_t *page_dir_clone(page_directory_t *src) {
    page_directory_t *dest;
    uint32_t i, j;
    
    if (src == NULL) {
        return NULL;
    }
    
    dest = page_dir_create();
    if (dest == NULL) {
        return NULL;
    }
    
    /* Copy/share page tables */
    for (i = 0; i < PAGE_DIR_SIZE; i++) {
        if (src->tables[i] != NULL) {
            if (i >= 768) {
                /* Kernel space - share the page table */
                dest->entries[i] = src->entries[i];
                dest->tables[i] = src->tables[i];
            } else {
                /* User space - copy the page table */
                page_table_t *new_table;
                uint32_t frame;
                
                new_table = (page_table_t *)heap_alloc(sizeof(page_table_t));
                if (new_table == NULL) {
                    page_dir_destroy(dest);
                    return NULL;
                }
                
                /* Copy entries (could implement COW here) */
                for (j = 0; j < PAGE_TABLE_SIZE; j++) {
                    new_table->entries[j] = src->tables[i]->entries[j];
                }
                
                frame = frame_alloc();
                if (frame == 0) {
                    heap_free(new_table);
                    page_dir_destroy(dest);
                    return NULL;
                }
                
                dest->tables[i] = new_table;
                dest->entries[i] = FRAME_TO_ADDR(frame) | 
                                  (src->entries[i] & PTE_FLAGS_MASK);
            }
        }
    }
    
    return dest;
}

/* page_dir_destroy - Destroy a page directory */
void page_dir_destroy(page_directory_t *pd) {
    uint32_t i;
    
    if (pd == NULL || pd == kernel_directory) {
        return;
    }
    
    /* Free user-space page tables */
    for (i = 0; i < 768; i++) {  /* Below kernel space */
        if (pd->tables[i] != NULL) {
            /* Free frames used by this table */
            uint32_t j;
            for (j = 0; j < PAGE_TABLE_SIZE; j++) {
                if (pd->tables[i]->entries[j] & PTE_P) {
                    uint32_t frame = ADDR_TO_FRAME(pd->tables[i]->entries[j] & PTE_ADDR_MASK);
                    frame_free(frame);
                }
            }
            
            heap_free(pd->tables[i]);
        }
    }
    
    /* Free directory's physical frame */
    frame_free(ADDR_TO_FRAME(pd->phys_addr));
    
    /* Free directory structure */
    heap_free(pd);
}

/* page_dir_switch - Switch to a page directory */
void page_dir_switch(page_directory_t *pd) {
    if (pd == NULL) {
        return;
    }
    
    current_directory = pd;
    
#if defined(__i386__) || defined(__x86_64__)
    /* Load CR3 with new directory address */
    /* __asm__ volatile("mov %0, %%cr3" : : "r"(pd->phys_addr) : "memory"); */
#endif
}

/* page_dir_current - Get current page directory */
page_directory_t *page_dir_current(void) {
    return current_directory;
}

/* page_dir_kernel - Get kernel page directory */

page_directory_t *page_dir_kernel(void) {
    return kernel_directory;
}

/* Page Mapping */

/* get_or_create_table - Get page table, create if needed */
static page_table_t *get_or_create_table(page_directory_t *pd, 
                                          uint32_t pd_index, 
                                          bool create) {
    page_table_t *table;
    uint32_t frame;
    
    if (pd->tables[pd_index] != NULL) {
        return pd->tables[pd_index];
    }
    
    if (!create) {
        return NULL;
    }
    
    /* Create new page table */
    table = (page_table_t *)heap_alloc(sizeof(page_table_t));
    if (table == NULL) {
        return NULL;
    }
    
    memset(table, 0, sizeof(page_table_t));
    
    /* Allocate physical frame for table */
    frame = frame_alloc();
    if (frame == 0) {
        heap_free(table);
        return NULL;
    }
    
    pd->tables[pd_index] = table;
    pd->entries[pd_index] = FRAME_TO_ADDR(frame) | PTE_P | PTE_W | PTE_U;
    
    return table;
}

/* page_map_in - Map page in specific directory */
bool page_map_in(page_directory_t *pd, uint32_t vaddr, 
                 uint32_t paddr, uint32_t flags) {
    uint32_t pd_index, pt_index;
    page_table_t *table;
    intmask mask;
    
    if (pd == NULL) {
        return false;
    }
    
    /* Align addresses */
    vaddr = PAGE_ALIGN(vaddr);
    paddr = PAGE_ALIGN(paddr);
    
    /* Get indices */
    pd_index = PD_INDEX(vaddr);
    pt_index = PT_INDEX(vaddr);
    
    mask = disable();
    
    /* Get or create page table */
    table = get_or_create_table(pd, pd_index, true);
    if (table == NULL) {
        restore(mask);
        return false;
    }
    
    /* Set page table entry */
    table->entries[pt_index] = (paddr & PTE_ADDR_MASK) | (flags & PTE_FLAGS_MASK) | PTE_P;
    
    stats.page_maps++;
    
    /* Flush TLB for this page */
    tlb_flush_page(vaddr);
    
    restore(mask);
    return true;
}

/* page_map - Map page in current directory */
bool page_map(uint32_t vaddr, uint32_t paddr, uint32_t flags) {
    return page_map_in(current_directory, vaddr, paddr, flags);
}

/* page_unmap_in - Unmap page in specific directory */
 
void page_unmap_in(page_directory_t *pd, uint32_t vaddr) {
    uint32_t pd_index, pt_index;
    page_table_t *table;
    intmask mask;
    
    if (pd == NULL) {
        return;
    }
    
    vaddr = PAGE_ALIGN(vaddr);
    pd_index = PD_INDEX(vaddr);
    pt_index = PT_INDEX(vaddr);
    
    mask = disable();
    
    table = pd->tables[pd_index];
    if (table == NULL) {
        restore(mask);
        return;
    }
    
    if (table->entries[pt_index] & PTE_P) {
        table->entries[pt_index] = 0;
        stats.page_unmaps++;
        tlb_flush_page(vaddr);
    }
    
    restore(mask);
}

/* page_unmap - Unmap page in current directory */
void page_unmap(uint32_t vaddr) {
    page_unmap_in(current_directory, vaddr);
}

/* page_map_range - Map a range of pages */
bool page_map_range(uint32_t vaddr, uint32_t paddr, 
                    uint32_t size, uint32_t flags) {
    uint32_t offset;
    
    vaddr = PAGE_ALIGN(vaddr);
    paddr = PAGE_ALIGN(paddr);
    size = PAGE_ALIGN_UP(size);
    
    for (offset = 0; offset < size; offset += PAGE_SIZE) {
        if (!page_map(vaddr + offset, paddr + offset, flags)) {
            /* Rollback on failure */
            page_unmap_range(vaddr, offset);
            return false;
        }
    }
    
    return true;
}

/* page_unmap_range - Unmap a range of pages */
void page_unmap_range(uint32_t vaddr, uint32_t size) {
    uint32_t offset;
    
    vaddr = PAGE_ALIGN(vaddr);
    size = PAGE_ALIGN_UP(size);
    
    for (offset = 0; offset < size; offset += PAGE_SIZE) {
        page_unmap(vaddr + offset);
    }
}

/* Address Translation */

/* page_translate_in - Translate address in specific directory */
uint32_t page_translate_in(page_directory_t *pd, uint32_t vaddr) {
    uint32_t pd_index, pt_index;
    page_table_t *table;
    pte_t pte;
    
    if (pd == NULL) {
        return 0;
    }
    
    pd_index = PD_INDEX(vaddr);
    pt_index = PT_INDEX(vaddr);
    
    table = pd->tables[pd_index];
    if (table == NULL) {
        return 0;
    }
    
    pte = table->entries[pt_index];
    if (!(pte & PTE_P)) {
        return 0;
    }
    
    return (pte & PTE_ADDR_MASK) | PAGE_OFFSET(vaddr);
}

/* page_translate - Translate address in current directory */
uint32_t page_translate(uint32_t vaddr) {
    return page_translate_in(current_directory, vaddr);
}

/* page_get_flags - Get page flags */
 
uint32_t page_get_flags(uint32_t vaddr) {
    uint32_t pd_index, pt_index;
    page_table_t *table;
    
    if (current_directory == NULL) {
        return 0;
    }
    
    pd_index = PD_INDEX(vaddr);
    pt_index = PT_INDEX(vaddr);
    
    table = current_directory->tables[pd_index];
    if (table == NULL) {
        return 0;
    }
    
    return table->entries[pt_index] & PTE_FLAGS_MASK;
}

/**
 * page_set_flags - Set page flags
 */
bool page_set_flags(uint32_t vaddr, uint32_t flags) {
    uint32_t pd_index, pt_index;
    page_table_t *table;
    intmask mask;
    
    if (current_directory == NULL) {
        return false;
    }
    
    pd_index = PD_INDEX(vaddr);
    pt_index = PT_INDEX(vaddr);
    
    mask = disable();
    
    table = current_directory->tables[pd_index];
    if (table == NULL || !(table->entries[pt_index] & PTE_P)) {
        restore(mask);
        return false;
    }
    
    table->entries[pt_index] = (table->entries[pt_index] & PTE_ADDR_MASK) | 
                               (flags & PTE_FLAGS_MASK);
    
    tlb_flush_page(vaddr);
    
    restore(mask);
    return true;
}

/* page_is_present - Check if page is present */
bool page_is_present(uint32_t vaddr) {
    return (page_get_flags(vaddr) & PTE_P) != 0;
}

/* page_is_writable - Check if page is writable */
bool page_is_writable(uint32_t vaddr) {
    return (page_get_flags(vaddr) & PTE_W) != 0;
}

/* page_is_user - Check if page is user-accessible */
bool page_is_user(uint32_t vaddr) {
    return (page_get_flags(vaddr) & PTE_U) != 0;
}

/* TLB Management */

/* tlb_flush - Flush entire TLB */
void tlb_flush(void) {
#if defined(__i386__) || defined(__x86_64__)
    /* Reload CR3 to flush TLB */
    /* uint32_t cr3;
     * __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
     * __asm__ volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
     */
#endif
    
    stats.tlb_flushes++;
}

/* tlb_flush_page - Flush single TLB entry */
void tlb_flush_page(uint32_t vaddr) {
#if defined(__i386__) || defined(__x86_64__)
    /* Use INVLPG instruction */
    /* __asm__ volatile("invlpg (%0)" : : "r"(vaddr) : "memory"); */
#endif
}

/* tlb_flush_range - Flush TLB entries for range */
void tlb_flush_range(uint32_t vaddr, uint32_t size) {
    uint32_t addr;
    
    vaddr = PAGE_ALIGN(vaddr);
    size = PAGE_ALIGN_UP(size);
    
    for (addr = vaddr; addr < vaddr + size; addr += PAGE_SIZE) {
        tlb_flush_page(addr);
    }
}

/* Page Fault Handling */

/* page_fault_handler - Handle page fault */
void page_fault_handler(uint32_t error_code, uint32_t fault_addr) {
    stats.page_faults++;
    
    /* Call custom handler if registered */
    if (custom_fault_handler != NULL) {
        custom_fault_handler(error_code, fault_addr);
        return;
    }
    
    /* Default handling */
    kprintf("Page fault at 0x%08X, error code: 0x%X\n", fault_addr, error_code);
    
    if (error_code & PF_PRESENT) {
        kprintf("  Protection violation\n");
    } else {
        kprintf("  Page not present\n");
    }
    
    if (error_code & PF_WRITE) {
        kprintf("  Write access\n");
    } else {
        kprintf("  Read access\n");
    }
    
    if (error_code & PF_USER) {
        kprintf("  User mode\n");
    } else {
        kprintf("  Kernel mode\n");
    }

    panic("Unhandled page fault");
}

/* page_fault_register - Register custom handler */
void page_fault_register(page_fault_handler_t handler) {
    custom_fault_handler = handler;
}

/* Page Allocation (Virtual Memory) */

/* paging_alloc_page - Allocate a page */
void *paging_alloc_page(void) {
    return paging_alloc_pages(1);
}

/* paging_alloc_pages - Allocate multiple pages */

void *paging_alloc_pages(uint32_t count) {
    uint32_t vaddr;
    uint32_t frame;
    uint32_t i;
    
    if (count == 0) {
        return NULL;
    }
    
    frame = frame_alloc_range(count);
    if (frame == 0) {
        return NULL;
    }
    
    vaddr = FRAME_TO_ADDR(frame);
    
    /* Map the pages */
    for (i = 0; i < count; i++) {
        if (!page_map(vaddr + i * PAGE_SIZE, 
                     FRAME_TO_ADDR(frame + i), 
                     PTE_P | PTE_W)) {
            /* Rollback */
            frame_free_range(frame, count);
            return NULL;
        }
    }
    
    return (void *)vaddr;
}

/* paging_free_page - Free a page */
void paging_free_page(void *page) {
    paging_free_pages(page, 1);
}

/* paging_free_pages - Free multiple pages */
void paging_free_pages(void *page, uint32_t count) {
    uint32_t vaddr = (uint32_t)page;
    uint32_t i;
    
    if (page == NULL || count == 0) {
        return;
    }
    
    for (i = 0; i < count; i++) {
        uint32_t paddr = page_translate(vaddr + i * PAGE_SIZE);
        if (paddr != 0) {
            page_unmap(vaddr + i * PAGE_SIZE);
            frame_free(ADDR_TO_FRAME(paddr));
        }
    }
}

/* Statistics and Debug */

/* paging_stats - Get paging statistics */
paging_stats_t paging_stats(void) {
    paging_stats_t result;
    intmask mask;
    
    mask = disable();
    
    result = stats;
    result.frames_total = total_frames;
    result.frames_free = free_frames;
    result.frames_used = total_frames - free_frames;
    
    restore(mask);
    
    return result;
}

/* page_dir_dump - Dump page directory */

void page_dir_dump(page_directory_t *pd) {
    uint32_t i, j;
    int count = 0;
    
    if (pd == NULL) {
        kprintf("NULL page directory\n");
        return;
    }
    
    kprintf("\n Page Directory Dump \n");
    kprintf("Physical address: 0x%08X\n", pd->phys_addr);
    
    for (i = 0; i < PAGE_DIR_SIZE && count < 20; i++) {
        if (pd->tables[i] != NULL) {
            kprintf("  PD[%3d]: 0x%08X\n", i, pd->entries[i]);
            
            /* Show first few entries of page table */
            for (j = 0; j < 4 && j < PAGE_TABLE_SIZE; j++) {
                if (pd->tables[i]->entries[j] & PTE_P) {
                    kprintf("    PT[%3d]: 0x%08X -> 0x%08X\n",
                            j, MAKE_VADDR(i, j, 0),
                            pd->tables[i]->entries[j] & PTE_ADDR_MASK);
                }
            }
            
            count++;
        }
    }
    

}

/* paging_info - Print paging information */
void paging_info(void) {
    kprintf("\n Paging Information \n");
    kprintf("Status: %s\n", paging_enabled ? "Enabled" : "Disabled");
    kprintf("Total frames:  %u (%u KB)\n", total_frames, total_frames * 4);
    kprintf("Free frames:   %u (%u KB)\n", free_frames, free_frames * 4);
    kprintf("Used frames:   %u (%u KB)\n", total_frames - free_frames,
            (total_frames - free_frames) * 4);
    kprintf("Page faults:   %u\n", stats.page_faults);
    kprintf("Page maps:     %u\n", stats.page_maps);
    kprintf("Page unmaps:   %u\n", stats.page_unmaps);
    kprintf("TLB flushes:   %u\n", stats.tlb_flushes);
}
