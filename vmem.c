
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../include/kernel.h"
#include "../include/process.h"
#include "vmem.h"
#include "paging.h"
#include "memory.h"

static vmspace_t kernel_vmspace;
static vmspace_t kernel_vmspace;

/* Current address space */
static vmspace_t *current_vmspace = NULL;

/* Free region pool */
static vmregion_t region_pool[MAX_VM_REGIONS * NPROC];
static vmregion_t *free_regions = NULL;
static uint32_t total_regions = 0;

/* Virtual memory statistics */
static uint32_t total_vmspaces = 0;
static uint32_t total_mapped = 0;
static uint32_t total_unmapped = 0;

/* Lock for global VM structures */
static sid32 vmem_lock;

static vmregion_t *region_alloc(void);
static void region_free(vmregion_t *region);
static void region_insert(vmspace_t *vm, vmregion_t *region);
static void region_remove(vmspace_t *vm, vmregion_t *region);
static vmregion_t *region_split(vmregion_t *region, uint32_t addr);
static bool regions_merge(vmspace_t *vm, vmregion_t *r1, vmregion_t *r2);
static uint32_t flags_to_pte(uint32_t flags);
static bool map_pages(vmspace_t *vm, uint32_t start, uint32_t end, uint32_t flags);
static void unmap_pages(vmspace_t *vm, uint32_t start, uint32_t end);

void vmem_init(void) {
    int i;
    intmask mask;
    
    mask = disable();
    
    /* Initialize region free pool */
    free_regions = NULL;
    for (i = MAX_VM_REGIONS * NPROC - 1; i >= 0; i--) {
        region_pool[i].next = free_regions;
        free_regions = &region_pool[i];
    }
    total_regions = MAX_VM_REGIONS * NPROC;
    
    /* Initialize kernel address space */
    kernel_vmspace.pdir = page_dir_create();
    kernel_vmspace.regions = NULL;
    kernel_vmspace.region_count = 0;
    kernel_vmspace.brk = 0;
    kernel_vmspace.stack_start = 0;
    kernel_vmspace.stack_end = 0;
    kernel_vmspace.code_start = VMEM_KERNEL_START;
    kernel_vmspace.code_end = VMEM_KERNEL_START;
    kernel_vmspace.data_start = 0;
    kernel_vmspace.data_end = 0;
    kernel_vmspace.total_vm = 0;
    kernel_vmspace.total_rss = 0;
    kernel_vmspace.lock = semcreate(1);
    
    /* Map kernel space (identity map for now) */
    vmem_map(&kernel_vmspace, VMEM_KERNEL_START, 
             VMEM_KERNEL_END - VMEM_KERNEL_START,
             VMR_TYPE_CODE, VMR_RWX);
    
    current_vmspace = &kernel_vmspace;
    
    /* Create global lock */
    vmem_lock = semcreate(1);
    
    restore(mask);
    
    kprintf("Virtual memory manager initialized\n");
}

static vmregion_t *region_alloc(void) {
    vmregion_t *region;
    intmask mask;
    
    mask = disable();
    
    if (free_regions == NULL) {
        restore(mask);
        return NULL;
    }
    
    region = free_regions;
    free_regions = free_regions->next;
    
    /* Initialize region */
    region->start = 0;
    region->end = 0;
    region->type = VMR_TYPE_FREE;
    region->flags = 0;
    region->file_offset = 0;
    region->private_data = NULL;
    region->next = NULL;
    region->prev = NULL;
    
    restore(mask);
    
    return region;
}

static void region_free(vmregion_t *region) {
    intmask mask;
    
    if (region == NULL) {
        return;
    }
    
    mask = disable();
    
    region->next = free_regions;
    free_regions = region;
    
    restore(mask);
}

static void region_insert(vmspace_t *vm, vmregion_t *region) {
    vmregion_t *curr, *prev;
    
    if (vm == NULL || region == NULL) {
        return;
    }
    
    /* Find insertion point */
    prev = NULL;
    curr = vm->regions;
    
    while (curr != NULL && curr->start < region->start) {
        prev = curr;
        curr = curr->next;
    }
    
    /* Insert into list */
    region->prev = prev;
    region->next = curr;
    
    if (prev != NULL) {
        prev->next = region;
    } else {
        vm->regions = region;
    }
    
    if (curr != NULL) {
        curr->prev = region;
    }
    
    vm->region_count++;
}

static void region_remove(vmspace_t *vm, vmregion_t *region) {
    if (vm == NULL || region == NULL) {
        return;
    }
    
    if (region->prev != NULL) {
        region->prev->next = region->next;
    } else {
        vm->regions = region->next;
    }
    
    if (region->next != NULL) {
        region->next->prev = region->prev;
    }
    
    vm->region_count--;
}

static vmregion_t *region_split(vmregion_t *region, uint32_t addr) {
    vmregion_t *new_region;
    
    if (region == NULL || addr <= region->start || addr >= region->end) {
        return NULL;
    }
    
    new_region = region_alloc();
    if (new_region == NULL) {
        return NULL;
    }
    
    /* Setup new region (upper half) */
    new_region->start = addr;
    new_region->end = region->end;
    new_region->type = region->type;
    new_region->flags = region->flags;
    new_region->file_offset = region->file_offset + (addr - region->start);
    new_region->private_data = region->private_data;
    
    /* Adjust original region (lower half) */
    region->end = addr;
    
    /* Link new region after original */
    new_region->next = region->next;
    new_region->prev = region;
    
    if (region->next != NULL) {
        region->next->prev = new_region;
    }
    region->next = new_region;
    
    return new_region;
}

static bool regions_merge(vmspace_t *vm, vmregion_t *r1, vmregion_t *r2) {
    if (r1 == NULL || r2 == NULL) {
        return false;
    }
    
    /* Check if mergeable */
    if (r1->end != r2->start) {
        return false;
    }
    
    if (r1->type != r2->type || r1->flags != r2->flags) {
        return false;
    }
    
    /* Merge r2 into r1 */
    r1->end = r2->end;
    
    /* Remove r2 from list */
    r1->next = r2->next;
    if (r2->next != NULL) {
        r2->next->prev = r1;
    }
    
    vm->region_count--;
    region_free(r2);
    
    return true;
}

vmspace_t *vmspace_create(void) {
    vmspace_t *vm;
    intmask mask;
    
    mask = disable();
    
    /* Allocate vmspace structure */
    vm = (vmspace_t *)getmem(sizeof(vmspace_t));
    if (vm == (vmspace_t *)SYSERR) {
        restore(mask);
        return NULL;
    }
    
    /* Create page directory */
    vm->pdir = page_dir_create();
    if (vm->pdir == NULL) {
        freemem((char *)vm, sizeof(vmspace_t));
        restore(mask);
        return NULL;
    }
    
    /* Initialize fields */
    vm->regions = NULL;
    vm->region_count = 0;
    vm->brk = VMEM_USER_HEAP;
    vm->stack_start = VMEM_USER_STACK - VMEM_STACK_SIZE;
    vm->stack_end = VMEM_USER_STACK;
    vm->code_start = VMEM_USER_START;
    vm->code_end = VMEM_USER_START;
    vm->data_start = 0;
    vm->data_end = 0;
    vm->total_vm = 0;
    vm->total_rss = 0;
    vm->lock = semcreate(1);
    
    /* Copy kernel mappings */
    /* In a real system, we'd share kernel page tables */
    
    total_vmspaces++;
    
    restore(mask);
    
    return vm;
}

vmspace_t *vmspace_clone(vmspace_t *src) {
    vmspace_t *dst;
    vmregion_t *src_region, *dst_region;
    intmask mask;
    
    if (src == NULL) {
        return NULL;
    }
    
    mask = disable();
    wait(src->lock);
    
    /* Create new address space */
    dst = vmspace_create();
    if (dst == NULL) {
        signal(src->lock);
        restore(mask);
        return NULL;
    }
    
    /* Copy metadata */
    dst->brk = src->brk;
    dst->stack_start = src->stack_start;
    dst->stack_end = src->stack_end;
    dst->code_start = src->code_start;
    dst->code_end = src->code_end;
    dst->data_start = src->data_start;
    dst->data_end = src->data_end;
    
    /* Clone all regions */
    src_region = src->regions;
    while (src_region != NULL) {
        dst_region = region_alloc();
        if (dst_region == NULL) {
            signal(src->lock);
            vmspace_destroy(dst);
            restore(mask);
            return NULL;
        }
        
        /* Copy region info */
        dst_region->start = src_region->start;
        dst_region->end = src_region->end;
        dst_region->type = src_region->type;
        dst_region->flags = src_region->flags;
        dst_region->file_offset = src_region->file_offset;
        
        /* For private regions, set up COW */
        if (src_region->flags & VMR_PRIVATE) {
            /* Mark source pages read-only for COW */
            uint32_t addr;
            for (addr = src_region->start; addr < src_region->end; addr += PAGE_SIZE) {
                /* Set up COW in page tables */
                /* In a real implementation, we'd clear the write bit */
            }
        }
        
        region_insert(dst, dst_region);
        dst->total_vm += dst_region->end - dst_region->start;
        
        src_region = src_region->next;
    }
    
    /* Clone page directory */
    page_dir_destroy(dst->pdir);
    dst->pdir = page_dir_clone(src->pdir);
    
    signal(src->lock);
    restore(mask);
    
    return dst;
}

void vmspace_destroy(vmspace_t *vm) {
    vmregion_t *region, *next;
    intmask mask;
    
    if (vm == NULL || vm == &kernel_vmspace) {
        return;
    }
    
    mask = disable();
    wait(vm->lock);
    
    /* Unmap and free all regions */
    region = vm->regions;
    while (region != NULL) {
        next = region->next;
        
        /* Unmap pages */
        unmap_pages(vm, region->start, region->end);
        
        /* Free region descriptor */
        region_free(region);
        
        region = next;
    }
    
    /* Destroy page directory */
    if (vm->pdir != NULL) {
        page_dir_destroy(vm->pdir);
    }
    
    /* Free lock */
    signal(vm->lock);
    semdelete(vm->lock);
    
    /* Free vmspace structure */
    freemem((char *)vm, sizeof(vmspace_t));
    
    total_vmspaces--;
    
    restore(mask);
}

void vmspace_switch(vmspace_t *vm) {
    intmask mask;
    
    if (vm == NULL) {
        return;
    }
    
    mask = disable();
    
    if (current_vmspace != vm) {
        current_vmspace = vm;
        page_dir_switch(vm->pdir);
    }
    
    restore(mask);
}

vmspace_t *vmspace_current(void) {
    return current_vmspace;
}

vmspace_t *vmspace_kernel(void) {
    return &kernel_vmspace;
}

static uint32_t flags_to_pte(uint32_t flags) {
    uint32_t pte_flags = PTE_P;  /* Present */
    
    if (flags & VMR_WRITE) {
        pte_flags |= PTE_W;
    }
    if (flags & VMR_USER) {
        pte_flags |= PTE_U;
    }
    
    return pte_flags;
}

static bool map_pages(vmspace_t *vm, uint32_t start, uint32_t end, uint32_t flags) {
    uint32_t addr;
    uint32_t frame;
    uint32_t pte_flags;
    
    pte_flags = flags_to_pte(flags);
    
    for (addr = start; addr < end; addr += PAGE_SIZE) {
        /* Allocate a frame */
        frame = frame_alloc();
        if (frame == 0) {
            /* Out of memory - unmap what we've done */
            unmap_pages(vm, start, addr);
            return false;
        }
        
        /* Map the page */
        if (page_map(vm->pdir, addr, frame, pte_flags) != OK) {
            frame_free(frame);
            unmap_pages(vm, start, addr);
            return false;
        }
        
        vm->total_rss += PAGE_SIZE;
    }
    
    return true;
}

static void unmap_pages(vmspace_t *vm, uint32_t start, uint32_t end) {
    uint32_t addr;
    uint32_t frame;
    
    for (addr = start; addr < end; addr += PAGE_SIZE) {
        frame = page_translate(vm->pdir, addr);
        if (frame != 0) {
            page_unmap(vm->pdir, addr);
            frame_free(frame);
            vm->total_rss -= PAGE_SIZE;
        }
    }
}

uint32_t vmem_map(vmspace_t *vm, uint32_t addr, uint32_t size,
                  uint32_t type, uint32_t flags) {
    vmregion_t *region;
    uint32_t start, end;
    intmask mask;
    
    if (vm == NULL || size == 0) {
        return 0;
    }
    
    /* Round to page boundaries */
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    mask = disable();
    wait(vm->lock);
    
    /* Find address if not specified */
    if (addr == 0) {
        addr = vmem_find_free(vm, size, 0);
        if (addr == 0) {
            signal(vm->lock);
            restore(mask);
            return 0;
        }
    } else {
        /* Align requested address */
        addr = addr & ~(PAGE_SIZE - 1);
    }
    
    start = addr;
    end = addr + size;
    
    /* Check for overlap with existing regions */
    vmregion_t *check = vm->regions;
    while (check != NULL) {
        if (start < check->end && end > check->start) {
            signal(vm->lock);
            restore(mask);
            return 0;  /* Overlap */
        }
        check = check->next;
    }
    
    /* Allocate region descriptor */
    region = region_alloc();
    if (region == NULL) {
        signal(vm->lock);
        restore(mask);
        return 0;
    }
    
    /* Setup region */
    region->start = start;
    region->end = end;
    region->type = type;
    region->flags = flags;
    region->file_offset = 0;
    region->private_data = NULL;
    
    /* Insert into region list */
    region_insert(vm, region);
    
    /* Map physical pages */
    if (!map_pages(vm, start, end, flags)) {
        region_remove(vm, region);
        region_free(region);
        signal(vm->lock);
        restore(mask);
        return 0;
    }
    
    vm->total_vm += size;
    total_mapped++;
    
    signal(vm->lock);
    restore(mask);
    
    return start;
}

syscall vmem_unmap(vmspace_t *vm, uint32_t addr, uint32_t size) {
    vmregion_t *region;
    uint32_t start, end;
    intmask mask;
    
    if (vm == NULL || size == 0) {
        return SYSERR;
    }
    
    /* Round to page boundaries */
    addr = addr & ~(PAGE_SIZE - 1);
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    start = addr;
    end = addr + size;
    
    mask = disable();
    wait(vm->lock);
    
    /* Find containing region */
    region = vmem_find_region(vm, addr);
    if (region == NULL) {
        signal(vm->lock);
        restore(mask);
        return SYSERR;
    }
    
    /* Handle partial unmaps */
    if (start > region->start) {
        /* Split off beginning */
        region_split(region, start);
        region = region->next;
    }
    
    if (end < region->end) {
        /* Split off end */
        region_split(region, end);
    }
    
    /* Now region exactly matches [start, end) */
    /* Unmap pages */
    unmap_pages(vm, start, end);
    
    /* Remove and free region */
    vm->total_vm -= (region->end - region->start);
    region_remove(vm, region);
    region_free(region);
    
    total_unmapped++;
    
    signal(vm->lock);
    restore(mask);
    
    return OK;
}

syscall vmem_protect(vmspace_t *vm, uint32_t addr, uint32_t size,
                     uint32_t flags) {
    vmregion_t *region;
    uint32_t start, end, page_addr;
    uint32_t pte_flags;
    intmask mask;
    
    if (vm == NULL || size == 0) {
        return SYSERR;
    }
    
    /* Round to page boundaries */
    addr = addr & ~(PAGE_SIZE - 1);
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    start = addr;
    end = addr + size;
    
    mask = disable();
    wait(vm->lock);
    
    /* Find containing region */
    region = vmem_find_region(vm, addr);
    if (region == NULL) {
        signal(vm->lock);
        restore(mask);
        return SYSERR;
    }
    
    /* Update region flags */
    region->flags = flags;
    
    /* Update page table entries */
    pte_flags = flags_to_pte(flags);
    for (page_addr = start; page_addr < end; page_addr += PAGE_SIZE) {
        uint32_t frame = page_translate(vm->pdir, page_addr);
        if (frame != 0) {
            page_unmap(vm->pdir, page_addr);
            page_map(vm->pdir, page_addr, frame, pte_flags);
        }
    }
    
    /* Flush TLB */
    tlb_flush();
    
    signal(vm->lock);
    restore(mask);
    
    return OK;
}

vmregion_t *vmem_find_region(vmspace_t *vm, uint32_t addr) {
    vmregion_t *region;
    
    if (vm == NULL) {
        return NULL;
    }
    
    region = vm->regions;
    while (region != NULL) {
        if (addr >= region->start && addr < region->end) {
            return region;
        }
        region = region->next;
    }
    
    return NULL;
}

uint32_t vmem_find_free(vmspace_t *vm, uint32_t size, uint32_t hint) {
    vmregion_t *region;
    uint32_t addr;
    
    if (vm == NULL || size == 0) {
        return 0;
    }
    
    /* Round size up */
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    /* Start from hint or beginning of user space */
    if (hint != 0) {
        addr = (hint + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    } else {
        addr = VMEM_USER_START;
    }
    
    /* Search for gap */
    region = vm->regions;
    while (region != NULL) {
        if (region->start >= addr + size) {
            /* Found gap before this region */
            if (addr + size <= VMEM_USER_END) {
                return addr;
            }
        }
        
        /* Move past this region */
        if (region->end > addr) {
            addr = region->end;
        }
        
        region = region->next;
    }
    
    /* Check remaining space */
    if (addr + size <= VMEM_USER_END) {
        return addr;
    }
    
    return 0;
}

void *vmem_sbrk(vmspace_t *vm, int32_t increment) {
    uint32_t old_brk, new_brk;
    intmask mask;
    
    if (vm == NULL) {
        return (void *)-1;
    }
    
    mask = disable();
    wait(vm->lock);
    
    old_brk = vm->brk;
    new_brk = old_brk + increment;
    
    /* Check bounds */
    if (new_brk < VMEM_USER_HEAP || new_brk >= vm->stack_start) {
        signal(vm->lock);
        restore(mask);
        return (void *)-1;
    }
    
    if (increment > 0) {
        /* Growing heap - map new pages */
        uint32_t page_start = (old_brk + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        uint32_t page_end = (new_brk + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        
        if (page_end > page_start) {
            if (!map_pages(vm, page_start, page_end, VMR_USER_RW)) {
                signal(vm->lock);
                restore(mask);
                return (void *)-1;
            }
        }
    } else if (increment < 0) {
        /* Shrinking heap - unmap pages */
        uint32_t page_start = (new_brk + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        uint32_t page_end = (old_brk + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        
        if (page_end > page_start) {
            unmap_pages(vm, page_start, page_end);
        }
    }
    
    vm->brk = new_brk;
    
    signal(vm->lock);
    restore(mask);
    
    return (void *)old_brk;
}

syscall vmem_brk(vmspace_t *vm, uint32_t addr) {
    int32_t increment;
    
    if (vm == NULL) {
        return SYSERR;
    }
    
    increment = addr - vm->brk;
    
    if (vmem_sbrk(vm, increment) == (void *)-1) {
        return SYSERR;
    }
    
    return OK;
}

uint32_t vmem_getbrk(vmspace_t *vm) {
    if (vm == NULL) {
        return 0;
    }
    
    return vm->brk;
}

bool vmem_grow_stack(vmspace_t *vm, uint32_t addr) {
    uint32_t new_start;
    intmask mask;
    
    if (vm == NULL) {
        return false;
    }
    
    mask = disable();
    wait(vm->lock);
    
    /* Check if address is in stack growth region */
    if (addr >= vm->stack_end || addr < vm->stack_start - VMEM_STACK_SIZE) {
        signal(vm->lock);
        restore(mask);
        return false;
    }
    
    /* Calculate new stack start (page-aligned, below fault address) */
    new_start = addr & ~(PAGE_SIZE - 1);
    
    /* Check if we need to grow */
    if (new_start >= vm->stack_start) {
        signal(vm->lock);
        restore(mask);
        return true;  /* Already covered */
    }
    
    /* Map new stack pages */
    if (!map_pages(vm, new_start, vm->stack_start, VMR_USER_RW | VMR_GROWSDOWN)) {
        signal(vm->lock);
        restore(mask);
        return false;
    }
    
    /* Update stack start */
    vm->stack_start = new_start;
    vm->total_vm += (vm->stack_start - new_start);
    
    signal(vm->lock);
    restore(mask);
    
    return true;
}

void vmem_set_stack_limit(vmspace_t *vm, uint32_t limit) {
    if (vm == NULL) {
        return;
    }
    
    /* Ensure limit is reasonable */
    if (limit > VMEM_STACK_SIZE) {
        limit = VMEM_STACK_SIZE;
    }
    
    vm->stack_start = vm->stack_end - limit;
}

bool vmem_fault(vmspace_t *vm, uint32_t fault_addr, uint32_t error_code) {
    vmregion_t *region;
    intmask mask;
    bool write_fault;
    
    if (vm == NULL) {
        return false;
    }
    
    write_fault = (error_code & 0x02) != 0;  /* Bit 1 = write */
    
    mask = disable();
    wait(vm->lock);
    
    /* Find region containing fault address */
    region = vmem_find_region(vm, fault_addr);
    
    if (region == NULL) {
        /* Check if it's a stack growth fault */
        if (fault_addr < vm->stack_end && 
            fault_addr >= vm->stack_start - VMEM_STACK_SIZE) {
            signal(vm->lock);
            restore(mask);
            return vmem_grow_stack(vm, fault_addr);
        }
        
        /* Invalid access */
        signal(vm->lock);
        restore(mask);
        return false;
    }
    
    /* Check permissions */
    if (write_fault && !(region->flags & VMR_WRITE)) {
        /* Check for COW */
        if (region->flags & VMR_PRIVATE) {
            signal(vm->lock);
            restore(mask);
            return vmem_cow_fault(vm, fault_addr);
        }
        
        /* Write to read-only region */
        signal(vm->lock);
        restore(mask);
        return false;
    }
    
    /* Page not present - need to map it */
    uint32_t page_addr = fault_addr & ~(PAGE_SIZE - 1);
    uint32_t frame = frame_alloc();
    
    if (frame == 0) {
        signal(vm->lock);
        restore(mask);
        return false;
    }
    
    uint32_t pte_flags = flags_to_pte(region->flags);
    
    if (page_map(vm->pdir, page_addr, frame, pte_flags) != OK) {
        frame_free(frame);
        signal(vm->lock);
        restore(mask);
        return false;
    }
    
    /* Zero the page */
    memzero((void *)page_addr, PAGE_SIZE);
    
    vm->total_rss += PAGE_SIZE;
    
    signal(vm->lock);
    restore(mask);
    
    return true;
}

bool vmem_cow_fault(vmspace_t *vm, uint32_t addr) {
    uint32_t page_addr;
    uint32_t old_frame, new_frame;
    uint32_t pte_flags;
    vmregion_t *region;
    intmask mask;
    
    if (vm == NULL) {
        return false;
    }
    
    page_addr = addr & ~(PAGE_SIZE - 1);
    
    mask = disable();
    wait(vm->lock);
    
    region = vmem_find_region(vm, addr);
    if (region == NULL) {
        signal(vm->lock);
        restore(mask);
        return false;
    }
    
    /* Get old frame */
    old_frame = page_translate(vm->pdir, page_addr);
    if (old_frame == 0) {
        signal(vm->lock);
        restore(mask);
        return false;
    }
    
    /* Allocate new frame */
    new_frame = frame_alloc();
    if (new_frame == 0) {
        signal(vm->lock);
        restore(mask);
        return false;
    }
    
    /* Copy page contents */
    memcopy((void *)new_frame, (void *)old_frame, PAGE_SIZE);
    
    /* Unmap old page */
    page_unmap(vm->pdir, page_addr);
    
    /* Map new page with write permission */
    pte_flags = flags_to_pte(region->flags) | PTE_W;
    if (page_map(vm->pdir, page_addr, new_frame, pte_flags) != OK) {
        frame_free(new_frame);
        signal(vm->lock);
        restore(mask);
        return false;
    }
    
    /* Flush TLB for this page */
    tlb_flush_page(page_addr);
    
    signal(vm->lock);
    restore(mask);
    
    return true;
}

uint32_t vmem_mmap(vmspace_t *vm, uint32_t addr, uint32_t size,
                   uint32_t flags, int fd, uint32_t offset) {
    uint32_t mapped_addr;
    vmregion_t *region;
    
    /* For now, just do anonymous mapping */
    mapped_addr = vmem_map(vm, addr, size, VMR_TYPE_MMAP, flags);
    if (mapped_addr == 0) {
        return 0;
    }
    
    /* If file mapping, store file info */
    if (fd >= 0) {
        region = vmem_find_region(vm, mapped_addr);
        if (region != NULL) {
            region->file_offset = offset;
            /* Would store file reference here */
        }
    }
    
    return mapped_addr;
}

syscall vmem_munmap(vmspace_t *vm, uint32_t addr, uint32_t size) {
    return vmem_unmap(vm, addr, size);
}

/* Shared memory region table */
#define MAX_SHM_REGIONS 32

typedef struct shm_region {
    uint32_t key;
    uint32_t size;
    uint32_t frame_start;
    uint32_t ref_count;
    bool valid;
} shm_region_t;

static shm_region_t shm_table[MAX_SHM_REGIONS];

int32_t vmem_shmget(uint32_t key, uint32_t size, uint32_t flags) {
    int i;
    intmask mask;
    
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    mask = disable();
    wait(vmem_lock);
    
    /* Check if region with this key exists */
    for (i = 0; i < MAX_SHM_REGIONS; i++) {
        if (shm_table[i].valid && shm_table[i].key == key) {
            signal(vmem_lock);
            restore(mask);
            return i;
        }
    }
    
    /* Find free slot */
    for (i = 0; i < MAX_SHM_REGIONS; i++) {
        if (!shm_table[i].valid) {
            break;
        }
    }
    
    if (i >= MAX_SHM_REGIONS) {
        signal(vmem_lock);
        restore(mask);
        return SYSERR;
    }
    
    /* Allocate physical frames */
    uint32_t num_frames = size / PAGE_SIZE;
    uint32_t frame_start = frame_alloc_range(num_frames);
    
    if (frame_start == 0) {
        signal(vmem_lock);
        restore(mask);
        return SYSERR;
    }
    
    /* Initialize region */
    shm_table[i].key = key;
    shm_table[i].size = size;
    shm_table[i].frame_start = frame_start;
    shm_table[i].ref_count = 0;
    shm_table[i].valid = true;
    
    signal(vmem_lock);
    restore(mask);
    
    return i;
}

uint32_t vmem_shmat(vmspace_t *vm, int32_t shmid, uint32_t addr,
                    uint32_t flags) {
    uint32_t mapped_addr;
    uint32_t size, frame;
    uint32_t page_addr;
    intmask mask;
    
    if (shmid < 0 || shmid >= MAX_SHM_REGIONS) {
        return 0;
    }
    
    mask = disable();
    wait(vmem_lock);
    
    if (!shm_table[shmid].valid) {
        signal(vmem_lock);
        restore(mask);
        return 0;
    }
    
    size = shm_table[shmid].size;
    
    /* Find address if not specified */
    if (addr == 0) {
        addr = vmem_find_free(vm, size, VMEM_SHARED_START);
    }
    
    if (addr == 0) {
        signal(vmem_lock);
        restore(mask);
        return 0;
    }
    
    /* Create region */
    mapped_addr = vmem_map(vm, addr, size, VMR_TYPE_SHARED, flags | VMR_SHARED);
    if (mapped_addr == 0) {
        signal(vmem_lock);
        restore(mask);
        return 0;
    }
    
    /* Map shared frames */
    frame = shm_table[shmid].frame_start;
    for (page_addr = mapped_addr; page_addr < mapped_addr + size; 
         page_addr += PAGE_SIZE, frame += PAGE_SIZE) {
        page_unmap(vm->pdir, page_addr);  /* Remove anonymous mapping */
        page_map(vm->pdir, page_addr, frame, flags_to_pte(flags));
    }
    
    shm_table[shmid].ref_count++;
    
    signal(vmem_lock);
    restore(mask);
    
    return mapped_addr;
}

syscall vmem_shmdt(vmspace_t *vm, uint32_t addr) {
    vmregion_t *region;
    int i;
    intmask mask;
    
    mask = disable();
    wait(vm->lock);
    
    region = vmem_find_region(vm, addr);
    if (region == NULL || !(region->flags & VMR_SHARED)) {
        signal(vm->lock);
        restore(mask);
        return SYSERR;
    }
    
    /* Find shared memory ID */
    wait(vmem_lock);
    for (i = 0; i < MAX_SHM_REGIONS; i++) {
        if (shm_table[i].valid && shm_table[i].frame_start == 
            page_translate(vm->pdir, addr)) {
            shm_table[i].ref_count--;
            break;
        }
    }
    signal(vmem_lock);
    
    /* Unmap region (but don't free shared frames) */
    uint32_t page_addr;
    for (page_addr = region->start; page_addr < region->end; 
         page_addr += PAGE_SIZE) {
        page_unmap(vm->pdir, page_addr);
    }
    
    vm->total_vm -= (region->end - region->start);
    region_remove(vm, region);
    region_free(region);
    
    signal(vm->lock);
    restore(mask);
    
    return OK;
}

void vmem_stats(vmspace_t *vm, uint32_t *total_vm, uint32_t *total_rss) {
    if (vm == NULL) {
        if (total_vm) *total_vm = 0;
        if (total_rss) *total_rss = 0;
        return;
    }
    
    if (total_vm) *total_vm = vm->total_vm;
    if (total_rss) *total_rss = vm->total_rss;
}

void vmem_dump(vmspace_t *vm) {
    vmregion_t *region;
    
    if (vm == NULL) {
        kprintf("vmem_dump: NULL address space\n");
        return;
    }
    
    kprintf("\n=== Virtual Address Space Dump ===\n");
    kprintf("Page Directory: %08x\n", (uint32_t)vm->pdir);
    kprintf("Break: %08x\n", vm->brk);
    kprintf("Stack: %08x - %08x\n", vm->stack_start, vm->stack_end);
    kprintf("Total VM: %u KB\n", vm->total_vm / 1024);
    kprintf("RSS: %u KB\n", vm->total_rss / 1024);
    kprintf("Regions: %u\n\n", vm->region_count);
    
    kprintf("Region List:\n");
    kprintf("  Start     End       Type  Flags\n");
    kprintf("  --------  --------  ----  -----\n");
    
    region = vm->regions;
    while (region != NULL) {
        char type_char;
        
        switch (region->type) {
            case VMR_TYPE_CODE:   type_char = 'C'; break;
            case VMR_TYPE_DATA:   type_char = 'D'; break;
            case VMR_TYPE_BSS:    type_char = 'B'; break;
            case VMR_TYPE_HEAP:   type_char = 'H'; break;
            case VMR_TYPE_STACK:  type_char = 'S'; break;
            case VMR_TYPE_SHARED: type_char = 'M'; break;
            case VMR_TYPE_MMAP:   type_char = 'F'; break;
            default:              type_char = '?'; break;
        }
        
        kprintf("  %08x  %08x  %c     %c%c%c%c\n",
                region->start, region->end, type_char,
                (region->flags & VMR_READ) ? 'r' : '-',
                (region->flags & VMR_WRITE) ? 'w' : '-',
                (region->flags & VMR_EXEC) ? 'x' : '-',
                (region->flags & VMR_USER) ? 'u' : '-');
        
        region = region->next;
    }
    
    kprintf("\n");
}

void vmem_info(void) {
    kprintf("\n Virtual Memory Manager Info \n");
    kprintf("Total address spaces: %u\n", total_vmspaces);
    kprintf("Total regions available: %u\n", total_regions);
    kprintf("Total mappings: %u\n", total_mapped);
    kprintf("Total unmappings: %u\n", total_unmapped);
    kprintf("\n");
}
