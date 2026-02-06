#ifndef _VMEM_H_
#define _VMEM_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "paging.h"

/* Virtual address space layout */
#define VMEM_USER_START     0x00400000      /* User space start (4MB) */
#define VMEM_USER_END       0xBFFFFFFF      /* User space end */
#define VMEM_KERNEL_START   0xC0000000      /* Kernel space start (3GB) */
#define VMEM_KERNEL_END     0xFFFFFFFF      /* Kernel space end */

/* Stack region */
#define VMEM_USER_STACK     0xBFFFF000      /* User stack top */
#define VMEM_STACK_SIZE     (8 * 1024 * 1024)   /* 8MB max stack */

/* Heap region */
#define VMEM_USER_HEAP      0x10000000      /* User heap start */
#define VMEM_HEAP_MAX       (256 * 1024 * 1024) /* 256MB max heap */

/* Shared memory region */
#define VMEM_SHARED_START   0x60000000      /* Shared memory region */
#define VMEM_SHARED_END     0x80000000      /* End of shared region */

/* Maximum regions per address space */
#define MAX_VM_REGIONS      64

#define VMR_TYPE_FREE       0       /* Unallocated region */
#define VMR_TYPE_CODE       1       /* Executable code */
#define VMR_TYPE_DATA       2       /* Initialized data */
#define VMR_TYPE_BSS        3       /* Uninitialized data */
#define VMR_TYPE_HEAP       4       /* Heap memory */
#define VMR_TYPE_STACK      5       /* Stack memory */
#define VMR_TYPE_SHARED     6       /* Shared memory */
#define VMR_TYPE_MMAP       7       /* Memory-mapped region */
#define VMR_TYPE_DEVICE     8       /* Device memory */

#define VMR_READ            0x01    /* Region is readable */
#define VMR_WRITE           0x02    /* Region is writable */
#define VMR_EXEC            0x04    /* Region is executable */
#define VMR_USER            0x08    /* Region is user-accessible */
#define VMR_SHARED          0x10    /* Region is shared */
#define VMR_PRIVATE         0x20    /* Region is private (COW) */
#define VMR_GROWSDOWN       0x40    /* Region grows downward (stack) */
#define VMR_LOCKED          0x80    /* Region is locked in memory */

/* Common flag combinations */
#define VMR_RW              (VMR_READ | VMR_WRITE)
#define VMR_RX              (VMR_READ | VMR_EXEC)
#define VMR_RWX             (VMR_READ | VMR_WRITE | VMR_EXEC)
#define VMR_USER_RW         (VMR_READ | VMR_WRITE | VMR_USER)
#define VMR_USER_RX         (VMR_READ | VMR_EXEC | VMR_USER)

typedef struct vmregion {
    uint32_t    start;          /* Start virtual address */
    uint32_t    end;            /* End virtual address (exclusive) */
    uint32_t    type;           /* Region type */
    uint32_t    flags;          /* Region flags */
    uint32_t    file_offset;    /* File offset (for mmap) */
    void        *private_data;  /* Private data pointer */
    struct vmregion *next;      /* Next region in list */
    struct vmregion *prev;      /* Previous region in list */
} vmregion_t;

typedef struct vmspace {
    page_directory_t *pdir;     /* Page directory */
    vmregion_t  *regions;       /* Region list (sorted by address) */
    uint32_t    region_count;   /* Number of regions */
    uint32_t    brk;            /* Current heap break */
    uint32_t    stack_start;    /* Stack start (bottom) */
    uint32_t    stack_end;      /* Stack end (top) */
    uint32_t    code_start;     /* Code segment start */
    uint32_t    code_end;       /* Code segment end */
    uint32_t    data_start;     /* Data segment start */
    uint32_t    data_end;       /* Data segment end */
    uint32_t    total_vm;       /* Total virtual memory mapped */
    uint32_t    total_rss;      /* Resident set size */
    sid32       lock;           /* Address space lock */
} vmspace_t;

void vmem_init(void);

vmspace_t *vmspace_create(void);
vmspace_t *vmspace_clone(vmspace_t *src);
void vmspace_destroy(vmspace_t *vm);
void vmspace_switch(vmspace_t *vm);
vmspace_t *vmspace_current(void);
vmspace_t *vmspace_kernel(void);

uint32_t vmem_map(vmspace_t *vm, uint32_t addr, uint32_t size,
                  uint32_t type, uint32_t flags);
syscall vmem_unmap(vmspace_t *vm, uint32_t addr, uint32_t size);
syscall vmem_protect(vmspace_t *vm, uint32_t addr, uint32_t size,
                     uint32_t flags);
vmregion_t *vmem_find_region(vmspace_t *vm, uint32_t addr);
uint32_t vmem_find_free(vmspace_t *vm, uint32_t size, uint32_t hint);

void *vmem_sbrk(vmspace_t *vm, int32_t increment);
syscall vmem_brk(vmspace_t *vm, uint32_t addr);
uint32_t vmem_getbrk(vmspace_t *vm);

bool vmem_grow_stack(vmspace_t *vm, uint32_t addr);
void vmem_set_stack_limit(vmspace_t *vm, uint32_t limit);

bool vmem_fault(vmspace_t *vm, uint32_t fault_addr, uint32_t error_code);
bool vmem_cow_fault(vmspace_t *vm, uint32_t addr);

uint32_t vmem_mmap(vmspace_t *vm, uint32_t addr, uint32_t size,
                   uint32_t flags, int fd, uint32_t offset);
syscall vmem_munmap(vmspace_t *vm, uint32_t addr, uint32_t size);

int32_t vmem_shmget(uint32_t key, uint32_t size, uint32_t flags);
uint32_t vmem_shmat(vmspace_t *vm, int32_t shmid, uint32_t addr,
                    uint32_t flags);
syscall vmem_shmdt(vmspace_t *vm, uint32_t addr);

void vmem_stats(vmspace_t *vm, uint32_t *total_vm, uint32_t *total_rss);
void vmem_dump(vmspace_t *vm);
void vmem_info(void);

#endif /* _VMEM_H_ */
