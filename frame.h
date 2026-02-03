#ifndef _FRAME_H_
#define _FRAME_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Frame size (same as page size) */
#define FRAME_SIZE          4096

/* Maximum physical memory supported (256 MB) */
#define MAX_PHYS_MEMORY     (256 * 1024 * 1024)

/* Maximum number of frames */
#define MAX_FRAMES          (MAX_PHYS_MEMORY / FRAME_SIZE)

/* Reserved frames for kernel */
#define KERNEL_FRAMES       256 

#define FRAME_FREE          0x00    /* Frame is free */
#define FRAME_USED          0x01    /* Frame is in use */
#define FRAME_KERNEL        0x02    /* Kernel-owned frame */
#define FRAME_LOCKED        0x04    /* Frame is locked (non-swappable) */
#define FRAME_DMA           0x08    /* Frame suitable for DMA */
#define FRAME_SHARED        0x10    /* Frame is shared */
#define FRAME_COW           0x20    /* Copy-on-write frame */

#define ZONE_DMA            0       /* DMA-able memory (< 16MB) */
#define ZONE_NORMAL         1       /* Normal memory */
#define ZONE_HIGH           2       /* High memory (> 896MB) */
#define NUM_ZONES           3

/* Zone boundaries */
#define ZONE_DMA_END        (16 * 1024 * 1024)
#define ZONE_NORMAL_END     (896 * 1024 * 1024)

typedef struct frame {
    uint8_t     flags;          /* Frame flags */
    uint8_t     zone;           /* Memory zone */
    uint16_t    ref_count;      /* Reference count */
    uint32_t    order;          /* Buddy allocator order */
    struct frame *next;         /* Next frame in free list */
    struct frame *prev;         /* Previous frame in free list */
} frame_t;

typedef struct zone_stats {
    uint32_t    total_frames;   /* Total frames in zone */
    uint32_t    free_frames;    /* Free frames in zone */
    uint32_t    used_frames;    /* Used frames in zone */
    uint32_t    reserved;       /* Reserved frames */
    uint32_t    allocations;    /* Total allocations */
    uint32_t    frees;          /* Total frees */
} zone_stats_t;

typedef struct frame_stats {
    uint32_t    total_memory;   /* Total physical memory */
    uint32_t    total_frames;   /* Total frames */
    uint32_t    free_frames;    /* Total free frames */
    uint32_t    used_frames;    /* Total used frames */
    uint32_t    kernel_frames;  /* Kernel frames */
    uint32_t    user_frames;    /* User frames */
    uint32_t    shared_frames;  /* Shared frames */
    uint32_t    locked_frames;  /* Locked frames */
    uint32_t    allocations;    /* Total allocations */
    uint32_t    frees;          /* Total frees */
    uint32_t    failures;       /* Allocation failures */
    zone_stats_t zones[NUM_ZONES]; /* Per-zone stats */
} frame_stats_t;

void frame_init(uint32_t mem_size);
void frame_reserve(uint32_t start_frame, uint32_t count);
void frame_unreserve(uint32_t start_frame, uint32_t count);

uint32_t frame_alloc_single(void);
uint32_t frame_alloc_zone(uint32_t zone);
void frame_free_single(uint32_t frame_num);

uint32_t frame_alloc_contiguous(uint32_t count);
void frame_free_contiguous(uint32_t start_frame, uint32_t count);
uint32_t frame_alloc_order(uint32_t order);
void frame_free_order(uint32_t frame_num, uint32_t order);

uint32_t frame_ref_inc(uint32_t frame_num);
uint32_t frame_ref_dec(uint32_t frame_num);
uint32_t frame_ref_get(uint32_t frame_num);
void frame_ref_set(uint32_t frame_num, uint32_t count);

void frame_set_flags(uint32_t frame_num, uint32_t flags);
void frame_clear_flags(uint32_t frame_num, uint32_t flags);
uint32_t frame_get_flags(uint32_t frame_num);
bool frame_test_flags(uint32_t frame_num, uint32_t flags);

void frame_lock(uint32_t frame_num);
void frame_unlock(uint32_t frame_num);
bool frame_is_locked(uint32_t frame_num);

uint32_t frame_to_phys(uint32_t frame_num);
uint32_t phys_to_frame(uint32_t phys_addr);
uint32_t frame_get_zone(uint32_t frame_num);

bool frame_is_free(uint32_t frame_num);
uint32_t frame_free_count(void);
uint32_t frame_free_count_zone(uint32_t zone);
frame_t *frame_get_desc(uint32_t frame_num);

void frame_get_stats(frame_stats_t *stats);
void frame_print_stats(void);
void frame_dump_map(void);
uint32_t frame_usage_percent(void);

#endif /* _FRAME_H_ */
