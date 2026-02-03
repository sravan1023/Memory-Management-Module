#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../include/kernel.h"
#include "../include/memory.h"
#include "frame.h"
#include "memory.h"

/* Frame descriptor table */
static frame_t frame_table[MAX_FRAMES];

/* Free lists per zone */
static frame_t *free_list[NUM_ZONES];

/* Zone boundaries (frame numbers) */
static uint32_t zone_start[NUM_ZONES];
static uint32_t zone_end[NUM_ZONES];

/* Statistics */
static frame_stats_t global_stats;

/* Total frames available */
static uint32_t total_frames = 0;

/* Lock for frame allocator */
static sid32 frame_lock_sem;

/* Initialized flag */
static bool frame_initialized = false;

static void free_list_add(uint32_t frame_num) {
    frame_t *frame = &frame_table[frame_num];
    uint32_t zone = frame->zone;
    
    frame->next = free_list[zone];
    frame->prev = NULL;
    
    if (free_list[zone] != NULL) {
        free_list[zone]->prev = frame;
    }
    
    free_list[zone] = frame;
    global_stats.zones[zone].free_frames++;
    global_stats.free_frames++;
}

/**
 * Remove frame from free list
 */
static void free_list_remove(uint32_t frame_num) {
    frame_t *frame = &frame_table[frame_num];
    uint32_t zone = frame->zone;
    
    if (frame->prev != NULL) {
        frame->prev->next = frame->next;
    } else {
        free_list[zone] = frame->next;
    }
    
    if (frame->next != NULL) {
        frame->next->prev = frame->prev;
    }
    
    frame->next = NULL;
    frame->prev = NULL;
    
    global_stats.zones[zone].free_frames--;
    global_stats.free_frames--;
}

static uint32_t determine_zone(uint32_t frame_num) {
    uint32_t phys_addr = frame_num * FRAME_SIZE;
    
    if (phys_addr < ZONE_DMA_END) {
        return ZONE_DMA;
    } else if (phys_addr < ZONE_NORMAL_END) {
        return ZONE_NORMAL;
    } else {
        return ZONE_HIGH;
    }
}

void frame_init(uint32_t mem_size) {
    uint32_t i;
    intmask mask;
    
    mask = disable();
    
    /* Limit memory to maximum supported */
    if (mem_size > MAX_PHYS_MEMORY) {
        mem_size = MAX_PHYS_MEMORY;
    }
    
    total_frames = mem_size / FRAME_SIZE;
    
    /* Initialize statistics */
    memzero(&global_stats, sizeof(global_stats));
    global_stats.total_memory = mem_size;
    global_stats.total_frames = total_frames;
    
    /* Initialize zone boundaries */
    zone_start[ZONE_DMA] = 0;
    zone_end[ZONE_DMA] = (ZONE_DMA_END < mem_size ? ZONE_DMA_END : mem_size) / FRAME_SIZE;
    
    zone_start[ZONE_NORMAL] = zone_end[ZONE_DMA];
    zone_end[ZONE_NORMAL] = (ZONE_NORMAL_END < mem_size ? ZONE_NORMAL_END : mem_size) / FRAME_SIZE;
    
    zone_start[ZONE_HIGH] = zone_end[ZONE_NORMAL];
    zone_end[ZONE_HIGH] = total_frames;
    
    /* Initialize free lists */
    for (i = 0; i < NUM_ZONES; i++) {
        free_list[i] = NULL;
        global_stats.zones[i].total_frames = zone_end[i] - zone_start[i];
    }
    
    /* Initialize frame descriptors */
    for (i = 0; i < total_frames; i++) {
        frame_table[i].flags = FRAME_FREE;
        frame_table[i].zone = determine_zone(i);
        frame_table[i].ref_count = 0;
        frame_table[i].order = 0;
        frame_table[i].next = NULL;
        frame_table[i].prev = NULL;
    }
    
    /* Reserve kernel frames (first 1MB) */
    for (i = 0; i < KERNEL_FRAMES && i < total_frames; i++) {
        frame_table[i].flags = FRAME_USED | FRAME_KERNEL | FRAME_LOCKED;
        frame_table[i].ref_count = 1;
        global_stats.kernel_frames++;
        global_stats.zones[frame_table[i].zone].reserved++;
    }
    global_stats.used_frames = KERNEL_FRAMES;
    
    /* Add remaining frames to free lists */
    for (i = KERNEL_FRAMES; i < total_frames; i++) {
        free_list_add(i);
    }
    
    /* Create lock */
    frame_lock_sem = semcreate(1);
    
    frame_initialized = true;
    
    restore(mask);
    
    kprintf("Frame manager initialized: %u frames (%u KB), %u free\n",
            total_frames, mem_size / 1024, global_stats.free_frames);
}

void frame_reserve(uint32_t start_frame, uint32_t count) {
    uint32_t i;
    intmask mask;
    
    if (!frame_initialized || start_frame >= total_frames) {
        return;
    }
    
    mask = disable();
    wait(frame_lock_sem);
    
    for (i = start_frame; i < start_frame + count && i < total_frames; i++) {
        if (frame_table[i].flags == FRAME_FREE) {
            free_list_remove(i);
        }
        frame_table[i].flags = FRAME_USED | FRAME_LOCKED;
        frame_table[i].ref_count = 1;
        global_stats.used_frames++;
        global_stats.zones[frame_table[i].zone].reserved++;
    }
    
    signal(frame_lock_sem);
    restore(mask);
}

void frame_unreserve(uint32_t start_frame, uint32_t count) {
    uint32_t i;
    intmask mask;
    
    if (!frame_initialized || start_frame >= total_frames) {
        return;
    }
    
    mask = disable();
    wait(frame_lock_sem);
    
    for (i = start_frame; i < start_frame + count && i < total_frames; i++) {
        if (frame_table[i].flags != FRAME_FREE) {
            frame_table[i].flags = FRAME_FREE;
            frame_table[i].ref_count = 0;
            free_list_add(i);
            global_stats.used_frames--;
            global_stats.zones[frame_table[i].zone].reserved--;
        }
    }
    
    signal(frame_lock_sem);
    restore(mask);
}

uint32_t frame_alloc_single(void) {
    int zone;
    frame_t *frame;
    uint32_t frame_num;
    intmask mask;
    
    if (!frame_initialized) {
        return 0;
    }
    
    mask = disable();
    wait(frame_lock_sem);
    
    /* Try each zone, starting from NORMAL */
    for (zone = ZONE_NORMAL; zone >= 0; zone--) {
        if (free_list[zone] != NULL) {
            frame = free_list[zone];
            frame_num = frame - frame_table;
            
            free_list_remove(frame_num);
            
            frame->flags = FRAME_USED;
            frame->ref_count = 1;
            
            global_stats.used_frames++;
            global_stats.user_frames++;
            global_stats.allocations++;
            global_stats.zones[zone].allocations++;
            global_stats.zones[zone].used_frames++;
            
            signal(frame_lock_sem);
            restore(mask);
            
            /* Zero the frame */
            memzero((void *)frame_to_phys(frame_num), FRAME_SIZE);
            
            return frame_num;
        }
    }
    
    /* Try high memory */
    if (free_list[ZONE_HIGH] != NULL) {
        frame = free_list[ZONE_HIGH];
        frame_num = frame - frame_table;
        
        free_list_remove(frame_num);
        
        frame->flags = FRAME_USED;
        frame->ref_count = 1;
        
        global_stats.used_frames++;
        global_stats.user_frames++;
        global_stats.allocations++;
        global_stats.zones[ZONE_HIGH].allocations++;
        global_stats.zones[ZONE_HIGH].used_frames++;
        
        signal(frame_lock_sem);
        restore(mask);
        
        memzero((void *)frame_to_phys(frame_num), FRAME_SIZE);
        
        return frame_num;
    }
    
    global_stats.failures++;
    
    signal(frame_lock_sem);
    restore(mask);
    
    return 0;
}

uint32_t frame_alloc_zone(uint32_t zone) {
    frame_t *frame;
    uint32_t frame_num;
    intmask mask;
    
    if (!frame_initialized || zone >= NUM_ZONES) {
        return 0;
    }
    
    mask = disable();
    wait(frame_lock_sem);
    
    if (free_list[zone] == NULL) {
        global_stats.failures++;
        signal(frame_lock_sem);
        restore(mask);
        return 0;
    }
    
    frame = free_list[zone];
    frame_num = frame - frame_table;
    
    free_list_remove(frame_num);
    
    frame->flags = FRAME_USED;
    frame->ref_count = 1;
    
    global_stats.used_frames++;
    global_stats.user_frames++;
    global_stats.allocations++;
    global_stats.zones[zone].allocations++;
    global_stats.zones[zone].used_frames++;
    
    signal(frame_lock_sem);
    restore(mask);
    
    memzero((void *)frame_to_phys(frame_num), FRAME_SIZE);
    
    return frame_num;
}

void frame_free_single(uint32_t frame_num) {
    frame_t *frame;
    intmask mask;
    
    if (!frame_initialized || frame_num >= total_frames) {
        return;
    }
    
    mask = disable();
    wait(frame_lock_sem);
    
    frame = &frame_table[frame_num];
    
    /* Check if already free */
    if (frame->flags == FRAME_FREE) {
        signal(frame_lock_sem);
        restore(mask);
        return;
    }
    
    /* Don't free kernel frames */
    if (frame->flags & FRAME_KERNEL) {
        signal(frame_lock_sem);
        restore(mask);
        return;
    }
    
    /* Decrement reference count */
    if (frame->ref_count > 0) {
        frame->ref_count--;
    }
    
    /* Only free if ref count is 0 */
    if (frame->ref_count == 0) {
        uint32_t zone = frame->zone;
        
        frame->flags = FRAME_FREE;
        free_list_add(frame_num);
        
        global_stats.used_frames--;
        global_stats.user_frames--;
        global_stats.frees++;
        global_stats.zones[zone].frees++;
        global_stats.zones[zone].used_frames--;
    }
    
    signal(frame_lock_sem);
    restore(mask);
}

uint32_t frame_alloc_contiguous(uint32_t count) {
    uint32_t i, j;
    uint32_t start = 0;
    uint32_t found = 0;
    intmask mask;
    
    if (!frame_initialized || count == 0) {
        return 0;
    }
    
    mask = disable();
    wait(frame_lock_sem);
    
    /* Search for contiguous free frames */
    for (i = KERNEL_FRAMES; i < total_frames; i++) {
        if (frame_table[i].flags == FRAME_FREE) {
            if (found == 0) {
                start = i;
            }
            found++;
            
            if (found == count) {
                /* Found enough frames */
                for (j = start; j < start + count; j++) {
                    free_list_remove(j);
                    frame_table[j].flags = FRAME_USED;
                    frame_table[j].ref_count = 1;
                    frame_table[j].order = 0;  /* Not buddy-allocated */
                    
                    global_stats.used_frames++;
                    global_stats.user_frames++;
                    global_stats.zones[frame_table[j].zone].used_frames++;
                }
                
                global_stats.allocations++;
                
                signal(frame_lock_sem);
                restore(mask);
                
                /* Zero the frames */
                memzero((void *)frame_to_phys(start), count * FRAME_SIZE);
                
                return start;
            }
        } else {
            found = 0;
        }
    }
    
    global_stats.failures++;
    
    signal(frame_lock_sem);
    restore(mask);
    
    return 0;
}

void frame_free_contiguous(uint32_t start_frame, uint32_t count) {
    uint32_t i;
    
    if (!frame_initialized || start_frame >= total_frames) {
        return;
    }
    
    for (i = start_frame; i < start_frame + count && i < total_frames; i++) {
        frame_free_single(i);
    }
}

uint32_t frame_alloc_order(uint32_t order) {
    uint32_t count = 1 << order;
    uint32_t alignment = count;
    uint32_t i, j;
    uint32_t start;
    intmask mask;
    
    if (!frame_initialized || order > 10) {  /* Max 1024 frames */
        return 0;
    }
    
    mask = disable();
    wait(frame_lock_sem);
    
    /* Find aligned contiguous frames */
    for (i = KERNEL_FRAMES; i < total_frames; i += alignment) {
        if (i + count > total_frames) {
            break;
        }
        
        /* Check if all frames are free */
        bool all_free = true;
        for (j = i; j < i + count; j++) {
            if (frame_table[j].flags != FRAME_FREE) {
                all_free = false;
                break;
            }
        }
        
        if (all_free) {
            start = i;
            
            /* Allocate all frames */
            for (j = start; j < start + count; j++) {
                free_list_remove(j);
                frame_table[j].flags = FRAME_USED;
                frame_table[j].ref_count = 1;
                frame_table[j].order = order;
                
                global_stats.used_frames++;
                global_stats.user_frames++;
                global_stats.zones[frame_table[j].zone].used_frames++;
            }
            
            global_stats.allocations++;
            
            signal(frame_lock_sem);
            restore(mask);
            
            memzero((void *)frame_to_phys(start), count * FRAME_SIZE);
            
            return start;
        }
    }
    
    global_stats.failures++;
    
    signal(frame_lock_sem);
    restore(mask);
    
    return 0;
}

void frame_free_order(uint32_t frame_num, uint32_t order) {
    uint32_t count = 1 << order;
    frame_free_contiguous(frame_num, count);
}

uint32_t frame_ref_inc(uint32_t frame_num) {
    intmask mask;
    uint32_t count;
    
    if (!frame_initialized || frame_num >= total_frames) {
        return 0;
    }
    
    mask = disable();
    wait(frame_lock_sem);
    
    frame_table[frame_num].ref_count++;
    count = frame_table[frame_num].ref_count;
    
    if (count > 1) {
        frame_table[frame_num].flags |= FRAME_SHARED;
        global_stats.shared_frames++;
    }
    
    signal(frame_lock_sem);
    restore(mask);
    
    return count;
}

uint32_t frame_ref_dec(uint32_t frame_num) {
    intmask mask;
    uint32_t count;
    
    if (!frame_initialized || frame_num >= total_frames) {
        return 0;
    }
    
    mask = disable();
    wait(frame_lock_sem);
    
    if (frame_table[frame_num].ref_count > 0) {
        frame_table[frame_num].ref_count--;
    }
    
    count = frame_table[frame_num].ref_count;
    
    if (count == 1) {
        frame_table[frame_num].flags &= ~FRAME_SHARED;
        global_stats.shared_frames--;
    }
    
    signal(frame_lock_sem);
    restore(mask);
    
    /* Free if no more references */
    if (count == 0) {
        frame_free_single(frame_num);
    }
    
    return count;
}

uint32_t frame_ref_get(uint32_t frame_num) {
    if (!frame_initialized || frame_num >= total_frames) {
        return 0;
    }
    
    return frame_table[frame_num].ref_count;
}

void frame_ref_set(uint32_t frame_num, uint32_t count) {
    intmask mask;
    
    if (!frame_initialized || frame_num >= total_frames) {
        return;
    }
    
    mask = disable();
    wait(frame_lock_sem);
    
    frame_table[frame_num].ref_count = count;
    
    if (count > 1) {
        frame_table[frame_num].flags |= FRAME_SHARED;
    } else {
        frame_table[frame_num].flags &= ~FRAME_SHARED;
    }
    
    signal(frame_lock_sem);
    restore(mask);
}

void frame_set_flags(uint32_t frame_num, uint32_t flags) {
    intmask mask;
    
    if (!frame_initialized || frame_num >= total_frames) {
        return;
    }
    
    mask = disable();
    frame_table[frame_num].flags |= flags;
    
    if (flags & FRAME_LOCKED) {
        global_stats.locked_frames++;
    }
    
    restore(mask);
}

void frame_clear_flags(uint32_t frame_num, uint32_t flags) {
    intmask mask;
    
    if (!frame_initialized || frame_num >= total_frames) {
        return;
    }
    
    mask = disable();
    
    if ((frame_table[frame_num].flags & FRAME_LOCKED) && (flags & FRAME_LOCKED)) {
        global_stats.locked_frames--;
    }
    
    frame_table[frame_num].flags &= ~flags;
    restore(mask);
}

uint32_t frame_get_flags(uint32_t frame_num) {
    if (!frame_initialized || frame_num >= total_frames) {
        return 0;
    }
    
    return frame_table[frame_num].flags;
}

bool frame_test_flags(uint32_t frame_num, uint32_t flags) {
    if (!frame_initialized || frame_num >= total_frames) {
        return false;
    }
    
    return (frame_table[frame_num].flags & flags) == flags;
}

void frame_lock(uint32_t frame_num) {
    frame_set_flags(frame_num, FRAME_LOCKED);
}

void frame_unlock(uint32_t frame_num) {
    frame_clear_flags(frame_num, FRAME_LOCKED);
}

bool frame_is_locked(uint32_t frame_num) {
    return frame_test_flags(frame_num, FRAME_LOCKED);
}

uint32_t frame_to_phys(uint32_t frame_num) {
    return frame_num * FRAME_SIZE;
}

uint32_t phys_to_frame(uint32_t phys_addr) {
    return phys_addr / FRAME_SIZE;
}

uint32_t frame_get_zone(uint32_t frame_num) {
    if (!frame_initialized || frame_num >= total_frames) {
        return 0;
    }
    
    return frame_table[frame_num].zone;
}

bool frame_is_free(uint32_t frame_num) {
    if (!frame_initialized || frame_num >= total_frames) {
        return false;
    }
    
    return frame_table[frame_num].flags == FRAME_FREE;
}

uint32_t frame_free_count(void) {
    if (!frame_initialized) {
        return 0;
    }
    
    return global_stats.free_frames;
}

uint32_t frame_free_count_zone(uint32_t zone) {
    if (!frame_initialized || zone >= NUM_ZONES) {
        return 0;
    }
    
    return global_stats.zones[zone].free_frames;
}

frame_t *frame_get_desc(uint32_t frame_num) {
    if (!frame_initialized || frame_num >= total_frames) {
        return NULL;
    }
    
    return &frame_table[frame_num];
}

void frame_get_stats(frame_stats_t *stats) {
    intmask mask;
    
    if (stats == NULL || !frame_initialized) {
        return;
    }
    
    mask = disable();
    memcopy(stats, &global_stats, sizeof(frame_stats_t));
    restore(mask);
}

void frame_print_stats(void) {
    int i;
    
    if (!frame_initialized) {
        kprintf("Frame manager not initialized\n");
        return;
    }
    
    kprintf("\n=== Frame Manager Statistics ===\n");
    kprintf("Total Memory:    %u KB\n", global_stats.total_memory / 1024);
    kprintf("Total Frames:    %u\n", global_stats.total_frames);
    kprintf("Free Frames:     %u (%u KB)\n", 
            global_stats.free_frames,
            global_stats.free_frames * FRAME_SIZE / 1024);
    kprintf("Used Frames:     %u (%u KB)\n",
            global_stats.used_frames,
            global_stats.used_frames * FRAME_SIZE / 1024);
    kprintf("Kernel Frames:   %u\n", global_stats.kernel_frames);
    kprintf("User Frames:     %u\n", global_stats.user_frames);
    kprintf("Shared Frames:   %u\n", global_stats.shared_frames);
    kprintf("Locked Frames:   %u\n", global_stats.locked_frames);
    kprintf("Allocations:     %u\n", global_stats.allocations);
    kprintf("Frees:           %u\n", global_stats.frees);
    kprintf("Failures:        %u\n", global_stats.failures);
    
    kprintf("\nPer-Zone Statistics:\n");
    for (i = 0; i < NUM_ZONES; i++) {
        const char *zone_name;
        switch (i) {
            case ZONE_DMA:    zone_name = "DMA"; break;
            case ZONE_NORMAL: zone_name = "Normal"; break;
            case ZONE_HIGH:   zone_name = "High"; break;
            default:          zone_name = "Unknown"; break;
        }
        
        kprintf("  %s Zone:\n", zone_name);
        kprintf("    Total:  %u frames\n", global_stats.zones[i].total_frames);
        kprintf("    Free:   %u frames\n", global_stats.zones[i].free_frames);
        kprintf("    Used:   %u frames\n", global_stats.zones[i].used_frames);
        kprintf("    Reserved: %u frames\n", global_stats.zones[i].reserved);
    }
    
    kprintf("\n");
}

void frame_dump_map(void) {
    uint32_t i, j;
    uint32_t rows = (total_frames + 63) / 64;
    
    if (!frame_initialized) {
        kprintf("Frame manager not initialized\n");
        return;
    }
    
    kprintf("\n Frame Allocation Map \n");
    kprintf("Legend: . = free, # = used, K = kernel, L = locked\n\n");
    
    for (i = 0; i < rows && i < 32; i++) {  /* Limit output */
        kprintf("%04x: ", i * 64);
        for (j = 0; j < 64; j++) {
            uint32_t idx = i * 64 + j;
            if (idx >= total_frames) {
                break;
            }
            
            uint32_t flags = frame_table[idx].flags;
            char c;
            
            if (flags == FRAME_FREE) {
                c = '.';
            } else if (flags & FRAME_KERNEL) {
                c = 'K';
            } else if (flags & FRAME_LOCKED) {
                c = 'L';
            } else {
                c = '#';
            }
            
            kprintf("%c", c);
        }
        kprintf("\n");
    }
    
    if (rows > 32) {
        kprintf("... (%u more rows)\n", rows - 32);
    }
    
    kprintf("\n");
}

uint32_t frame_usage_percent(void) {
    if (!frame_initialized || global_stats.total_frames == 0) {
        return 0;
    }
    
    return (global_stats.used_frames * 100) / global_stats.total_frames;
}
