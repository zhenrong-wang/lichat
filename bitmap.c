/**
 * This is the simplest code to create and manage a bitmap. Bitmap is very 
 * important in many data processing scenarios. A typical one in networking
 * is to record the data packats with Serial Numbers and keep the integrity.
 * This code is only for demo, and it is licensed under MIT.
 * X/Twitter: @wangzhr4
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define INVALID_BITMAP_SIZE 0
typedef unsigned char bitmap_t;
typedef unsigned char u8;

/** 
 * Create a bitmap with the format below: 
 * Head : sizeof(size_t) width to record the # of elements.
 * Body : a group of bytes, each *bit* corresponds to the serial number of a 
 *      : raw data packet.
 */
bitmap_t *create_bitmap(const size_t n) {
    if(!n) return NULL;
    size_t bitmap_size = sizeof(size_t) + (n >> 3) + ((n & 0x07) ? 1 : 0);
    bitmap_t *ptr_bitmap = (bitmap_t *)calloc(bitmap_size, sizeof(bitmap_t));
    if(ptr_bitmap == NULL) 
        return NULL;
    /* Push the size n to the header of the map. */
    for(u8 i = 0; i < sizeof(size_t); ++ i)
        ptr_bitmap[i] = (n >> (i << 3)) & 0xFF;
    return ptr_bitmap;
}

/* Extract the size n from a given bitmap. */
size_t get_bitmap_size(const bitmap_t *ptr_bitmap) {
    if(!ptr_bitmap) return INVALID_BITMAP_SIZE;
    size_t n = 0x00;
    for(u8 i = 0; i < sizeof(size_t); ++ i)
        n |= (size_t)ptr_bitmap[i] << (i << 3);
    return n;
}

/**
 * Return -3: Invalid bitmap size; -1: invalid serial number. 
 * Return  0: Good to go.
 * The serial number should be [0, (bitmap_size - 1)]
 */
int precheck_sn_size(const size_t sn, const bitmap_t *ptr_bitmap) {
    size_t bitmap_size = get_bitmap_size(ptr_bitmap);
    if(bitmap_size == INVALID_BITMAP_SIZE) 
        return -3; /* Invalid bitmap size. */
    if(sn >= bitmap_size) 
        return -1; /* Invalid serial number. */
    return 0;
}

/**
 * Check whether a serial number has been recorded in the map or not. 
 * This usually happens when we'd like to drop a duplicate data packet.
 */
int sn_check(const size_t sn, const bitmap_t *ptr_bitmap) {
    int check = precheck_sn_size(sn, ptr_bitmap);
    if(check < 0) 
        return check;
    const bitmap_t *head = ptr_bitmap + sizeof(size_t);
    return (head[sn >> 3] & ((u8)0x80 >> (sn & 0x07))) ? 1 : 0;
}

/**
 * Flip the bit corresponding to the provided serial number. 
 * This usually happens when we want to record a recieved data.
 */
int sn_update(const size_t sn, bitmap_t *ptr_bitmap) {
    int check = precheck_sn_size(sn, ptr_bitmap);
    if(check < 0) 
        return check;
    (ptr_bitmap + sizeof(size_t))[sn >> 3] |= ((u8)0x80 >> (sn & 0x07));
    return 1;
}

/**
 * Walk across the map to see whether it is full or not. 
 * This usually happens when checking data integrity (avoid data loss).
 */
int all_check(const bitmap_t *ptr_bitmap) {
    size_t bitmap_size = get_bitmap_size(ptr_bitmap);
    if(bitmap_size == INVALID_BITMAP_SIZE) 
        return -3;

    size_t level1_rounds = bitmap_size >> 6;
    size_t level2_rounds = (bitmap_size & 0x3F) >> 3;
    u8 res_bits = (bitmap_size & 0x3F) & 0x07;

    uint64_t *level1_ptr = (uint64_t *)(ptr_bitmap + sizeof(size_t));
    for(size_t i = 0; i < level1_rounds; ++ i) {
        if(level1_ptr[i] != UINT64_MAX)
            return 1; /* Vacancy found. */
    }
    u8 *level2_ptr = (u8 *)(level1_ptr + level1_rounds);
    for(size_t i = 0; i < level2_rounds; ++ i) {
        if(level2_ptr[i] != UINT8_MAX)
            return 1; /* Vacancy found. */
    }
    u8 last_byte = (*(level2_ptr + level2_rounds)) >> (8 - res_bits);
    if(last_byte ^ (0xFF >> (8 - res_bits)))
        return 1; /* Vacancy found. */
    return 0; /* The bitmap is full. */
}

/* Free the allocated bitmap and null the pointer to avoid risks. */
void free_bitmap(bitmap_t **ptr_bitmap) {
    free(*ptr_bitmap);
    *ptr_bitmap = NULL;
}

int main(int argc, char **argv) {
    bitmap_t *p = create_bitmap(100);
    printf("Created a bitmap with size: %lu.\n", get_bitmap_size(p));
    sn_update(0, p);
    printf("Updated the element[0].\n");
    sn_update(1, p);
    printf("Updated the element[1].\n");
    printf("Elem[0]:\t%d\nElem[1]:\t%d\nElem[2]:\t%d\n", sn_check(0, p), \
            sn_check(1, p), sn_check(2, p));
    printf("All_check:\t%d\n", all_check(p));
    for(size_t i = 0; i < 100; ++ i) {
        sn_update(i, p);
    }
    printf("All_check:\t%d\n", all_check(p));
    free_bitmap(&p);
}
