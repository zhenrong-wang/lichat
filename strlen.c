#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include <stdint.h> /* MUST include to use const width types. */
#include <immintrin.h> /* MUST include it for SIMD intrinsics. */

size_t _simd_strlen(const char *str) {
    if (!str) 
        return 0;
    __m256i *ptr = (__m256i *)str;
    __m256i zero = _mm256_setzero_si256();
    while(1) {
        __m256i vec = _mm256_loadu_si256(ptr);
        __m256i vec_cmp = _mm256_cmpeq_epi8(vec, zero);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(vec_cmp);
        if(mask == 0x00000000) {
            ++ ptr; continue;
        }
        uint8_t j = 0;
        uint32_t target = 0x00000001;
        while(!(target & mask)) {
            ++ j; target <<= 1;
        }
        return (char *)ptr - str + j;
    }
}

size_t _quick_strlen(const char *str) {
    if (!str) 
        return 0; /* Actually there should be an errno. */
    uint64_t *ptr = (uint64_t *)str;
    while(1) {
        uint64_t val = *ptr;
        uint64_t ad = val + (uint64_t)0x7efefefefefefeff;
        val = (~val) ^ ad;
        if((val & (uint64_t)0x8101010101010100) == 0) {
            ++ ptr;
            continue;
        }
        uint8_t i = 0;
        uint64_t val_tail = *ptr;

        /* Non-strict: We assume it is little-endian. */
        while((val_tail & 0xFF) != 0 && i < 8) {
            ++ i; val_tail = val_tail >> 8;
        }
        return (char *)ptr - str + i;
    }
}

size_t _naive_strlen(const char *str) {
    if (!str) 
        return 0; /* Actually there should be an errno. */
    char *ptr = (char *)str;
    while(*ptr != '\0') 
        ++ ptr;
    return ptr - str;
}

#define ARR_SIZE 3000000
int main(int argc, char **argv) {
    char *str = NULL;
    size_t len = 0;
    if(argc < 2) {
        str = (char *)malloc(ARR_SIZE * sizeof(char));
        len = ARR_SIZE;
    }
    else {
        len = atol(argv[1]);
        if(!len) {
            str = (char *)malloc(ARR_SIZE * sizeof(char));
            len = ARR_SIZE;
        }
        else {
            str = (char *)malloc(len * sizeof(char));
        }
    }
    if(str == NULL) {
        return 1;
    }
    for(size_t i = 0; i < len; ++ i) {
        str[i] = rand() % 60 + 60;
    }
    srand(time(0));
    size_t pos = ((size_t)rand() + (size_t)rand()) % len;
    str[pos] = '\0';
    clock_t s, e;

    s = clock();
    strlen(str);
    e = clock();
    printf("%lu\t%lu\n", e - s, strlen(str));

    s = clock();
    _simd_strlen(str);
    e = clock();
    printf("%lu\t%lu\n", e - s, _simd_strlen(str));

    s = clock();
    _naive_strlen(str);
    e = clock();
    printf("%lu\t%lu\n", e - s, _naive_strlen(str));

    s = clock();
    _quick_strlen(str);
    e = clock();
    printf("%lu\t%lu\n", e - s, _quick_strlen(str));
    
    free(str);
    return 0;
}
