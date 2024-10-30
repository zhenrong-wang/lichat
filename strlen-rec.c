/**
 * A recursion mini example.
 * Implement the C strlen() in three lines without loop. 
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* The core function with 3 lines. */
size_t my_strlen_core(const char *ptr, size_t len){
    if(ptr == NULL) return 0; 
    if(*ptr == '\0') return len;
    return my_strlen_core(++ptr, ++len);
}

/* The final API exposed to users. */
size_t my_strlen(const char *ptr_str) {
    return my_strlen_core(ptr_str, 0);
}

#define LENMAX 200000
/**
 * Test some strings against the standard strlen() function.
 * This implementation is better because it avoids segfault
 * triggered by strlen(NULL). 
 */
int main(int argc, char **argv) {
    char *str1 = "hello world!", *str2 = "foo", *str3 = NULL;
    printf("%lu\t%ld\t%s\n", my_strlen(str1), strlen(str1), str1);
    printf("%lu\t%ld\t%s\n", my_strlen(str2), strlen(str2), str2);
    printf("%lu\n", my_strlen(str3));
    size_t k = my_strlen(str3);
    if(k == (size_t)-1) {
        printf("NOOOOOOOOOOOOOOOOOOOOOOO!\n");
    }
    char *longstr = (char *)calloc(LENMAX, sizeof(char));
    for(size_t i = 0; i < LENMAX - 1; i++) {
        longstr[i] = 'a';
    }
    clock_t start, stop;
    start = clock();
    my_strlen(longstr);
    stop = clock();
    printf("%ld\n", stop - start);
    start = clock();
    strlen(longstr);
    stop = clock();
    printf("%ld\n", stop - start);
    printf("%ld\t%ld\n", my_strlen(longstr), strlen(longstr));
    return 0;
}
