/*
 * test_uaf.c – Use-After-Free demonstration
 *
 * Bug: process_data() frees `buf` in the error path at line 28,
 * then the caller dereferences it again at line 45.
 * ASTrace AI should catch the execution path:
 *   alloc → conditional free → return ptr → dereference freed ptr
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 256

/* Returns a heap-allocated buffer, or NULL on error. */
char *process_data(const char *input, int validate)
{
    char *buf = malloc(MAX_SIZE);
    if (!buf) {
        return NULL;
    }

    strncpy(buf, input, MAX_SIZE - 1);
    buf[MAX_SIZE - 1] = '\0';

    if (validate && strlen(input) > 100) {
        /* ERROR PATH: frees buf but still returns its address */
        free(buf);
        fprintf(stderr, "Input too long\n");
        return buf;   /* BUG: returning freed pointer */
    }

    return buf;
}

int main(void)
{
    const char *input = "hello world";
    char *result = process_data(input, 1);

    if (result) {
        /* BUG: if process_data took the error path, this is UAF */
        printf("Result: %s\n", result);
        free(result);
    }

    return 0;
}
