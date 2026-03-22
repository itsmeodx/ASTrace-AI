/*
 * test_safe.c – Clean code baseline (expected: NO findings)
 *
 * This file follows correct C memory management patterns:
 *   - Every allocation is checked for NULL.
 *   - Every malloc'd pointer is freed before all return paths.
 *   - Array accesses are bounds-checked before use.
 *   - No pointer arithmetic.
 *
 * LogicAudit should report 0 findings here. If it reports any,
 * that would indicate a false-positive issue to investigate.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 256
#define MAX_ITEMS 32

typedef struct {
    int   id;
    char  name[64];
} Item;

/* Safe string copy into a heap buffer – always frees on error. */
char *safe_copy(const char *src)
{
    if (!src) return NULL;

    size_t len = strlen(src);
    if (len >= BUF_SIZE) {
        fprintf(stderr, "String too long\n");
        return NULL;
    }

    char *dst = malloc(BUF_SIZE);
    if (!dst) return NULL;

    memcpy(dst, src, len + 1);   /* includes NUL terminator */
    return dst;
}

/* Safe array processing – bounds-checked index, all paths free. */
int process_items(int count)
{
    if (count <= 0 || count > MAX_ITEMS) {
        fprintf(stderr, "Invalid count: %d\n", count);
        return -1;
    }

    Item *items = malloc(sizeof(Item) * (size_t)count);
    if (!items) return -1;

    for (int i = 0; i < count; i++) {
        items[i].id = i;
        snprintf(items[i].name, sizeof(items[i].name), "item_%d", i);
    }

    int total = 0;
    for (int i = 0; i < count; i++) {
        /* Bounds are guaranteed by the loop condition */
        total += items[i].id;
    }

    free(items);   /* always freed before returning */
    return total;
}

int main(void)
{
    char *copy = safe_copy("hello");
    if (!copy) {
        fprintf(stderr, "safe_copy failed\n");
        return 1;
    }
    printf("Copy: %s\n", copy);
    free(copy);

    int result = process_items(10);
    if (result < 0) {
        fprintf(stderr, "process_items failed\n");
        return 1;
    }
    printf("Total: %d\n", result);

    return 0;
}
