/*
 * test_double_free.c – Double-Free demonstration
 *
 * Bug: cleanup() calls free(ctx->buffer) unconditionally, but
 * handle_error() also calls cleanup() after already calling free()
 * directly, resulting in the same pointer being freed twice.
 * ASTrace AI should trace the two free() call sites.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *buffer;
    int   size;
} Context;

Context *ctx_create(int size)
{
    Context *ctx = malloc(sizeof(Context));
    if (!ctx) return NULL;

    ctx->buffer = malloc((size_t)size);
    if (!ctx->buffer) {
        free(ctx);
        return NULL;
    }
    ctx->size = size;
    return ctx;
}

void cleanup(Context *ctx)
{
    if (!ctx) return;
    free(ctx->buffer);   /* first free site */
    free(ctx);
}

void handle_error(Context *ctx)
{
    /* BUG: frees buffer directly, then calls cleanup which frees it again */
    free(ctx->buffer);   /* second free site - double free */
    fprintf(stderr, "Error encountered\n");
    cleanup(ctx);        /* cleanup() will free ctx->buffer a second time */
}

int main(void)
{
    Context *ctx = ctx_create(128);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }

    memset(ctx->buffer, 0, (size_t)ctx->size);

    int error_condition = 1;
    if (error_condition) {
        handle_error(ctx);   /* triggers double-free */
    } else {
        cleanup(ctx);
    }

    return 0;
}
