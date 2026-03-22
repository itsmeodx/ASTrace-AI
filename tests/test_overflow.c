/*
 * test_overflow.c – Buffer Overflow / Integer Overflow demonstration
 *
 * Bug 1 (integer overflow → heap overflow):
 *   copy_packets() multiplies user-controlled `count * sizeof(Packet)`.
 *   If count is large enough, the multiplication overflows size_t and
 *   malloc() allocates a tiny buffer; the loop then writes past it.
 *
 * Bug 2 (off-by-one stack overflow):
 *   build_path() copies `name` into a 64-byte stack buffer using
 *   strcpy – no bounds check at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PATH_LEN 64

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  payload[512];
} Packet;

/* BUG: integer overflow if count > SIZE_MAX / sizeof(Packet) */
Packet *copy_packets(const Packet *src, size_t count)
{
    /* No overflow check before multiplication */
    Packet *dst = malloc(count * sizeof(Packet));
    if (!dst) return NULL;

    for (size_t i = 0; i < count; i++) {
        dst[i] = src[i];   /* write past the (tiny) allocation if overflowed */
    }
    return dst;
}

/* BUG: stack buffer overflow – name length is not checked */
void build_path(const char *base, const char *name)
{
    char path[PATH_LEN];
    strcpy(path, base);         /* no bounds check */
    strcat(path, "/");
    strcat(path, name);         /* overflows if base+name >= 64 bytes */
    printf("Path: %s\n", path);
}

int main(void)
{
    Packet sample = {0};
    sample.src_ip = 0x7f000001;
    sample.dst_ip = 0x08080808;

    /* Simulate receiving a count from an untrusted source */
    size_t user_count = SIZE_MAX / sizeof(Packet) + 1;  /* triggers overflow */
    Packet *packets = copy_packets(&sample, user_count);
    if (packets) free(packets);

    /* Long strings cause stack overflow in build_path */
    build_path("/very/long/base/directory/path/that/exceeds",
               "a_very_long_filename_that_will_overflow.txt");

    return 0;
}
