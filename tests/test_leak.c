/*
 * test_leak.c – Memory Leak demonstration
 *
 * Bug: parse_records() allocates a records[] array on every call,
 * but on the early-return error paths (lines 38 and 45) it returns
 * without freeing the allocation.  Only the happy path frees it.
 * ASTrace AI should identify all three return paths and flag the
 * two that skip free().
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RECORDS 64
#define RECORD_LEN  128

typedef struct {
    char data[RECORD_LEN];
    int  id;
} Record;

int parse_records(const char *filename, int expected_count)
{
    if (!filename) {
        return -1;   /* no leak here – nothing allocated yet */
    }

    Record *records = malloc(sizeof(Record) * MAX_RECORDS);
    if (!records) {
        return -1;
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        /* BUG: returns without freeing records */
        return -1;
    }

    int count = 0;
    while (count < MAX_RECORDS && fgets(records[count].data, RECORD_LEN, fp)) {
        records[count].id = count;
        count++;
    }
    fclose(fp);

    if (count != expected_count) {
        /* BUG: returns without freeing records */
        fprintf(stderr, "Expected %d records, got %d\n", expected_count, count);
        return -1;
    }

    printf("Parsed %d records successfully\n", count);
    free(records);   /* only the happy path frees */
    return count;
}

int main(void)
{
    int result = parse_records("/tmp/data.txt", 10);
    if (result < 0) {
        fprintf(stderr, "parse_records failed\n");
        return 1;
    }
    return 0;
}
