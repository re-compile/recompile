#ifndef PROJECT_FIXTURE_STORE_H
#define PROJECT_FIXTURE_STORE_H

#include <stddef.h>

struct store {
    char *data;
    size_t capacity;
};

struct store store_create(size_t capacity);
int store_write(struct store *store, const char *src);
void store_destroy(struct store *store);

#endif
