#include "store.h"

#include <stdlib.h>
#include <string.h>

struct store store_create(size_t capacity) {
    struct store store;
    store.data = (char *)calloc(capacity, 1);
    store.capacity = capacity;
    return store;
}

int store_write(struct store *store, const char *src) {
    size_t len = strlen(src);
    if (len + 1 > store->capacity) {
        return 2;
    }
    memcpy(store->data, src, len + 1);
    return 0;
}

void store_destroy(struct store *store) {
    free(store->data);
    store->data = NULL;
    store->capacity = 0;
}
