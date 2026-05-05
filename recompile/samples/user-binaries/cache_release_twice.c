#include <stdlib.h>

struct cache_entry {
    char *buffer;
};

static struct cache_entry cache_entry_create(void) {
    struct cache_entry entry;
    entry.buffer = (char *)malloc(64);
    return entry;
}

static void cache_entry_release(struct cache_entry *entry) {
    free(entry->buffer);
}

int main(void) {
    struct cache_entry entry = cache_entry_create();
    cache_entry_release(&entry);
    cache_entry_release(&entry);
    return 0;
}
