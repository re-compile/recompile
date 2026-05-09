#include <stdlib.h>
#include <string.h>

struct scratch {
    char *bytes;
    size_t capacity;
};

static struct scratch scratch_new(size_t capacity) {
    struct scratch scratch;
    scratch.bytes = (char *)malloc(capacity);
    scratch.capacity = capacity;
    return scratch;
}

static void scratch_clear(struct scratch *scratch, size_t len) {
    memset(scratch->bytes, 0, len);
}

int main(void) {
    struct scratch scratch = scratch_new(16);
    scratch_clear(&scratch, 64);
    free(scratch.bytes);
    return 0;
}
