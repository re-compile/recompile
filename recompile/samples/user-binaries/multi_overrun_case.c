#include <stdlib.h>
#include <string.h>

struct buffer {
    char *data;
    size_t capacity;
};

static struct buffer buffer_new(size_t capacity) {
    struct buffer buf;
    buf.data = (char *)malloc(capacity);
    buf.capacity = capacity;
    return buf;
}

static void buffer_fill(struct buffer *buf, const char *src, size_t len) {
    memcpy(buf->data, src, len);
}

int main(void) {
    struct buffer first = buffer_new(16);
    struct buffer second = buffer_new(24);
    char source_a[64];
    char source_b[80];

    memset(source_a, 'A', sizeof(source_a));
    memset(source_b, 'B', sizeof(source_b));

    buffer_fill(&first, source_a, sizeof(source_a));
    buffer_fill(&second, source_b, sizeof(source_b));

    return first.data == NULL || second.data == NULL;
}
