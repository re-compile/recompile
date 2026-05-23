#include <stdlib.h>
#include <string.h>

struct label {
    char *text;
    size_t capacity;
};

static struct label label_new(size_t capacity) {
    struct label label;
    label.text = (char *)malloc(capacity);
    label.capacity = capacity;
    return label;
}

static void label_assign_prefix(struct label *label, const char *src, size_t len) {
    strncpy(label->text, src, len);
}

int main(void) {
    struct label label = label_new(16);
    const char *source = "prefix data";
    label_assign_prefix(&label, source, 48);
    free(label.text);
    return 0;
}
