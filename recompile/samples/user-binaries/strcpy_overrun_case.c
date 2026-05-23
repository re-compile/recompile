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

static void label_assign(struct label *label, const char *src) {
    strcpy(label->text, src);
}

int main(void) {
    struct label label = label_new(12);
    const char *source = "this string is longer than the label buffer";
    label_assign(&label, source);
    free(label.text);
    return 0;
}
