#include <stdlib.h>
#include <string.h>

struct cache_line {
    char *value;
};

static struct cache_line cache_line_create(void) {
    struct cache_line line;
    line.value = (char *)malloc(32);
    if (line.value) {
        strcpy(line.value, "stale");
    }
    return line;
}

static int cache_line_score(struct cache_line *line) {
    return line->value[0] == 's';
}

int main(void) {
    struct cache_line line = cache_line_create();
    if (!line.value) {
        return 1;
    }

    free(line.value);
    return cache_line_score(&line) ? 0 : 2;
}
