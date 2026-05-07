#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_payload(const char *path, char *buffer, size_t capacity) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        return -1;
    }
    size_t read_count = fread(buffer, 1, capacity, file);
    fclose(file);
    return (int)read_count;
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "trigger") != 0) {
        return 3;
    }

    char incoming[96];
    int len = read_payload(argv[2], incoming, sizeof(incoming));
    if (len <= 0) {
        return 4;
    }

    char *target = (char *)malloc(24);
    if (!target) {
        return 1;
    }
    memcpy(target, incoming, (size_t)len);
    free(target);
    return 0;
}
