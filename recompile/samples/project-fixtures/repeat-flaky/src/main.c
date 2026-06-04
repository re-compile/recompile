#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_attempt(const char *path) {
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }

    int attempt = 0;
    if (fscanf(file, "%d", &attempt) != 1) {
        attempt = 0;
    }
    fclose(file);
    return attempt;
}

static int write_attempt(const char *path, int attempt) {
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        return -1;
    }

    int rc = fprintf(file, "%d\n", attempt) < 0 ? -1 : 0;
    if (fclose(file) != 0) {
        rc = -1;
    }
    return rc;
}

static int run_clean_path(void) {
    char *dst = malloc(64);
    if (dst == NULL) {
        return 2;
    }

    const char *payload = "repeat fixture deterministic clean path";
    memcpy(dst, payload, strlen(payload) + 1);
    int rc = strcmp(dst, payload) == 0 ? 0 : 1;
    free(dst);
    return rc;
}

static int run_failing_path(void) {
    char *dst = malloc(8);
    if (dst == NULL) {
        return 2;
    }

    char src[32];
    memset(src, 'X', sizeof(src));
    memcpy(dst, src, sizeof(src));

    int rc = dst[0] == 'X' ? 0 : 1;
    free(dst);
    return rc;
}

int main(void) {
    const char *state_path = "attempt-state.txt";
    int attempt = read_attempt(state_path);
    if (write_attempt(state_path, attempt + 1) != 0) {
        return 3;
    }

    if (attempt % 3 == 1) {
        return run_failing_path();
    }
    return run_clean_path();
}
