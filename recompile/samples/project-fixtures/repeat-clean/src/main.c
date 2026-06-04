#include <stdlib.h>
#include <string.h>

int main(void) {
    char *dst = malloc(64);
    if (dst == NULL) {
        return 2;
    }

    const char *payload = "repeat fixture clean payload";
    memcpy(dst, payload, strlen(payload) + 1);
    int rc = strcmp(dst, payload) == 0 ? 0 : 1;
    free(dst);
    return rc;
}
