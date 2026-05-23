#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) {
        return 1;
    }

    memset(buf, 0x42, 32);
    char *failed = (char *)realloc(buf, SIZE_MAX / 2);
    if (failed) {
        free(failed);
        return 0;
    }

    memset(buf, 0x43, 32);
    free(buf);
    return 0;
}
