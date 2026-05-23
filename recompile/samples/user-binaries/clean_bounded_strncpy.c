#include <stdlib.h>
#include <string.h>

int main(void) {
    char *dst = (char *)malloc(64);
    if (!dst) {
        return 1;
    }

    strncpy(dst, "safe prefix", 12);
    dst[63] = '\0';
    free(dst);
    return 0;
}
