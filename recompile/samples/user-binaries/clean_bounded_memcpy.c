#include <stdlib.h>
#include <string.h>

int main(void) {
    char *dst = (char *)malloc(64);
    if (!dst) {
        return 1;
    }

    const char *src = "safe copy";
    memcpy(dst, src, strlen(src) + 1);
    free(dst);
    return 0;
}
