#include <stdlib.h>
#include <string.h>

int main(void) {
    char *dst = (char *)malloc(64);
    if (!dst) {
        return 1;
    }

    memset(dst, 0, 64);
    free(dst);
    return 0;
}
