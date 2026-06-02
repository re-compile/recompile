#include <stdlib.h>
#include <string.h>

int main(void) {
    char *dst = (char *)malloc(32);
    if (!dst) {
        return 1;
    }

    char src[32];
    memset(src, 'I', sizeof(src));
    memcpy(dst + 24, src, sizeof(src));

    free(dst);
    return 0;
}
