#include <stdlib.h>
#include <string.h>

int main(void) {
    char *dst = malloc(8);
    if (dst == NULL) {
        return 2;
    }

    char src[32];
    memset(src, 'F', sizeof(src));
    memcpy(dst, src, sizeof(src));

    int rc = dst[0] == 'F' ? 0 : 1;
    free(dst);
    return rc;
}
