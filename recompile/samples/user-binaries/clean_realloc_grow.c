#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(16);
    if (!buf) {
        return 1;
    }

    char *grown = (char *)realloc(buf, 64);
    if (!grown) {
        free(buf);
        return 1;
    }

    memset(grown, 0x41, 64);
    free(grown);
    return 0;
}
