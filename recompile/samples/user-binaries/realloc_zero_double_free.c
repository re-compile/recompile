#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) {
        return 1;
    }

    memset(buf, 0x46, 32);
    char *released = (char *)realloc(buf, 0);
    if (!released) {
        free(buf);
    } else {
        free(released);
    }
    return 0;
}
