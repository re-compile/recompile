#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)realloc(NULL, 32);
    if (!buf) {
        return 1;
    }

    memset(buf, 0x44, 32);
    free(buf);
    return 0;
}
