#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *copy = strdup("short");
    if (!copy) {
        return 1;
    }

    memset(copy, 0x4b, 16);
    free(copy);
    return 0;
}
