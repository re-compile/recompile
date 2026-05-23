#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *copy = strdup("safe duplicate");
    if (!copy) {
        return 1;
    }

    memset(copy, 0x4c, strlen(copy));
    free(copy);
    return 0;
}
