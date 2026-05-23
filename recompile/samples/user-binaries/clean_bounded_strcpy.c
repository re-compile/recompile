#include <stdlib.h>
#include <string.h>

int main(void) {
    char *dst = (char *)malloc(64);
    if (!dst) {
        return 1;
    }

    strcpy(dst, "safe string");
    free(dst);
    return 0;
}
