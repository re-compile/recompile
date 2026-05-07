#include <stdlib.h>
#include <string.h>

int main(void) {
    char *slot = (char *)malloc(32);
    if (!slot) {
        return 1;
    }
    memcpy(slot, "ok", 3);
    free(slot);
    return 0;
}
