#include <stdlib.h>
#include <string.h>

int main(void) {
    void *ptr = aligned_alloc(64, 64);
    if (!ptr) {
        return 1;
    }

    memset(ptr, 0x4a, 64);
    free(ptr);
    return 0;
}
