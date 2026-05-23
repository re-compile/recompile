#include <stdlib.h>
#include <string.h>

int main(void) {
    void *ptr = aligned_alloc(16, 16);
    if (!ptr) {
        return 1;
    }

    memset(ptr, 0x49, 32);
    free(ptr);
    return 0;
}
