#include <stdlib.h>
#include <string.h>

int main(void) {
    void *ptr = NULL;
    if (posix_memalign(&ptr, 64, 16) != 0) {
        return 1;
    }

    memset(ptr, 0x47, 32);
    free(ptr);
    return 0;
}
