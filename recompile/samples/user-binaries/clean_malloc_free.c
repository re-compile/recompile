#include <stdlib.h>

int main(void) {
    void *ptr = malloc(32);
    free(ptr);
    return 0;
}
