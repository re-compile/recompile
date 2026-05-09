#include <stdio.h>

int main(void) {
    volatile int shift = 32;
    int result = 1 << shift;
    printf("%d\n", result);
    return 0;
}
