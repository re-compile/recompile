#include <stdio.h>

int main(void) {
    volatile int *ptr = (int *)0;
    *ptr = 7;
    puts("unreachable");
    return 0;
}
