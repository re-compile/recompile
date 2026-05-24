#include <stdio.h>

int main(void) {
    puts("about to segfault");
    fflush(stdout);
    volatile int *ptr = (int *)0;
    return *ptr;
}
