#include <limits.h>
#include <stdio.h>

int main(void) {
    volatile int value = INT_MAX;
    int result = value + 1;
    printf("%d\n", result);
    return 0;
}
