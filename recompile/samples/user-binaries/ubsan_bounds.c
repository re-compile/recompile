#include <stdio.h>

int main(void) {
    int values[4] = {1, 2, 3, 4};
    volatile int index = 4;
    printf("%d\n", values[index]);
    return 0;
}
