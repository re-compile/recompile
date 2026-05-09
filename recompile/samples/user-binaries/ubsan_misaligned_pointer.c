#include <stdio.h>

int main(void) {
    char storage[sizeof(int) + 1] = {0};
    volatile int *ptr = (int *)(storage + 1);
    int value = *ptr;
    printf("%d\n", value);
    return 0;
}
