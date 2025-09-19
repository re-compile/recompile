#include <stdlib.h>

int main() {
    int x;
    free(&x); // invalid free
    return 0;
}


