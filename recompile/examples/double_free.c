#include <stdlib.h>

int main() {
    char *p = (char*)malloc(16);
    free(p);
    free(p); // double free
    return 0;
}


