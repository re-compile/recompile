#include <string.h>
#include <stdlib.h>

static void makeBuf(char **out) {
    *out = (char*)malloc(32);
}

int main() {
    char *buf = NULL;
    makeBuf(&buf);
    char src[64];
    memset(src, 'A', sizeof(src));
    memcpy(buf, src, 64); // intentional overflow
    free(buf);
    return 0;
}


