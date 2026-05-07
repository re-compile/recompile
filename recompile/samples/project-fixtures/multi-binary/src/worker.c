#include <stdlib.h>
#include <string.h>

int main(void) {
    char *slot = (char *)malloc(16);
    if (!slot) {
        return 1;
    }
    char source[72];
    memset(source, 'W', sizeof(source));
    memcpy(slot, source, sizeof(source));
    free(slot);
    return 0;
}
