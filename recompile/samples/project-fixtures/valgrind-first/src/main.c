#include <stdlib.h>
#include <string.h>

int main(void) {
    char *value = (char *)malloc(32);
    if (!value) {
        return 1;
    }
    strcpy(value, "stale");
    free(value);
    return value[0] == 's' ? 0 : 2;
}
