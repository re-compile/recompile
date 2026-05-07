#include "buglib.h"

#include <stdlib.h>
#include <string.h>

int project_fixture_shared_copy(void) {
    char *buffer = (char *)malloc(20);
    if (!buffer) {
        return 1;
    }
    char source[68];
    memset(source, 'L', sizeof(source));
    memcpy(buffer, source, sizeof(source));
    free(buffer);
    return 0;
}
