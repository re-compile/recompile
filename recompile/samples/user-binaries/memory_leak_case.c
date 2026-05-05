#include <stdlib.h>
#include <string.h>

struct session {
    char *scratch;
};

static struct session session_open(void) {
    struct session session;
    session.scratch = (char *)malloc(48);
    if (session.scratch) {
        memset(session.scratch, 0, 48);
    }
    return session;
}

int main(void) {
    struct session session = session_open();
    if (!session.scratch) {
        return 1;
    }

    session.scratch[0] = 'x';
    return 0;
}
