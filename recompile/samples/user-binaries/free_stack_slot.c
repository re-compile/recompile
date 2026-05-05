#include <stdlib.h>

struct request {
    int status;
    int retries;
};

static void request_dispose(struct request *req) {
    free(req);
}

int main(void) {
    struct request req = {
        .status = 200,
        .retries = 1,
    };
    request_dispose(&req);
    return 0;
}
