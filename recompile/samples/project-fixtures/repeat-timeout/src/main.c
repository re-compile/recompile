#include <time.h>

int main(void) {
    const struct timespec delay = {
        .tv_sec = 10,
        .tv_nsec = 0,
    };

    while (1) {
        nanosleep(&delay, NULL);
    }

    return 0;
}
