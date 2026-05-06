#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char path[] = "/tmp/recompile_clean_fd_close_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }

    unlink(path);
    const char *message = "closed fd sample\n";
    write(fd, message, strlen(message));

    if (close(fd) != 0) {
        perror("close");
        return 1;
    }

    return 0;
}
