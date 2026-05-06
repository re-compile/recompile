#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char path[] = "/tmp/recompile_fd_leak_case_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }

    unlink(path);
    const char *message = "fd leak sample\n";
    write(fd, message, strlen(message));

    return 0;
}
