#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char path[] = "/tmp/recompile_fd_dup_leak_case_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    unlink(path);

    int duplicate = dup(fd);
    if (duplicate < 0) {
        perror("dup");
        close(fd);
        return 1;
    }

    const char *message = "dup leak sample\n";
    write(duplicate, message, strlen(message));

    if (close(fd) != 0) {
        perror("close fd");
        return 1;
    }

    return 0;
}
