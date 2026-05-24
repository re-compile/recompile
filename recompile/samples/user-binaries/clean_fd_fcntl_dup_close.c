#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char path[] = "/tmp/recompile_clean_fd_fcntl_dup_close_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    unlink(path);

    int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) {
        perror("fcntl F_DUPFD_CLOEXEC");
        close(fd);
        return 1;
    }

    const char *message = "fcntl dup close sample\n";
    write(duplicate, message, strlen(message));

    if (close(fd) != 0) {
        perror("close fd");
        return 1;
    }
    if (close(duplicate) != 0) {
        perror("close duplicate");
        return 1;
    }
    return 0;
}
