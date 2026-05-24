#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char first[] = "/tmp/recompile_clean_fd_dup2_first_XXXXXX";
    char second[] = "/tmp/recompile_clean_fd_dup2_second_XXXXXX";
    int source = mkstemp(first);
    int target = mkstemp(second);
    if (source < 0 || target < 0) {
        perror("mkstemp");
        if (source >= 0) close(source);
        if (target >= 0) close(target);
        return 1;
    }
    unlink(first);
    unlink(second);

    if (dup2(source, target) != target) {
        perror("dup2");
        close(source);
        close(target);
        return 1;
    }

    const char *message = "dup2 replace sample\n";
    write(target, message, strlen(message));

    if (close(source) != 0) {
        perror("close source");
        return 1;
    }
    if (close(target) != 0) {
        perror("close target");
        return 1;
    }
    return 0;
}
