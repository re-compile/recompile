#include <pthread.h>
#include <stdio.h>

static int shared_counter;

static void *increment_counter(void *arg) {
    (void)arg;
    for (int i = 0; i < 100000; i++) {
        shared_counter++;
    }
    return NULL;
}

int main(void) {
    pthread_t first;
    pthread_t second;

    if (pthread_create(&first, NULL, increment_counter, NULL) != 0) {
        return 1;
    }
    if (pthread_create(&second, NULL, increment_counter, NULL) != 0) {
        return 1;
    }

    pthread_join(first, NULL);
    pthread_join(second, NULL);
    printf("shared_counter=%d\n", shared_counter);
    return 0;
}
