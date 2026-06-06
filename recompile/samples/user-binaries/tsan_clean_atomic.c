#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>

static atomic_int shared_counter;

static void *increment_counter(void *arg) {
    (void)arg;
    for (int i = 0; i < 100000; i++) {
        atomic_fetch_add_explicit(&shared_counter, 1, memory_order_relaxed);
    }
    return NULL;
}

int main(void) {
    pthread_t first;
    pthread_t second;

    atomic_init(&shared_counter, 0);
    if (pthread_create(&first, NULL, increment_counter, NULL) != 0) {
        return 1;
    }
    if (pthread_create(&second, NULL, increment_counter, NULL) != 0) {
        return 1;
    }

    pthread_join(first, NULL);
    pthread_join(second, NULL);
    printf("shared_counter=%d\n", atomic_load_explicit(&shared_counter, memory_order_relaxed));
    return 0;
}
