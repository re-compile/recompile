#include "store.h"

int main(void) {
    struct store store = store_create(64);
    if (!store.data) {
        return 1;
    }
    int rc = store_write(&store, "bounded fixture payload");
    store_destroy(&store);
    return rc;
}
