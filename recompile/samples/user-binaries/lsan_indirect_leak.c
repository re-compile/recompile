#include <stdlib.h>
#include <string.h>

struct cache_node {
    char *payload;
};

int main(void) {
    struct cache_node *node = (struct cache_node *)malloc(sizeof(struct cache_node));
    if (!node) {
        return 1;
    }

    node->payload = (char *)malloc(64);
    if (!node->payload) {
        return 1;
    }

    memset(node->payload, 0, 64);
    return 0;
}
