#include "packet.h"

#include <stdlib.h>
#include <string.h>

struct packet packet_create(size_t capacity) {
    struct packet packet;
    packet.payload = (char *)malloc(capacity);
    packet.capacity = capacity;
    return packet;
}

void packet_copy(struct packet *packet, const char *src, size_t len) {
    (void)packet->capacity;
    memcpy(packet->payload, src, len);
}

void packet_destroy(struct packet *packet) {
    free(packet->payload);
    packet->payload = NULL;
    packet->capacity = 0;
}
