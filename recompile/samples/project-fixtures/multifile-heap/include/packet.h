#ifndef PROJECT_FIXTURE_PACKET_H
#define PROJECT_FIXTURE_PACKET_H

#include <stddef.h>

struct packet {
    char *payload;
    size_t capacity;
};

struct packet packet_create(size_t capacity);
void packet_copy(struct packet *packet, const char *src, size_t len);
void packet_destroy(struct packet *packet);

#endif
