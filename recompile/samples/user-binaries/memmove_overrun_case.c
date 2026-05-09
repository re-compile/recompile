#include <stdlib.h>
#include <string.h>

struct packet {
    char *payload;
    size_t capacity;
};

static struct packet packet_new(size_t capacity) {
    struct packet pkt;
    pkt.payload = (char *)malloc(capacity);
    pkt.capacity = capacity;
    return pkt;
}

static void packet_shift(struct packet *pkt, const char *src, size_t len) {
    memmove(pkt->payload, src, len);
}

int main(void) {
    struct packet pkt = packet_new(24);
    char incoming[80];
    memset(incoming, 'M', sizeof(incoming));
    packet_shift(&pkt, incoming, sizeof(incoming));
    free(pkt.payload);
    return 0;
}
