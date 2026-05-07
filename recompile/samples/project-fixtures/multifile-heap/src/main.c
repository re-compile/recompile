#include "packet.h"

#include <string.h>

int main(void) {
    struct packet packet = packet_create(32);
    if (!packet.payload) {
        return 1;
    }

    char incoming[96];
    memset(incoming, 'A', sizeof(incoming));
    packet_copy(&packet, incoming, sizeof(incoming));
    packet_destroy(&packet);
    return 0;
}
