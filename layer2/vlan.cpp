#include <string>

extern "C" {
#include <arpa/inet.h>
}

#include "vlan.h"

namespace packet_analyzer::layer2 {
    string InfoVLAN(const uint8_t* packet) {
        uint32_t bytes {ntohl(*(uint32_t*)(packet + 12))};

        HeaderVLAN vlan {*(HeaderVLAN*)&bytes};
        return ' ' + to_string(vlan.tci.vid);
    }

    pair<const uint8_t*, int> SkipVLAN(const uint8_t* packet) {
        int packetType {ntohs(*(uint16_t*)(packet + 16))};
        packet += 4;

        return make_pair(packet, packetType);
    }
}
