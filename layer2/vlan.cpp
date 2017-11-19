#include <string>

extern "C" {
#include <arpa/inet.h>
}

#include "vlan.h"

namespace packet_analyzer::layer2 {
    string InfoVLAN(const uint8_t* packet) {
        constexpr size_t VlanOffset {12};
        uint32_t vlanHdr {ntohl(*reinterpret_cast<const uint32_t*>(next(packet, VlanOffset)))};

        HeaderVLAN vlan {*reinterpret_cast<HeaderVLAN*>(&vlanHdr)};
        return ' ' + to_string(vlan.tci.vid);
    }

    pair<const uint8_t*, int> SkipVLAN(const uint8_t* packet) {
        constexpr size_t VlanOffsetPlusSize {12 + sizeof(HeaderVLAN)};
        int packetType {ntohs(*reinterpret_cast<const uint16_t*>(next(packet, VlanOffsetPlusSize)))};
        packet = next(packet, 4);

        return make_pair(packet, packetType);
    }
}
