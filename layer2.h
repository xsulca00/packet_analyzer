#pragma once 

#include <string>

extern "C" {
#include <netinet/if_ether.h>
#include <netinet/ether.h>
}

namespace packet_analyzer::layer2 {
    using namespace std;

    string Layer2(const uint8_t* packet, size_t size);
    string MACtoString(const ether_addr* mac);

    namespace vlan {
        struct Tci {
            unsigned vid    :12;
            bool     dei    :1;
            unsigned pcp    :3;
        } __attribute__((packed));

        struct vlan_hdr {
            Tci tci;
            uint16_t tpid;
        } __attribute__((packed));

        string VlanInfo(const uint8_t* packet);
        pair<const uint8_t*, int> VlanSkip(const uint8_t* packet);
    }
}
