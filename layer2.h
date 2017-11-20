#pragma once 

#include <string>

extern "C" {
#include <netinet/if_ether.h>
#include <netinet/ether.h>
}

namespace packet_analyzer::layer2 {
    using namespace std;

    string PacketLayer2(const uint8_t* packet, size_t packetLen);
    pair<string, string> SrcDstMAC(const ether_header& ether);
    string PrintSrcDstMAC(const string& srcMAC, const string& dstMAC);
    string PrintMAC(const ether_addr& mac);

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

        string vlan_info(const uint8_t* packet);
        pair<const uint8_t*, int> vlan_skip(const uint8_t* packet);
    }
}
