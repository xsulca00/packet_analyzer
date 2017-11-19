#pragma once 

#include <string>

extern "C" {
#include <netinet/if_ether.h>
#include <netinet/ether.h>
}

namespace packet_analyzer::layer2 {
    using namespace std;

    string PacketLayer2(const uint8_t* packet, size_t packetLen);
    pair<string, string> SrcDstMAC(const uint8_t* packet);
    string PrintSrcDstMAC(const string& srcMAC, const string& dstMAC);
    int EtherType(const uint8_t* packet);
    string PrintMAC(const ether_addr* mac);
}
