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
}
