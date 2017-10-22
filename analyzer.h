#pragma once

#include <string>
#include <stdexcept>

extern "C" {
#include <pcap.h>
}

#include "pcap_ptr.h"

namespace PacketAnalyzer { namespace PCAP {
    using namespace std;

    class Analyzer {
    public:
        enum class Packet { Ethernet, IEEE_802_1Q, IEEE_802_1ad, 
                            IPv4, IPv6, ICMPv4, ICMPv6,
                            TCP, UDP };

        explicit Analyzer(const string& name)
            : pcapFile{name}
        {}

        bool NextPacket() {
            packet = pcap_next(pcapFile, &header);
            return packet;
        }

        const u_char* Packet() const { return packet; }
        const pcap_pkthdr& Header() const { return header; };

    private:
        const u_char* packet {nullptr};
        pcap_pkthdr header {};
        PcapPtr pcapFile;
    };
}}
