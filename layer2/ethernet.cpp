#include <string>
#include <tuple>
#include <utility>
#include <iomanip>
#include <stdexcept>
#include <sstream>

extern "C" {
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
}

#include "ethernet.h"
#include "vlan.h"
#include "../arguments.h"
#include "../layer3/ip.h"
#include "../utils.h"

namespace packet_analyzer::layer2 {
    string PacketLayer2(const uint8_t* packet, size_t packetLen) {
        enum class Layer2 { IEEE_802_1q  = 0x8100, IEEE_802_1ad = 0x88a8 };

        using arguments::options;
        using arguments::addAggr;

        string msg;
        const ether_header& ether {*reinterpret_cast<const ether_header*>(packet)};

        string srcMAC;
        string dstMAC;
        tie(srcMAC, dstMAC) = SrcDstMAC(ether);

        msg += PrintSrcDstMAC(srcMAC, dstMAC);

        if (options.aggregation.second) {
            const string& key {options.aggregation.first};
            if (key == "srcmac") {
                addAggr(srcMAC, packetLen);
            } else if (key == "dstmac") {
                addAggr(dstMAC, packetLen);
            }
        }

        auto packetType = ntohs(ether.ether_type);
        switch (static_cast<Layer2>(packetType)) {
            case Layer2::IEEE_802_1q:
            {
                msg += InfoVLAN(packet);
                tie(packet, packetType) = SkipVLAN(packet);
                break;
            }
            case Layer2::IEEE_802_1ad:
            {
                msg += InfoVLAN(packet);
                tie(packet, packetType) = SkipVLAN(packet);
                msg += InfoVLAN(packet);
                tie(packet, packetType) = SkipVLAN(packet);
                break;
            }
            default: utils::BadProtocolType{"Layer2: Unknown protocol type: " + to_string(packetType)};
        }

        constexpr auto ipOffset {14};
        packet = next(packet, ipOffset);
        return msg + " | " + layer3::PacketLayer3(packet, packetType, packetLen);
    }

    pair<string, string> SrcDstMAC(const ether_header& ether) {
        string SrcMAC {PrintMAC(*reinterpret_cast<const ether_addr*>(&ether.ether_shost))};
        string DstMAC {PrintMAC(*reinterpret_cast<const ether_addr*>(&ether.ether_dhost))};

        return make_pair(SrcMAC, DstMAC);
    }

    string PrintSrcDstMAC(const string& srcMAC, const string& dstMAC) {
        return "Ethernet: " + srcMAC + ' ' + dstMAC;
    }

    string PrintMAC(const ether_addr& mac) {
        const uint8_t* octets {&mac.ether_addr_octet[0]};

        ostringstream ss;
        ss.fill('0');
        ss << hex << setw(2) << unsigned{octets[0]} << ':'
                  << setw(2) << unsigned{octets[1]} << ':'
                  << setw(2) << unsigned{octets[2]} << ':'
                  << setw(2) << unsigned{octets[3]} << ':'
                  << setw(2) << unsigned{octets[4]} << ':'
                  << setw(2) << unsigned{octets[5]};
        return ss.str();
    }
}
