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

#include "layer2.h"
#include "layer3.h"
#include "arguments.h"
#include "utils.h"

namespace packet_analyzer::layer2 {
    string Layer2(const uint8_t* packet, size_t size) {
        enum Layer2 { IPv4 = 0x0800, IPv6 = 0x86DD, IEEE_802_1q  = 0x8100, IEEE_802_1ad = 0x88a8 };

        using arguments::options;
        using arguments::addAggr;

        ostringstream result;

        const ether_header* ether = (const ether_header*)packet;
        const size_t SkipToEtherType = 12;
        const size_t SkipToIP = 2;

        string srcMAC = MACtoString((const ether_addr*)(&ether->ether_shost));
        string dstMAC = MACtoString((const ether_addr*)(&ether->ether_dhost));

        result << "Ethernet: " << srcMAC << ' ' << dstMAC;

        // TODO
        if (options.aggregation.second) {
            const string& key {options.aggregation.first};
            if (key == "srcmac") {
                addAggr(srcMAC, size);
            } else if (key == "dstmac") {
                addAggr(dstMAC, size);
            }
        }

        uint16_t type = ntohs(ether->ether_type);
        switch (type) {
            case IEEE_802_1q:
            {
                packet += SkipToEtherType;

                result << vlan::VlanInfo(packet);
                auto p = vlan::VlanSkip(packet);
                packet = p.first;
                type = p.second;

                packet += SkipToIP;
                break;
            }
            case IEEE_802_1ad:
            {
                packet += SkipToEtherType;

                result << vlan::VlanInfo(packet);
                auto p = vlan::VlanSkip(packet);
                packet = p.first;
                type = p.second;

                result << vlan::VlanInfo(packet);
                auto p2 = vlan::VlanSkip(packet);
                packet = p2.first;
                type = p2.second;

                packet += SkipToIP;
                break;
            }
            default: 
            {
                if (type == IPv4 || type == IPv6) {
                    packet += SkipToEtherType + SkipToIP;
                } else {
                    // TODO
                    throw utils::BadProtocolType{"Layer2: Unknown protocol type: " + to_string(type)};
                }
            }
        }

        result << " | " << layer3::Layer3(packet, type, size);

        return result.str();
    }

    string MACtoString(const ether_addr* mac) {
        const uint8_t* octets {mac->ether_addr_octet};

        char buf[100];

        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                      (unsigned char) octets[0],
                      (unsigned char) octets[1],
                      (unsigned char) octets[2],
                      (unsigned char) octets[3],
                      (unsigned char) octets[4],
                      (unsigned char) octets[5]);

        return string{buf};
    }

    namespace vlan {
        string VlanInfo(const uint8_t* packet) {
            uint32_t vlanHdr = ntohl(*(const uint32_t*)(packet));
            const vlan_hdr* vlan {(const vlan_hdr*)(&vlanHdr)};

            return ' ' + to_string(vlan->tci.vid);
        }

        pair<const uint8_t*, int> VlanSkip(const uint8_t* packet) {
            const size_t SkipVlanHeader = sizeof(vlan_hdr);
            int packetType = ntohs(*(const uint16_t*)(packet + SkipVlanHeader));
            packet += SkipVlanHeader;

            return {packet, packetType};
        }
    }
}
