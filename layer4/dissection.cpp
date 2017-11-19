#include <string>
#include <sstream>
#include <stdexcept>
#include <utility>

extern "C" {
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
}

#include "dissection.h"
#include "tcp.h"
#include "../arguments.h"
#include "../utils.h"

namespace packet_analyzer::layer4 {
    string PacketLayer4(const uint8_t* packetL4, int packetType, size_t packetLen) {
        enum class Layer4 { TCP = 6, UDP = 17 };

        using arguments::options;
        using arguments::addAggr;

        switch (static_cast<Layer4>(packetType)) {
            case Layer4::TCP:
            {
                const tcphdr& tcp {*reinterpret_cast<const tcphdr*>(packetL4)};

                string srcPort {to_string(ntohs(tcp.th_sport))};
                string dstPort {to_string(ntohs(tcp.th_dport))};

                if (options.aggregation.second) {
                    const string& key {options.aggregation.first};
                    if (key == "srcport") {
                        addAggr(srcPort, packetLen);
                    } else if (key == "dstport") {
                        addAggr(dstPort, packetLen);
                    }
                }

                ostringstream ss;
                ss  << "TCP: " << srcPort << ' ' << dstPort << ' '
                    << ntohl(tcp.th_seq) << ' ' << ntohl(tcp.th_ack) << ' ' << TcpFlagsString(tcp.th_flags);
                return ss.str();
            }
            case Layer4::UDP:
            {
                const udphdr& udp {*reinterpret_cast<const udphdr*>(packetL4)};

                string srcPort {to_string(ntohs(udp.uh_sport))};
                string dstPort {to_string(ntohs(udp.uh_dport))};

                if (options.aggregation.second) {
                    const string& key {options.aggregation.first};
                    if (key == "srcport") {
                        addAggr(srcPort, packetLen);
                    } else if (key == "dstport") {
                        addAggr(dstPort, packetLen);
                    }
                }

                ostringstream ss;
                ss << "UDP: " << srcPort << ' ' << dstPort;
                return ss.str();
            }
            default: throw utils::BadProtocolType{"Layer4: Unknown protocol type: " + to_string(packetType)};
        }
    }
}
