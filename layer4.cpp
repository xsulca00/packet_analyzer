#include <string>
#include <sstream>
#include <stdexcept>
#include <utility>

extern "C" {
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
}

#include "layer4.h"
#include "arguments.h"
#include "utils.h"

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

    string TcpFlagsString(uint8_t flags) {
        Flags f {static_cast<Flags>(flags)};
        string s;

        if ((f & Flags::CWR) != Flags::NotSet)
            s += 'C';
        else
            s += '.';

        if ((f & Flags::ECE) != Flags::NotSet)
            s += 'E';
        else
            s += '.';

        if ((f & Flags::URG) != Flags::NotSet)
            s += 'U';
        else
            s += '.';

        if ((f & Flags::ACK) != Flags::NotSet)
            s += 'A';
        else
            s += '.';

        if ((f & Flags::PSH) != Flags::NotSet)
            s += 'P';
        else
            s += '.';

        if ((f & Flags::RST) != Flags::NotSet)
            s += 'R';
        else
            s += '.';

        if ((f & Flags::SYN) != Flags::NotSet)
            s += 'S';
        else
            s += '.';

        if ((f & Flags::FIN) != Flags::NotSet)
            s += 'F';
        else
            s += '.';

        return s;
    }
}
