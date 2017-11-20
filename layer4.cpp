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
    string Layer4(const uint8_t* packetL4, int type, size_t size) {
        enum Layer4 { TCP = 6, UDP = 17 };

        using arguments::options;
        using arguments::addAggr;

        ostringstream result;
        string srcPort;
        string dstPort;

        switch (type) {
            case TCP:
            {
                const tcphdr* tcp = (const tcphdr*)packetL4;

                srcPort = to_string(ntohs(tcp->th_sport));
                dstPort = to_string(ntohs(tcp->th_dport));

                // TODO
                if (options.aggregation.second) {
                    const string& key = options.aggregation.first;
                    if (key == "srcport") {
                        addAggr(srcPort, size);
                    } else if (key == "dstport") {
                        addAggr(dstPort, size);
                    }
                }

                result << "TCP: " << srcPort << ' ' << dstPort << ' '
                       << ntohl(tcp->th_seq) << ' ' << ntohl(tcp->th_ack) << ' ' 
                       << TCPFlags(tcp->th_flags);
                break;
            }
            case UDP:
            {
                const udphdr* udp = (const udphdr*)packetL4;

                srcPort = to_string(ntohs(udp->uh_sport));
                dstPort = to_string(ntohs(udp->uh_dport));

                // TODO
                if (options.aggregation.second) {
                    const string& key = options.aggregation.first;
                    if (key == "srcport") {
                        addAggr(srcPort, size);
                    } else if (key == "dstport") {
                        addAggr(dstPort, size);
                    }
                }

                result << "UDP: " << srcPort << ' ' << dstPort;
                break;
            }
            // TODO
            default: throw utils::BadProtocolType{"Layer4: Unknown protocol type: " + to_string(type)};
        }

        return result.str();
    }

    string TCPFlags(uint8_t f) {
        string s;

        s += (f & CWR) ? 'C' : '.';
        s += (f & ECE) ? 'E' : '.';
        s += (f & URG) ? 'U' : '.';
        s += (f & ACK) ? 'A' : '.';
        s += (f & PSH) ? 'P' : '.';
        s += (f & RST) ? 'R' : '.';
        s += (f & SYN) ? 'S' : '.';
        s += (f & FIN) ? 'F' : '.';

        return s;
    }
}
