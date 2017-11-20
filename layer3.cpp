#include <string>
#include <utility>
#include <sstream>
#include <array>
#include <stdexcept>

extern "C" {
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
}

#include "layer3.h"
#include "layer4.h"
#include "arguments.h"
#include "utils.h"

namespace packet_analyzer::layer3 {
    using namespace std;

    string Layer3(const uint8_t* packetL3, int type, size_t size) {
        enum Layer3 { IPv4 = 0x0800, IPv6 = 0x86DD, ICMPv4 = 1, ICMPv6 = 58 };

        using namespace packet_analyzer;
        using namespace packet_analyzer::parameters;

        ostringstream result;

        switch(type) {
            case IPv4:
            {
                const ip* ipv4 = (const ip*)packetL3;

                string src = inet_ntoa(ipv4->ip_src);
                string dst = inet_ntoa(ipv4->ip_dst);

                result << "IPv4: " << src << ' ' << dst << ' ' << (unsigned)ipv4->ip_ttl;

                if (argumentsParser.IsSet("a")) {
                    const string& key = arguments.aggregation;
                    if (key == "srcip") {
                        addAggr(src, size);
                    } else if (key == "dstip") {
                        addAggr(dst, size);
                    }
                }

                // is ICMPv4
                if (ipv4->ip_p == ICMPv4) {
                    // skip IPv4 header
                    const icmphdr* icmp = (const icmphdr*)(packetL3 + IPv4HeaderSize(ipv4));
                    // TODO
                    result << ICMPv4Messages(icmp->type, icmp->code);
                    return result.str();
                }

                type = ipv4->ip_p;
                packetL3 += IPv4HeaderSize(ipv4);
                break;
            }
            case IPv6:
            {
                const ip6_hdr* ip = (const ip6_hdr*)packetL3;

                char buffer[INET6_ADDRSTRLEN];
                string src = inet_ntop(AF_INET6, (void*)(&ip->ip6_src), buffer, INET6_ADDRSTRLEN);
                string dst = inet_ntop(AF_INET6, (void*)(&ip->ip6_dst), buffer, INET6_ADDRSTRLEN);

                // TODO
                if (argumentsParser.IsSet("a")) {
                    const string& key = arguments.aggregation;
                    if (key == "srcip") {
                        addAggr(src, size);
                    } else if (key == "dstip") {
                        addAggr(dst, size);
                    }
                }

                result << "IPv6: " << src << ' ' << dst << ' ' << (unsigned)ip->ip6_hlim;

                uint8_t next;
                auto p = SkipAllIPv6Extensions(ip->ip6_nxt, packetL3);
                next = p.first;
                packetL3 = p.second;

                // is ICMPv6
                if (next == ICMPv6) {
                    const icmp6_hdr* icmp = (const icmp6_hdr*)packetL3;
                    result << ICMPv6Messages(icmp->icmp6_type, icmp->icmp6_code);
                    return result.str();
                } else if (next == NoNextHeader) {
                    return result.str();
                }

                type = next;
                break;
            }
            default: throw InvalidProtocol{"Layer3 invalid protocol: " + to_string(type)};
        }

        if (!IsL4Protocol(type)) return result.str();

        result << " | " << layer4::Layer4(packetL3, type, size);
        return result.str();
    }


    bool IsL4Protocol(uint8_t n) {
        return n == TCP || n == UDP || n == ICMPv6;
    }

    pair<uint8_t, const uint8_t*> SkipAllIPv6Extensions(uint8_t next, const uint8_t* packet) {
        const uint8_t* p = packet + IPv6HeaderSize();
        const ip6_ext* e = (const ip6_ext*)p;

        while (!(IsL4Protocol(next) || next == NoNextHeader)) {
            next = e->ip6e_nxt;
            // skip extension to the next one
            // including first 8 bytes
            p += 8;
            p += e->ip6e_len*8;
            // next extension
            e = (const ip6_ext*)p;
        }

        return {next, p};
    }

    string ICMPv6Messages(uint8_t type, uint8_t code) {
        static ICMPv6ErrorMessages ICMPv6Messages;

        string typeMsg;
        string codeMsg;
        tie(typeMsg, codeMsg) = ICMPv6Messages.MessageFor(type, code);

        if (typeMsg.empty() || codeMsg.empty()) {
            return "";
        }

        return " | ICMPv6: " + to_string(type) + ' ' + to_string(code) + ' ' + typeMsg + ' ' + codeMsg;
    }

    string ICMPv4Messages(uint8_t type, uint8_t code) {
        static ICMPv4ErrorMessages ICMPv4Messages;

        string typeMsg;
        string codeMsg;
        tie(typeMsg, codeMsg) = ICMPv4Messages.MessageFor(type, code);

        if (typeMsg.empty() || codeMsg.empty()) {
            return "";
        }

        return " | ICMPv4: " + to_string(type) + ' ' + to_string(code) + ' ' + typeMsg + ' ' + codeMsg;
    }

    size_t IPv6HeaderSize() { return sizeof(ip6_hdr); }
    size_t IPv4HeaderSize(const ip* header) { return header->ip_hl * 4; }
}
