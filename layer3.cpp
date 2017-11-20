#include <string>
#include <utility>
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

        using arguments::addAggr;
        using arguments::options;

        string msg;

        string SrcIP;
        string DstIP;

        switch(type) {
            case IPv4:
            {
                const ip* ipv4 = (const ip*)packetL3;

                string src = inet_ntoa(ipv4->ip_src);
                string dst = inet_ntoa(ipv4->ip_dst);
                msg += "IPv4: " + src + ' ' + dst + ' ' + to_string(ipv4->ip_ttl);

                if (options.aggregation.second) {
                    const string& key = options.aggregation.first;
                    if (key == "srcip") {
                        addAggr(src, size);
                    } else if (key == "dstip") {
                        addAggr(dst, size);
                    }
                }

                // is ICMPv4
                if (ipv4->ip_p == ICMPv4) {
                    // skip IPv4 header
                    const icmphdr* icmp = (const icmphdr*)(packetL3 + HeaderLenIPv4(ipv4));
                    return msg + PrintICMPv4(icmp->type, icmp->code);
                }

                packetL3 += HeaderLenIPv4(ipv4);
                type = ipv4->ip_p;

                break;
            }
            case IPv6:
            {
                const ip6_hdr* ip = (const ip6_hdr*)packetL3;

                char buffer[INET6_ADDRSTRLEN];
                string src = inet_ntop(AF_INET6, (void*)(&ip->ip6_src), buffer, INET6_ADDRSTRLEN);
                string dst = inet_ntop(AF_INET6, (void*)(&ip->ip6_dst), buffer, INET6_ADDRSTRLEN);

                if (options.aggregation.second) {
                    const string& key = options.aggregation.first;
                    if (key == "srcip") {
                        addAggr(src, size);
                    } else if (key == "dstip") {
                        addAggr(dst, size);
                    }
                }

                msg += "IPv6: " + src + ' ' + dst + ' ' + to_string(ip->ip6_hlim);

                uint8_t next;
                tie(next, packetL3) = SkipExtensions(packetL3);

                // is ICMPv6
                if (next == ICMPv6) {
                    const icmp6_hdr* icmp = (const icmp6_hdr*)packetL3;
                    return msg + PrintICMPv6(icmp->icmp6_type, icmp->icmp6_code);
                } else if (next == NoNextHeader) {
                    return msg;
                }

                type = next;
                break;
            }
            default: throw utils::BadProtocolType{"Layer3: Unknown protocol type: " + to_string(type)};
        }

        if (!IsL4Protocol(type)) return msg;

        return msg + " | " + layer4::PacketLayer4(packetL3, type, size);
    }

    size_t HeaderLenIPv4(const ip* header) { return header->ip_hl * 4; }

    bool IsL4Protocol(uint8_t n) {
        return n == TCP || n == UDP || n == ICMPv6;
    }

    pair<uint8_t, const uint8_t*> SkipExtensions(const uint8_t* packet) {
        const ip6_hdr* ip = (const ip6_hdr*)packet;
        uint8_t next = ip->ip6_nxt;
        const uint8_t* p = packet + HeaderLenIPv6();

        const ip6_ext* e {reinterpret_cast<const ip6_ext*>(p)};


        for (; !(IsL4Protocol(next) || next == NoNextHeader);) {
            next = e->ip6e_nxt;
            // skip extension to the next one
            p += (e->ip6e_len + 1)*8;
            e = (const ip6_ext*)p;
        }

        return make_pair(next, p);
    }

    string PrintICMPv4(uint8_t type, uint8_t code) {
        static ICMPv4ErrorMessages ICMPv4Messages;

        string typeMsg;
        string codeMsg;
        tie(typeMsg, codeMsg) = ICMPv4Messages.MessageFor(type, code);

        if (typeMsg.empty() || codeMsg.empty()) {
            return "";
        }

        return " | ICMPv4: " + to_string(type) + ' ' + to_string(code) + ' ' + typeMsg + ' ' + codeMsg;
    }

    string PrintICMPv6(uint8_t type, uint8_t code) {
        static ICMPv6ErrorMessages ICMPv6Messages;

        string typeMsg;
        string codeMsg;
        tie(typeMsg, codeMsg) = ICMPv6Messages.MessageFor(type, code);

        if (typeMsg.empty() || codeMsg.empty()) {
            return "";
        }

        return " | ICMPv6: " + to_string(type) + ' ' + to_string(code) + ' ' + typeMsg + ' ' + codeMsg;
    }


    const uint8_t* SkipICMPv4Header(const uint8_t* packetL3) {
        return packetL3 + sizeof(icmphdr);
    }

    const uint8_t* SkipICMPv6Header(const uint8_t* packetL3) {
        return packetL3 + sizeof(icmp6_hdr);
    }
}
