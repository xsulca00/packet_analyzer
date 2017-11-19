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

#include "ip.h"
#include "../layer4/dissection.h"
#include "../arguments.h"
#include "../utils.h"

namespace packet_analyzer::layer3 {
    using namespace std;

    unordered_map<TupleToHashForIPv4, FragmentInfo> fragments {};

    string PacketLayer3(const uint8_t* packetL3, int packetType, size_t packetLen) {
        enum class Layer3 { IPv4 = ETHERTYPE_IP, IPv6 = ETHERTYPE_IPV6, ICMPv4 = 1 };

        using arguments::addAggr;

        string msg;

        string SrcIP;
        string DstIP;

        using arguments::options;

        switch(static_cast<Layer3>(packetType)) {
            case Layer3::IPv4:
            {
                const ip& packet {*(ip*)packetL3};

                // TODO: rfc 815 algorithm
                if (IsFragmented(packet)) {
                    size_t dataLen {ntohs(packet.ip_len) - HeaderLenIPv4(packet)};
                    uint16_t offset {ntohs(packet.ip_off)};

                    FragmentInfo& fragment = fragments[TupleToHash(packet)];

                    if (IsFlagMoreFragmentsSet(offset)) {
                        fragment.currentSize += dataLen;
                    } else if (IsOffsetNonZero(offset)) {
                        fragment.maxSize = offset*8 + dataLen;
                        fragment.currentSize += dataLen;
                    }

                    if (fragment.maxSize > 0 && fragment.currentSize >= fragment.maxSize) {
                        string src;
                        string dst;
                        tie(src,dst) = SrcAndDstIPv4Address(packet);

                        msg += MakeIPv4StringToPrint(src, dst, packet.ip_ttl);

                        if (IsICMPv4(packet)) {
                            const icmphdr& icmp {*(icmphdr*)(packetL3 + HeaderLenIPv4(packet))};
                            return msg + PrintICMPv4(icmp.type, icmp.code);
                        }

                        if (options.aggregation.second) {
                            const string& key {options.aggregation.first};
                            if (key == "srcip") {
                                addAggr(src, packetLen);
                            } else if (key == "dstip") {
                                addAggr(dst, packetLen);
                            }
                        }

                        packetL3 = SkipIPv4Header(packetL3);
                        packetType = packet.ip_p;
                    }
                } else {
                    string src;
                    string dst;
                    tie(src,dst) = SrcAndDstIPv4Address(packet);

                    msg += MakeIPv4StringToPrint(src, dst, packet.ip_ttl);

                    if (IsICMPv4(packet)) {
                        const icmphdr& icmp {*(icmphdr*)(packetL3 + HeaderLenIPv4(packet))};
                        return msg + PrintICMPv4(icmp.type, icmp.code);
                    }

                    if (options.aggregation.second) {
                        const string& key {options.aggregation.first};
                        if (key == "srcip") {
                            addAggr(src, packetLen);
                        } else if (key == "dstip") {
                            addAggr(dst, packetLen);
                        }
                    }

                    packetL3 = SkipIPv4Header(packetL3);
                    packetType = packet.ip_p;
                }

                break;
            }
            case Layer3::IPv6:
            {
                const ip6_hdr& ip {*(ip6_hdr*)packetL3};

                string src;
                string dst;
                tie(src,dst) = SrcAndDstIPv6Address(ip);

                if (options.aggregation.second) {
                    const string& key {options.aggregation.first};
                    if (key == "srcip") {
                        addAggr(src, packetLen);
                    } else if (key == "dstip") {
                        addAggr(dst, packetLen);
                    }
                }

                msg += MakeIPv6StringToPrint(src, dst, ip.ip6_hlim);

                uint8_t next {};
                tie(next, packetL3) = SkipExtensions(packetL3);

                if (NoNextProtocol(next)) {
                    return msg;
                }

                if (IsICMPv6(next)) {
                    const icmp6_hdr& icmp {*(icmp6_hdr*)(packetL3)};
                    return msg + PrintICMPv6(icmp.icmp6_type, icmp.icmp6_code);
                }

                packetType = next;
                break;
            }
            default: throw utils::BadProtocolType{"Layer3: Unknown protocol type: " + to_string(packetType)};
        }

        if (!IsProtocolFromL4(packetType)) return msg;

        return msg + " | " + layer4::PacketLayer4(packetL3, packetType, packetLen);
    }

    bool IsFlagMoreFragmentsSet(uint16_t offset) { return offset & IP_MF; }
    bool IsOffsetNonZero(uint16_t offset) { return offset != 0; }
    bool IsFragmented(const ip& header) {
        uint16_t offset {ntohs(header.ip_off)};
        return IsFlagMoreFragmentsSet(offset) || IsOffsetNonZero(offset);
    }

    TupleToHashForIPv4 TupleToHash(const ip& headerIPv4) {
        return {headerIPv4.ip_src.s_addr,
                headerIPv4.ip_dst.s_addr,
                headerIPv4.ip_id};
    }

    size_t HeaderLenIPv4(const ip& header) { return header.ip_hl * 4; }
    pair<string, string> SrcAndDstIPv4Address(const ip& iip) {
        string src {inet_ntoa(iip.ip_src)};
        string dst {inet_ntoa(iip.ip_dst)};
        return make_pair(src, dst);
    }

    string MakeIPv4StringToPrint(const string& src, const string& dst, uint8_t ttl) {
        return "IPv4: " + src + ' ' + dst + ' ' + to_string(ttl);
    }

    bool IsICMPv4(const ip& ip) { return ip.ip_p == 1; }

    pair<string, string> SrcAndDstIPv6Address(const ip6_hdr& ip) {
        array<char, INET6_ADDRSTRLEN> buf;

        string src {inet_ntop(AF_INET6, (void*)(&ip.ip6_src), buf.data(), buf.size())};
        string dst {inet_ntop(AF_INET6, (void*)(&ip.ip6_dst), buf.data(), buf.size())};

        return make_pair(src, dst);
    }

    string MakeIPv6StringToPrint(const string& src, const string& dst, uint8_t hopLimit) {
        return "IPv6: " + src + ' ' + dst + ' ' + to_string(hopLimit);
    }

    bool IsProtocolFromL4(uint8_t number) {
        UpperLayerIPv6 n {static_cast<UpperLayerIPv6>(number)};
        return n == UpperLayerIPv6::TCP ||
               n == UpperLayerIPv6::UDP ||
               n == UpperLayerIPv6::ICMPv6;
    }

    pair<uint8_t, const uint8_t*> SkipExtensions(const uint8_t* packet) {
        const ip6_hdr& ip {*reinterpret_cast<const ip6_hdr*>(packet)};
        uint8_t next {ip.ip6_nxt};
        const uint8_t* p {std::next(packet, HeaderLenIPv6())};

        const ip6_ext* e {reinterpret_cast<const ip6_ext*>(p)};

        for (; !IsProtocolFromL4(next);) {
            next = e->ip6e_nxt;
            p += (e->ip6e_len + 1)*8;
            e = reinterpret_cast<const ip6_ext*>(p);
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

    bool IsICMPv6(uint8_t next) {
        return static_cast<UpperLayerIPv6>(next) == UpperLayerIPv6::ICMPv6;
    }

    bool NoNextProtocol(uint8_t next) {
        return static_cast<ExtensionsIPv6>(next) == ExtensionsIPv6::NoNextHeader;
    }

    const uint8_t* SkipICMPv4Header(const uint8_t* packetL3) {
        return packetL3 + sizeof(icmphdr);
    }

    const uint8_t* SkipICMPv6Header(const uint8_t* packetL3) {
        return packetL3 + sizeof(icmp6_hdr);
    }

    const uint8_t* SkipIPv4Header(const uint8_t* packetL3) {
        return packetL3 + HeaderLenIPv4(*(ip*)packetL3);
    }
}
