#pragma once 

#include <string>
#include <utility>
#include <vector>
#include <unordered_map>

extern "C" {
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
}

namespace packet_analyzer::layer3 {
    struct TupleToHashForIPv4 {
        uint32_t SrcIP;
        uint32_t DstIP;
        uint16_t identification;
    };

    struct FragmentInfo {
        size_t maxSize;
        size_t currentSize;
    };
}

namespace std {
    using packet_analyzer::layer3::TupleToHashForIPv4;

    template<>
    struct hash<TupleToHashForIPv4> {
        size_t operator()(const TupleToHashForIPv4& t) const {
            return hash<uint32_t>{}(t.SrcIP) ^
                   hash<uint32_t>{}(t.DstIP) ^
                   hash<uint16_t>{}(t.identification);
        }
    };

    template<>
    struct equal_to<TupleToHashForIPv4> {
        bool operator()(const TupleToHashForIPv4& l, const TupleToHashForIPv4& r) const {
            return l.SrcIP == r.SrcIP &&
                   l.DstIP == r.DstIP &&
                   l.identification == r.identification;
        }
    };
}

namespace packet_analyzer::layer3 {
    using namespace std;

    class ICMPv4ErrorMessages {
    public:
        ICMPv4ErrorMessages() {
            errorMsgICMPv4[0]  = make_pair("echo reply", vector<string>{""});
            errorMsgICMPv4[3]  = make_pair("destination unreachable",
                                 vector<string>{"net unreachable", "host unreachable",
                                                "protocol unreachable", "port unreachable",
                                                "fragmentation needed and DF set", "source route failed"});
            errorMsgICMPv4[4]  = make_pair("source quench", vector<string>{""});
            errorMsgICMPv4[5]  = make_pair("redirect",
                                 vector<string>{"redirect datagrams for the network",
                                                "redirect datagrams for the host",
                                                "redirect datagrams for the type of service and network",
                                                "redirect datagrams for the type of service and host"});
            errorMsgICMPv4[8]  = make_pair("echo", vector<string>{""});
            errorMsgICMPv4[11] = make_pair("time exceeded", vector<string>{"time to live exceeded in transit",
                                                                           "fragment reassembly time exceeded"});
            errorMsgICMPv4[12] = make_pair("parameter problem", vector<string>{"pointer indicates the error"});
            errorMsgICMPv4[13] = make_pair("timestamp", vector<string>{""});
            errorMsgICMPv4[14] = make_pair("timestamp reply", vector<string>{""});
            errorMsgICMPv4[15] = make_pair("information request", vector<string>{""});
            errorMsgICMPv4[16] = make_pair("information reply", vector<string>{""});
        }

        pair<string, string> MessageFor(uint8_t type, uint8_t code) const {
            auto pos = errorMsgICMPv4.find(type);
            if (pos != errorMsgICMPv4.end()) {
                const auto& info = pos->second;
                if (code < info.second.size()) {
                    return make_pair(info.first, info.second[code]);
                }
            }
            return make_pair("", "");
        }
    private:
        unordered_map<int, pair<string, vector<string>>> errorMsgICMPv4;
    };

    class ICMPv6ErrorMessages {
    public:
        ICMPv6ErrorMessages() {
            errorMsgICMPv6[1]  = make_pair("destination unreachable",
                                 vector<string>{"no route to destination",
                                                "communication with destination administratively prohibited",
                                                "beyond scope of source address", "address unreachable",
                                                "port unreachable", "source address failed ingress/egress policy",
                                                "reject route to destination"});
            errorMsgICMPv6[2]  = make_pair("packet too big", vector<string>{""});
            errorMsgICMPv6[3] = make_pair("time exceeded", vector<string>{"hop limit exceeded in transit",
                                                                          "fragment reassembly time exceeded"});
            errorMsgICMPv6[4] = make_pair("parameter problem", vector<string>{"erroneous header field encountered",
                                                                              "unrecognized next header type encountered",
                                                                              "Unrecognized IPv6 option encountered"});
            errorMsgICMPv6[128]  = make_pair("echo request", vector<string>{""});
            errorMsgICMPv6[129]  = make_pair("echo reply", vector<string>{""});
        }

        pair<string, string> MessageFor(uint8_t type, uint8_t code) const {
            auto pos = errorMsgICMPv6.find(type);
            if (pos != errorMsgICMPv6.end()) {
                const auto& info = pos->second;
                if (code < info.second.size()) {
                    return make_pair(info.first, info.second[code]);
                }
            }
            return make_pair("", "");
        }
    private:
        unordered_map<int, pair<string, vector<string>>> errorMsgICMPv6;
    };

    extern unordered_map<TupleToHashForIPv4, FragmentInfo> fragments;

    enum class UpperLayerIPv6 { TCP = 6, UDP = 17, ICMPv6 = 58  };
    enum class ExtensionsIPv6 { HopByHop = 0,
                                Routing = 43,
                                // Fragment header not supported
                                DestinationOptions = 60,
                                NoNextHeader = 59 };


    string PacketLayer3(const uint8_t* packetL3, int packetType, size_t packetLen);
    bool IsFlagMoreFragmentsSet(uint16_t offset);
    bool IsOffsetNonZero(uint16_t offset);
    bool IsFragmented(const ip& header);
    TupleToHashForIPv4 TupleToHash(const ip& headerIPv4);
    size_t HeaderLenIPv4(const ip& header); 
    pair<string, string> SrcAndDstIPv4Address(const ip& iip);
    string MakeIPv4StringToPrint(const string& src, const string& dst, uint8_t ttl);
    bool IsICMPv4(const ip& ip);
    pair<string, string> SrcAndDstIPv6Address(const ip6_hdr& ip);
    string MakeIPv6StringToPrint(const string& src, const string& dst, uint8_t hopLimit);
    constexpr size_t HeaderLenIPv6() { return sizeof(ip6_hdr); }
    bool IsProtocolFromL4(uint8_t number);
    pair<uint8_t, const uint8_t*> SkipExtensions(const uint8_t* packet);
    string PrintICMPv4(uint8_t type, uint8_t code);
    string PrintICMPv6(uint8_t type, uint8_t code);
    bool IsICMPv6(uint8_t next);
    bool NoNextProtocol(uint8_t next);
    const uint8_t* SkipICMPv4Header(const uint8_t* packetL3);
    const uint8_t* SkipICMPv6Header(const uint8_t* packetL3);
    const uint8_t* SkipIPv4Header(const uint8_t* packetL3);
}
