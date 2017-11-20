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

    enum UpperLayerIPv6 { TCP = 6, UDP = 17, ICMPv6 = 58  };
    enum ExtensionsIPv6 { HopByHop = 0,
                          Routing = 43,
                          // Fragment header not supported
                          DestinationOptions = 60,
                          NoNextHeader = 59 };


    string Layer3(const uint8_t* packetL3, int type, size_t size);
    size_t HeaderLenIPv4(const ip* header); 
    string PrintICMPv4(uint8_t type, uint8_t code);
    pair<string, string> SrcAndDstIPv6Address(const ip6_hdr& ip);
    constexpr size_t HeaderLenIPv6() { return sizeof(ip6_hdr); }
    bool IsL4Protocol(uint8_t number);
    pair<uint8_t, const uint8_t*> SkipExtensions(const uint8_t* packet);
    string PrintICMPv4(uint8_t type, uint8_t code);
    string PrintICMPv6(uint8_t type, uint8_t code);
    bool IsICMPv6(uint8_t next);
    bool NoNextProtocol(uint8_t next);
    const uint8_t* SkipICMPv4Header(const uint8_t* packetL3);
    const uint8_t* SkipICMPv6Header(const uint8_t* packetL3);
}
