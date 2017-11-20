#pragma once 

#include <string>
#include <utility>
#include <vector>
#include <map>

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
            errorMsgICMPv4[0].first = "echo reply";
            errorMsgICMPv4[0].second = {""};

            errorMsgICMPv4[3].first = "destination unreachable";
            errorMsgICMPv4[3].second = {"net unreachable", "host unreachable",
                                        "protocol unreachable", "port unreachable",
                                        "fragmentation needed and DF set", "source route failed"};

            errorMsgICMPv4[4].first = "source quench";
            errorMsgICMPv4[4].second = {""};

            errorMsgICMPv4[5].first = "redirect";
            errorMsgICMPv4[5].second = {"redirect datagrams for the network",
                                        "redirect datagrams for the host",
                                        "redirect datagrams for the type of service and network",
                                        "redirect datagrams for the type of service and host"};

            errorMsgICMPv4[8].first  = "echo";
            errorMsgICMPv4[8].second = {""};

            errorMsgICMPv4[11].first = "time exceeded";
            errorMsgICMPv4[11].second = {"time to live exceeded in transit", "fragment reassembly time exceeded"};

            errorMsgICMPv4[12].first = "parameter problem";
            errorMsgICMPv4[12].second = {"pointer indicates the error"};

            errorMsgICMPv4[13].first = "timestamp";
            errorMsgICMPv4[13].second = {""};

            errorMsgICMPv4[14].first = "timestamp reply";
            errorMsgICMPv4[14].second = {""};

            errorMsgICMPv4[15].first = "information request";
            errorMsgICMPv4[15].second = {""};

            errorMsgICMPv4[16].first = "information reply";
            errorMsgICMPv4[16].second = {""};
        }

        pair<string, string> MessageFor(uint8_t type, uint8_t code) const {
            auto pos = errorMsgICMPv4.find(type);
            // type message exists
            if (pos != errorMsgICMPv4.end()) {
                const auto& info = pos->second;
                int size = info.second.size();
                // code message exists
                if (code < size) {
                    return {info.first, info.second[code]};
                }
            }
            return {"", ""};
        }
    private:
        map<int, pair<string, vector<string>>> errorMsgICMPv4;
    };

    class ICMPv6ErrorMessages {
    public:
        ICMPv6ErrorMessages() {
            errorMsgICMPv6[1].first = "destination unreachable";
            errorMsgICMPv6[1].second = {"no route to destination",
                                        "communication with destination administratively prohibited",
                                        "beyond scope of source address", "address unreachable",
                                        "port unreachable", "source address failed ingress/egress policy",
                                        "reject route to destination"};

            errorMsgICMPv6[2].first = "packet too big";
            errorMsgICMPv6[2].second = {""};

            errorMsgICMPv6[3].first = "time exceeded";
            errorMsgICMPv6[3].second = {"hop limit exceeded in transit", "fragment reassembly time exceeded"};

            errorMsgICMPv6[4].first = "parameter problem";
            errorMsgICMPv6[4].second = {"erroneous header field encountered",
                                        "unrecognized next header type encountered",
                                        "unrecognized ipv6 option encountered"};

            errorMsgICMPv6[128].first = "echo request";
            errorMsgICMPv6[128].second = {""};

            errorMsgICMPv6[129].first  = "echo reply";
            errorMsgICMPv6[129].second  = {""};
        }

        pair<string, string> MessageFor(uint8_t type, uint8_t code) const {
            auto pos = errorMsgICMPv6.find(type);
            // type message exists
            if (pos != errorMsgICMPv6.end()) {
                const auto& info = pos->second;
                // code message exists
                int size = info.second.size();
                if (code < size) {
                    return {info.first, info.second[code]};
                }
            }
            return {"", ""};
        }
    private:
        map<int, pair<string, vector<string>>> errorMsgICMPv6;
    };

    enum UpperLayerIPv6 { TCP = 6, UDP = 17, ICMPv6 = 58  };
    enum ExtensionsIPv6 { HopByHop = 0,
                          Routing = 43,
                          DestinationOptions = 60,
                          NoNextHeader = 59 };


    string Layer3(const uint8_t* packetL3, int type, size_t size);
    size_t IPv4HeaderSize(const ip* header); 
    size_t IPv6HeaderSize(); 
    bool IsL4Protocol(uint8_t number);
    pair<uint8_t, const uint8_t*> SkipAllIPv6Extensions(uint8_t next, const uint8_t* packet);
    string ICMPv4Messages(uint8_t type, uint8_t code);
    string ICMPv6Messages(uint8_t type, uint8_t code);
}
